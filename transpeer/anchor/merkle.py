"""P2Pool's merge-mining Merkle tree, aux-slot rule and tx_extra tag.

Transcribed from P2Pool v4.18 src/merkle.cpp, src/pool_block.h
(encode_merkle_tree_data) and src/block_template.cpp (tag writer);
vectors from tests/src/merkle_tests.cpp. Spec §6.3, §6.4.
"""

import hashlib
from dataclasses import dataclass

from .keccak import keccak256
from .varint import read_varint, write_varint

MM_TAG = 0x03
_TX_EXTRA_PADDING = 0x00
_TX_EXTRA_PUBKEY = 0x01
_TX_EXTRA_NONCE = 0x02
_TX_EXTRA_ADDITIONAL_PUBKEYS = 0x04


def _pow2_below(count: int) -> int:
    cnt = 1
    while cnt <= count:
        cnt <<= 1
    return cnt >> 1


def merkle_tree(hashes: list[bytes]) -> list[list[bytes]]:
    count = len(hashes)
    if count == 0:
        return []
    if count == 1:
        return [list(hashes)]
    if count == 2:
        return [list(hashes), [keccak256(hashes[0] + hashes[1])]]
    cnt = _pow2_below(count)
    k = cnt * 2 - count
    level = list(hashes[:k])
    for i in range(k, count, 2):
        level.append(keccak256(hashes[i] + hashes[i + 1]))
    tree = [list(hashes), level]
    while cnt > 1:
        cnt >>= 1
        prev = tree[-1]
        tree.append([keccak256(prev[2 * j] + prev[2 * j + 1]) for j in range(cnt)])
    return tree


def merkle_root(hashes: list[bytes]) -> bytes | None:
    tree = merkle_tree(hashes)
    return tree[-1][0] if tree else None


def merkle_proof(tree: list[list[bytes]], leaf: bytes) -> tuple[list[bytes], int] | None:
    if not tree:
        return None
    hashes = tree[0]
    count = len(hashes)
    try:
        index = hashes.index(leaf)
    except ValueError:
        return None
    proof: list[bytes] = []
    path = 0
    if count == 1:
        return proof, 0
    if count == 2:
        return [hashes[index ^ 1]], index
    cnt = _pow2_below(count)
    k = cnt * 2 - count
    if index >= k:
        index -= k
        j = (index ^ 1) + k
        if j >= count:
            return None
        proof.append(hashes[j])
        path = index & 1
        index = (index >> 1) + k
    i = 1
    while cnt >= 2:
        j = index ^ 1
        if i >= len(tree) or j >= len(tree[i]):
            return None
        proof.append(tree[i][j])
        path = (path << 1) | (index & 1)
        i += 1
        index >>= 1
        cnt >>= 1
    return proof, path


def verify_merkle_proof(leaf: bytes, proof: list[bytes], path: int, root: bytes) -> bool:
    h = leaf
    depth = len(proof)
    for d, sibling in enumerate(proof):
        if (path >> (depth - d - 1)) & 1:
            h = keccak256(sibling + h)
        else:
            h = keccak256(h + sibling)
    return h == root


def position_from_path(count: int, path: int) -> int:
    if count <= 1:
        return 0
    depth = 0
    k = 1
    while k < count:
        depth += 1
        k <<= 1
    k -= count
    pos = 0
    for _ in range(1, depth):
        pos = (pos << 1) | (path & 1)
        path >>= 1
    if pos < k:
        return pos
    return (((pos - k) << 1) | (path & 1)) + k


def aux_slot(chain_id: bytes, nonce: int, n: int) -> int:
    if n <= 1:
        return 0
    h = hashlib.sha256(chain_id + nonce.to_bytes(4, "little") + b"m").digest()
    return int.from_bytes(h[:4], "little") % n


def find_aux_nonce(chain_ids: list[bytes]) -> int:
    """Smallest nonce that puts every chain in a distinct slot."""
    n = len(chain_ids)
    for nonce in range(1 << 32):
        if len({aux_slot(c, nonce, n) for c in chain_ids}) == n:
            return nonce
    raise ValueError("no nonce found")


def encode_tree_params(n_aux_chains: int, nonce: int) -> int:
    n_bits = 1
    while (1 << n_bits) < n_aux_chains and n_bits < 8:
        n_bits += 1
    return (n_bits - 1) | ((n_aux_chains - 1) << 3) | (nonce << (3 + n_bits))


def decode_tree_params(v: int) -> tuple[int, int]:
    k = v & 0xFFFFFFFF
    n = 1 + (k & 7)
    n_aux_chains = 1 + ((k >> 3) & ((1 << n) - 1))
    nonce = (v >> (3 + n)) & 0xFFFFFFFF
    return n_aux_chains, nonce


@dataclass(frozen=True)
class MergeMiningTag:
    n_aux_chains: int
    nonce: int
    root: bytes


def build_mm_tag(n_aux_chains: int, nonce: int, root: bytes) -> bytes:
    params = write_varint(encode_tree_params(n_aux_chains, nonce))
    return bytes([MM_TAG, len(params) + 32]) + params + root


def parse_tx_extra_mm_tag(extra: bytes) -> MergeMiningTag | None:
    """Walk tx_extra and return the merge-mining tag, or None if absent
    or malformed. Unknown field types end the walk."""
    pos = 0
    try:
        while pos < len(extra):
            t = extra[pos]
            pos += 1
            if t == _TX_EXTRA_PADDING:
                continue
            if t == _TX_EXTRA_PUBKEY:
                pos += 32
            elif t == _TX_EXTRA_NONCE:
                n, pos = read_varint(extra, pos)
                pos += n
            elif t == _TX_EXTRA_ADDITIONAL_PUBKEYS:
                n, pos = read_varint(extra, pos)
                pos += 32 * n
            elif t == MM_TAG:
                size, pos = read_varint(extra, pos)
                end = pos + size
                if end > len(extra):
                    return None
                params, p = read_varint(extra, pos)
                if end - p != 32:
                    return None
                n_aux, nonce = decode_tree_params(params)
                return MergeMiningTag(n_aux, nonce, bytes(extra[p:end]))
            else:
                return None
            if pos > len(extra):
                return None
    except ValueError:
        return None
    return None
