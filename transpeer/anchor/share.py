"""P2Pool PoolBlock share codec: parser, share id, aux Merkle proof,
proof-of-work check and encoder.

Transcribed from P2Pool v4.18 src/pool_block_parser.inl (deserialize),
src/pool_block.cpp (serialize_mainchain_data, serialize_sidechain_data,
get_pow_hash) and src/merkle.cpp (get_root_from_proof, the index/count
form of verify_merkle_proof). Constants from src/common.h and
src/pool_block.h; consensus ids from src/side_chain.cpp. Spec §6.5.

Not supported: compact shares (compact=True in P2Pool) and pruned
shares (num_outputs == 0) -- both raise ShareError; skipped checks
(not transcribed, per the task-5 brief): network_major_version,
get_cached_next_difficulty, get_tx_keys/check_keys and any elliptic
curve validity check of the wallet keys (P2Pool's Wallet::assign) --
spend_pub/view_pub are stored as-is.
"""

from dataclasses import dataclass

from . import CHAIN_ID
from .keccak import keccak256
from .varint import read_varint, write_varint
from .merkle import aux_slot, find_aux_nonce, encode_tree_params, decode_tree_params
from .merkle import merkle_tree, merkle_proof as _merkle_proof_of, merkle_root as _merkle_root_of
from .monero import tree_hash, miner_tx_hash, check_hash
from .powhash import PowBackend

# common.h constants
HASH_SIZE = 32
HARDFORK_SUPPORTED_VERSION = 16
MINER_REWARD_UNLOCK_TIME = 60
NONCE_SIZE = 4
EXTRA_NONCE_SIZE = 4
EXTRA_NONCE_MAX_SIZE = 14
TX_VERSION = 2
TXIN_GEN = 0xFF
TXOUT_TO_TAGGED_KEY = 3
TX_EXTRA_TAG_PUBKEY = 1
TX_EXTRA_NONCE = 2
TX_EXTRA_MERGE_MINING_TAG = 3

# pool_block.h constants
MAX_BLOCK_SIZE = 128 * 1024 - 5
BASE_BLOCK_REWARD = 600000000000
MAX_OUTPUT_VALUE = (1 << 56) - 1
MAX_CUMULATIVE_DIFFICULTY = 13019633956666736640 + (1710 << 64)
MAX_SIDECHAIN_HEIGHT = 31556952000
CRYPTONOTE_MAX_BLOCK_NUMBER = 500000000
MERGE_MINING_MAX_CHAINS = 256
LOG2_MERGE_MINING_MAX_CHAINS = 8
MAX_UNCLES_PER_BLOCK = 5

# side_chain.cpp default_consensus_id / mini_consensus_id / nano_consensus_id
VENUES = {
    "main": bytes([34, 175, 126, 231, 181, 11, 104, 146, 227, 153, 218, 107, 44, 108, 68, 39,
                    178, 81, 4, 212, 169, 4, 142, 0, 177, 110, 157, 240, 68, 7, 249, 24]),
    "mini": bytes([57, 130, 201, 26, 149, 174, 199, 250, 66, 80, 189, 18, 108, 216, 194, 220,
                    136, 23, 63, 24, 64, 113, 221, 44, 219, 86, 39, 163, 53, 24, 126, 196]),
    "nano": bytes([171, 248, 206, 148, 210, 226, 114, 99, 250, 145, 221, 96, 13, 216, 23, 63,
                    104, 53, 129, 168, 244, 80, 141, 138, 157, 250, 50, 54, 37, 189, 5, 89]),
}
VENUE_PORTS = {"main": 37889, "mini": 37888, "nano": 37890}
VENUE_WINDOW = 2160
VENUE_BLOCK_TIME = {"main": 10, "mini": 10, "nano": 30}

_U64_MASK = (1 << 64) - 1


class ShareError(ValueError):
    pass


class _Reader:
    """Bounds-checked cursor over a share's wire bytes."""

    __slots__ = ("data", "pos")

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def remaining(self) -> int:
        return len(self.data) - self.pos

    def byte(self) -> int:
        if self.pos >= len(self.data):
            raise ShareError("truncated: expected a byte")
        b = self.data[self.pos]
        self.pos += 1
        return b

    def expect(self, value: int, what: str) -> None:
        if self.byte() != value:
            raise ShareError(f"expected {what}")

    def buf(self, n: int) -> bytes:
        if n > self.remaining():
            raise ShareError(f"truncated: expected {n} bytes")
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return bytes(out)

    def varint(self) -> int:
        try:
            v, self.pos = read_varint(self.data, self.pos)
        except ValueError as e:
            raise ShareError(f"truncated varint: {e}") from e
        return v


@dataclass(frozen=True)
class ParsedShare:
    id: bytes
    raw: bytes
    major: int
    minor: int
    timestamp: int
    prev_id: bytes
    nonce: int
    txin_gen_height: int
    outputs: tuple
    tx_pubkey: bytes
    extra_nonce: int
    n_aux_chains: int
    aux_nonce: int
    merkle_root: bytes
    tx_hashes: tuple
    spend_pub: bytes
    view_pub: bytes
    txkey_sec_seed: bytes
    parent: bytes
    uncles: tuple
    height: int
    difficulty: int
    cumulative_difficulty: int
    merkle_proof: tuple
    aux: dict
    aux_raw: dict
    extra_buf: bytes
    hashing_blob: bytes
    wallet: str


def _root_from_proof_by_index(leaf: bytes, proof: tuple, index: int, count: int) -> bytes | None:
    """Transcribed from p2pool merkle.cpp get_root_from_proof(h, proof, index, count)."""
    if index >= count:
        return None
    if count == 1:
        return leaf if len(proof) == 0 else None
    h = leaf
    if count == 2:
        if len(proof) != 1:
            return None
        h = keccak256(proof[0] + h) if (index & 1) else keccak256(h + proof[0])
        return h

    cnt = 1
    while cnt <= count:
        cnt <<= 1
    cnt >>= 1

    proof_index = 0
    k = cnt * 2 - count
    if index >= k:
        index -= k
        if not proof:
            return None
        h = keccak256(proof[0] + h) if (index & 1) else keccak256(h + proof[0])
        index = (index >> 1) + k
        proof_index = 1

    while cnt >= 2:
        if proof_index >= len(proof):
            return None
        h = keccak256(proof[proof_index] + h) if (index & 1) else keccak256(h + proof[proof_index])
        proof_index += 1
        index >>= 1
        cnt >>= 1

    if proof_index != len(proof):
        return None
    return h


def _verify_proof_by_index(leaf: bytes, proof: tuple, index: int, count: int, root: bytes) -> bool:
    r = _root_from_proof_by_index(leaf, proof, index, count)
    return r is not None and r == root


def parse_share(data: bytes, consensus_id: bytes) -> ParsedShare:
    """Non-compact, non-pruned PoolBlock::deserialize."""
    if len(data) > MAX_BLOCK_SIZE:
        raise ShareError("share exceeds MAX_BLOCK_SIZE")

    r = _Reader(data)

    major = r.byte()
    if major > HARDFORK_SUPPORTED_VERSION:
        raise ShareError("major version above hardfork support")
    minor = r.byte()
    if minor < major:
        raise ShareError("minor version below major")
    if minor > 127:
        raise ShareError("minor version too large")

    timestamp = r.varint()
    prev_id = r.buf(HASH_SIZE)

    nonce_offset = r.pos
    nonce = int.from_bytes(r.buf(NONCE_SIZE), "little")

    header_size = r.pos
    miner_tx_start = r.pos

    r.expect(TX_VERSION, "tx version")
    unlock_height = r.varint()
    if unlock_height > CRYPTONOTE_MAX_BLOCK_NUMBER:
        raise ShareError("unlock height too large")
    r.expect(1, "single input")
    r.expect(TXIN_GEN, "txin_gen tag")
    txin_gen_height = r.varint()
    if txin_gen_height > CRYPTONOTE_MAX_BLOCK_NUMBER:
        raise ShareError("txin_gen height too large")
    if unlock_height != txin_gen_height + MINER_REWARD_UNLOCK_TIME:
        raise ShareError("unlock height mismatch")

    num_outputs = r.varint()
    if num_outputs == 0:
        raise ShareError("pruned share")

    min_output_size = 35
    if num_outputs * min_output_size > r.remaining():
        raise ShareError("not enough data for outputs")

    outputs = []
    total_reward = 0
    for _ in range(num_outputs):
        reward = r.varint()
        if reward > MAX_OUTPUT_VALUE:
            raise ShareError("output reward too large")
        total_reward += reward
        r.expect(TXOUT_TO_TAGGED_KEY, "tagged key output")
        eph_pub = r.buf(HASH_SIZE)
        view_tag = r.byte()
        outputs.append((reward, eph_pub, view_tag))

    if total_reward < BASE_BLOCK_REWARD:
        raise ShareError("total reward below base block reward")

    tx_extra_size = r.varint()
    tx_extra_begin = r.pos

    r.expect(TX_EXTRA_TAG_PUBKEY, "tx_extra pubkey tag")
    tx_pubkey = r.buf(HASH_SIZE)

    r.expect(TX_EXTRA_NONCE, "tx_extra nonce tag")
    extra_nonce_size = r.varint()
    if extra_nonce_size < EXTRA_NONCE_SIZE or extra_nonce_size > EXTRA_NONCE_MAX_SIZE:
        raise ShareError("extra nonce size out of range")

    extra_nonce_offset = r.pos
    extra_nonce = int.from_bytes(r.buf(EXTRA_NONCE_SIZE), "little")
    for _ in range(EXTRA_NONCE_SIZE, extra_nonce_size):
        r.expect(0, "extra nonce padding")

    r.expect(TX_EXTRA_MERGE_MINING_TAG, "merge mining tag")

    mm_field_size = r.varint()
    mm_field_begin = r.pos
    merkle_tree_data = r.varint()
    n_aux_chains, aux_nonce = decode_tree_params(merkle_tree_data)

    mm_root_hash_offset = r.pos
    merkle_root_bytes = r.buf(HASH_SIZE)

    if r.pos - mm_field_begin != mm_field_size:
        raise ShareError("merge mining field size mismatch")
    if r.pos - tx_extra_begin != tx_extra_size:
        raise ShareError("tx_extra size mismatch")

    r.expect(0, "trailing rct null byte")
    miner_tx_end = r.pos
    miner_tx = data[miner_tx_start:miner_tx_end]

    num_transactions = r.varint()
    if num_transactions > MAX_BLOCK_SIZE // HASH_SIZE:
        raise ShareError("too many transactions")
    if num_transactions * HASH_SIZE > r.remaining():
        raise ShareError("not enough data for transaction hashes")
    tx_hashes = tuple(r.buf(HASH_SIZE) for _ in range(num_transactions))

    spend_pub = r.buf(HASH_SIZE)
    view_pub = r.buf(HASH_SIZE)
    txkey_sec_seed = r.buf(HASH_SIZE)
    parent = r.buf(HASH_SIZE)

    num_uncles = r.varint()
    if num_uncles > MAX_UNCLES_PER_BLOCK:
        raise ShareError("too many uncles")
    if num_uncles * HASH_SIZE > r.remaining():
        raise ShareError("not enough data for uncles")
    uncles = tuple(r.buf(HASH_SIZE) for _ in range(num_uncles))

    height = r.varint()
    if height > MAX_SIDECHAIN_HEIGHT:
        raise ShareError("sidechain height too large")

    difficulty = r.varint()
    difficulty += r.varint() << 64

    cumulative_difficulty = r.varint()
    cumulative_difficulty += r.varint() << 64
    if cumulative_difficulty > MAX_CUMULATIVE_DIFFICULTY:
        raise ShareError("cumulative difficulty too large")
    if difficulty > cumulative_difficulty:
        raise ShareError("difficulty exceeds cumulative difficulty")

    merkle_proof_size = r.byte()
    if merkle_proof_size > LOG2_MERGE_MINING_MAX_CHAINS:
        raise ShareError("merkle proof too long")
    merkle_proof = tuple(r.buf(HASH_SIZE) for _ in range(merkle_proof_size))

    mm_extra_data_count = r.varint()
    aux: dict = {}
    aux_raw: dict = {}
    if mm_extra_data_count:
        if mm_extra_data_count > MERGE_MINING_MAX_CHAINS:
            raise ShareError("too many merge mining chains")
        if mm_extra_data_count * (HASH_SIZE + 1) > r.remaining():
            raise ShareError("not enough data for merge mining extra")
        prev_chain_id = None
        for i in range(mm_extra_data_count):
            chain_id = r.buf(HASH_SIZE)
            if i and not (prev_chain_id < chain_id):
                raise ShareError("merge mining chain ids not ordered")
            prev_chain_id = chain_id
            n = r.varint()
            if n > r.remaining():
                raise ShareError("not enough data for merge mining chain data")
            t = r.buf(n) if n else b""
            aux_raw[chain_id] = t

            if len(t) < HASH_SIZE:
                if chain_id == CHAIN_ID:
                    raise ShareError("transpeer aux data too short")
                aux[chain_id] = (b"", 0)
                continue
            try:
                lo, p = read_varint(t, HASH_SIZE)
                hi, p = read_varint(t, p)
                if p != len(t):
                    raise ValueError("trailing bytes in aux data")
            except ValueError:
                if chain_id == CHAIN_ID:
                    raise ShareError("transpeer aux data malformed")
                aux[chain_id] = (b"", 0)
                continue
            aux[chain_id] = (t[:HASH_SIZE], lo + (hi << 64))

    extra_buf = r.buf(16)

    if r.pos != len(data):
        raise ShareError("trailing bytes after share")

    patched = bytearray(data)
    patched[nonce_offset:nonce_offset + NONCE_SIZE] = bytes(NONCE_SIZE)
    patched[extra_nonce_offset:extra_nonce_offset + EXTRA_NONCE_SIZE] = bytes(EXTRA_NONCE_SIZE)
    patched[mm_root_hash_offset:mm_root_hash_offset + HASH_SIZE] = bytes(HASH_SIZE)
    share_id = keccak256(bytes(patched) + consensus_id)

    slot = aux_slot(consensus_id, aux_nonce, n_aux_chains)
    if not _verify_proof_by_index(share_id, merkle_proof, slot, n_aux_chains, merkle_root_bytes):
        raise ShareError("aux merkle proof failed")

    header_bytes = data[:header_size]
    tx_root = tree_hash([miner_tx_hash(miner_tx)] + list(tx_hashes))
    hashing_blob = header_bytes + tx_root + write_varint(1 + len(tx_hashes))

    return ParsedShare(
        id=share_id, raw=bytes(data), major=major, minor=minor, timestamp=timestamp,
        prev_id=prev_id, nonce=nonce, txin_gen_height=txin_gen_height,
        outputs=tuple(outputs), tx_pubkey=tx_pubkey, extra_nonce=extra_nonce,
        n_aux_chains=n_aux_chains, aux_nonce=aux_nonce, merkle_root=merkle_root_bytes,
        tx_hashes=tx_hashes, spend_pub=spend_pub, view_pub=view_pub,
        txkey_sec_seed=txkey_sec_seed, parent=parent, uncles=uncles, height=height,
        difficulty=difficulty, cumulative_difficulty=cumulative_difficulty,
        merkle_proof=merkle_proof, aux=aux, aux_raw=aux_raw, extra_buf=extra_buf,
        hashing_blob=hashing_blob, wallet=spend_pub.hex() + view_pub.hex(),
    )


def verify_share_pow(share: ParsedShare, pow: PowBackend, seed_hash: bytes = bytes(32)) -> bool:
    return check_hash(pow.hash(share.hashing_blob, share.txin_gen_height, seed_hash), share.difficulty)


def transpeer_aux(share: ParsedShare, chain_id: bytes = CHAIN_ID) -> bytes | None:
    entry = share.aux.get(chain_id)
    return entry[0] if entry else None


def share_id_of(data: bytes, consensus_id: bytes) -> bytes:
    return parse_share(data, consensus_id).id


def _serialize_mainchain(major, minor, timestamp, prev_id, nonce, txin_gen_height, outputs,
                          tx_pubkey, extra_nonce, merkle_tree_data, merkle_root_bytes, tx_hashes):
    data = bytearray()
    data.append(major)
    data.append(minor)
    data += write_varint(timestamp)
    data += prev_id
    nonce_offset = len(data)
    data += nonce.to_bytes(NONCE_SIZE, "little")
    header_size = len(data)

    data.append(TX_VERSION)
    data += write_varint(txin_gen_height + MINER_REWARD_UNLOCK_TIME)
    data.append(1)
    data.append(TXIN_GEN)
    data += write_varint(txin_gen_height)

    data += write_varint(len(outputs))
    for reward, eph_pub, view_tag in outputs:
        data += write_varint(reward)
        data.append(TXOUT_TO_TAGGED_KEY)
        data += eph_pub
        data.append(view_tag)

    tx_extra = bytearray()
    tx_extra.append(TX_EXTRA_TAG_PUBKEY)
    tx_extra += tx_pubkey
    tx_extra.append(TX_EXTRA_NONCE)
    tx_extra += write_varint(EXTRA_NONCE_SIZE)
    extra_nonce_offset_local = len(tx_extra)
    tx_extra += extra_nonce.to_bytes(EXTRA_NONCE_SIZE, "little")
    tx_extra.append(TX_EXTRA_MERGE_MINING_TAG)
    tree_data_bytes = write_varint(merkle_tree_data)
    tx_extra.append(len(tree_data_bytes) + HASH_SIZE)
    tx_extra += tree_data_bytes
    mm_root_hash_offset_local = len(tx_extra)
    tx_extra += merkle_root_bytes

    data += write_varint(len(tx_extra))
    extra_nonce_offset = len(data) + extra_nonce_offset_local
    mm_root_hash_offset = len(data) + mm_root_hash_offset_local
    data += tx_extra

    data.append(0)  # trailing rct-null byte

    data += write_varint(len(tx_hashes))
    for h in tx_hashes:
        data += h

    return bytes(data), nonce_offset, header_size, extra_nonce_offset, mm_root_hash_offset


def _serialize_sidechain(spend_pub, view_pub, seed, parent, uncles, height, difficulty,
                          cumulative_difficulty, merkle_proof, aux_raw, extra_buf):
    data = bytearray()
    data += spend_pub
    data += view_pub
    data += seed
    data += parent
    data += write_varint(len(uncles))
    for u in uncles:
        data += u
    data += write_varint(height)
    data += write_varint(difficulty & _U64_MASK)
    data += write_varint(difficulty >> 64)
    data += write_varint(cumulative_difficulty & _U64_MASK)
    data += write_varint(cumulative_difficulty >> 64)
    data.append(len(merkle_proof))
    for h in merkle_proof:
        data += h
    data += write_varint(len(aux_raw))
    for chain_id in sorted(aux_raw):
        data += chain_id
        data += write_varint(len(aux_raw[chain_id]))
        data += aux_raw[chain_id]
    data += extra_buf
    return bytes(data)


def build_share(*, consensus_id, txin_gen_height, prev_id, timestamp, parent, height, difficulty,
                 cumulative_difficulty, aux, spend_pub=bytes(32), view_pub=bytes(32), seed=bytes(32),
                 uncles=(), tx_hashes=(), outputs=((BASE_BLOCK_REWARD, bytes(32), 0),),
                 tx_pubkey=b"\x01" * 32, extra_nonce=0, nonce=0, major=16, minor=16,
                 extra_buf=bytes(16)) -> bytes:
    chain_ids = [consensus_id] + list(aux.keys())
    n = len(chain_ids)
    aux_nonce = find_aux_nonce(chain_ids) if n > 1 else 0
    slots = {cid: aux_slot(cid, aux_nonce, n) for cid in chain_ids}
    merkle_tree_data = encode_tree_params(n, aux_nonce)

    aux_raw = {
        cid: h + write_varint(diff & _U64_MASK) + write_varint(diff >> 64)
        for cid, (h, diff) in aux.items()
    }

    leaves = None
    if n == 1:
        merkle_proof: tuple = ()
    else:
        placeholder = keccak256(b"share-id-placeholder" + consensus_id)
        leaves = [b""] * n
        for cid in chain_ids:
            leaves[slots[cid]] = placeholder if cid == consensus_id else aux[cid][0]
        tree = merkle_tree(leaves)
        proof_result = _merkle_proof_of(tree, placeholder)
        if proof_result is None:
            raise ValueError("failed to build aux merkle proof")
        merkle_proof = tuple(proof_result[0])

    main_placeholder, nonce_offset, _header_size, extra_nonce_offset, mm_root_hash_offset = (
        _serialize_mainchain(major, minor, timestamp, prev_id, nonce, txin_gen_height, outputs,
                              tx_pubkey, extra_nonce, merkle_tree_data, bytes(HASH_SIZE), tx_hashes))
    side = _serialize_sidechain(spend_pub, view_pub, seed, parent, uncles, height, difficulty,
                                 cumulative_difficulty, merkle_proof, aux_raw, extra_buf)
    blob = main_placeholder + side

    patched = bytearray(blob)
    patched[nonce_offset:nonce_offset + NONCE_SIZE] = bytes(NONCE_SIZE)
    patched[extra_nonce_offset:extra_nonce_offset + EXTRA_NONCE_SIZE] = bytes(EXTRA_NONCE_SIZE)
    patched[mm_root_hash_offset:mm_root_hash_offset + HASH_SIZE] = bytes(HASH_SIZE)
    share_id = keccak256(bytes(patched) + consensus_id)

    if n == 1:
        root = share_id
    else:
        leaves[slots[consensus_id]] = share_id
        root = _merkle_root_of(leaves)

    main_final, *_rest = _serialize_mainchain(major, minor, timestamp, prev_id, nonce, txin_gen_height,
                                               outputs, tx_pubkey, extra_nonce, merkle_tree_data, root,
                                               tx_hashes)
    return main_final + side


def mine_share(build_kwargs: dict, pow: PowBackend, max_nonce: int = 1 << 32) -> bytes:
    consensus_id = build_kwargs["consensus_id"]
    start = build_kwargs.get("nonce", 0)
    for n in range(start, max_nonce):
        raw = build_share(**{**build_kwargs, "nonce": n})
        share = parse_share(raw, consensus_id)
        if verify_share_pow(share, pow):
            return raw
    raise ValueError(f"exhausted {max_nonce} nonces without meeting difficulty")
