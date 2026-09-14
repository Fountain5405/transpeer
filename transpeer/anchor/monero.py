"""Minimal Monero block blob codec: enough to reach the coinbase
tx_extra (for the merge-mining tag) and the header fields.

Layout: major, minor, timestamp as varints; prev_id 32 bytes; nonce
4 bytes LE; miner tx; tx-hash count varint; 32 bytes per hash.
Miner tx: version varint; unlock_time varint; input count varint (1);
input type 0xff; height varint; output count varint; per output amount
varint, type byte (0x02 key: 32 bytes; 0x03 tagged key: 33 bytes);
extra length varint + bytes; for version 2, one RCT type byte (0).
"""

from dataclasses import dataclass

from .keccak import keccak256
from .varint import read_varint, write_varint

_TXIN_GEN = 0xFF
_TXOUT_KEY = 0x02
_TXOUT_TAGGED_KEY = 0x03


@dataclass(frozen=True)
class BlockHead:
    major: int
    minor: int
    timestamp: int
    prev_id: bytes
    nonce: int
    height: int
    tx_extra: bytes
    n_tx_hashes: int
    miner_tx: bytes = b""
    tx_hashes: tuple = ()


def _need(blob: bytes, pos: int, n: int) -> None:
    if pos + n > len(blob):
        raise ValueError("truncated block blob")


def parse_block_blob(blob: bytes) -> BlockHead:
    pos = 0
    major, pos = read_varint(blob, pos)
    minor, pos = read_varint(blob, pos)
    timestamp, pos = read_varint(blob, pos)
    _need(blob, pos, 36)
    prev_id = bytes(blob[pos:pos + 32])
    pos += 32
    nonce = int.from_bytes(blob[pos:pos + 4], "little")
    pos += 4
    # miner tx
    miner_start = pos
    version, pos = read_varint(blob, pos)
    _unlock, pos = read_varint(blob, pos)
    n_in, pos = read_varint(blob, pos)
    if n_in != 1:
        raise ValueError("miner tx must have one input")
    _need(blob, pos, 1)
    if blob[pos] != _TXIN_GEN:
        raise ValueError("miner tx input is not txin_gen")
    pos += 1
    height, pos = read_varint(blob, pos)
    n_out, pos = read_varint(blob, pos)
    for _ in range(n_out):
        _amount, pos = read_varint(blob, pos)
        _need(blob, pos, 1)
        t = blob[pos]
        pos += 1
        if t == _TXOUT_KEY:
            _need(blob, pos, 32)
            pos += 32
        elif t == _TXOUT_TAGGED_KEY:
            _need(blob, pos, 33)
            pos += 33
        else:
            raise ValueError(f"unknown output type {t:#x}")
    extra_len, pos = read_varint(blob, pos)
    _need(blob, pos, extra_len)
    tx_extra = bytes(blob[pos:pos + extra_len])
    pos += extra_len
    if version >= 2:
        _need(blob, pos, 1)
        pos += 1  # RCT type, 0 for a miner tx
    miner_tx = bytes(blob[miner_start:pos])
    n_tx, pos = read_varint(blob, pos)
    _need(blob, pos, 32 * n_tx)
    if pos + 32 * n_tx != len(blob):
        raise ValueError("trailing bytes in block blob")
    tx_hashes = tuple(bytes(blob[pos + 32 * i:pos + 32 * (i + 1)]) for i in range(n_tx))
    return BlockHead(major, minor, timestamp, prev_id, nonce, height, tx_extra, n_tx,
                      miner_tx, tx_hashes)


def build_block_blob(major: int, minor: int, timestamp: int, prev_id: bytes, nonce: int,
                     height: int, tx_extra: bytes, tx_hashes=()) -> bytes:
    """A version-2 miner tx with one 0x02 output of amount 1 and a zero
    key; sufficient for tests and the simulation oracle."""
    out = bytearray()
    out += write_varint(major) + write_varint(minor) + write_varint(timestamp)
    out += prev_id + nonce.to_bytes(4, "little")
    out += write_varint(2) + write_varint(height + 60)          # version, unlock_time
    out += write_varint(1) + bytes([_TXIN_GEN]) + write_varint(height)
    out += write_varint(1) + write_varint(1) + bytes([_TXOUT_KEY]) + bytes(32)
    out += write_varint(len(tx_extra)) + tx_extra
    out += b"\x00"                                               # RCT type null
    out += write_varint(len(tx_hashes))
    for h in tx_hashes:
        out += h
    return bytes(out)


HASH_SIZE = 32
DIFFICULTY_WINDOW = 720
DIFFICULTY_LAG = 15
DIFFICULTY_CUT = 60
DIFFICULTY_BLOCKS_COUNT = DIFFICULTY_WINDOW + DIFFICULTY_LAG
BLOCK_FUTURE_TIME_LIMIT = 7200
MONERO_BLOCK_TIME = 120
_MAX128 = (1 << 128) - 1


def tree_hash(hashes: list) -> bytes:
    """Monero crypto/tree-hash.c tree_hash (v0.18.4.1)."""
    count = len(hashes)
    if count == 0:
        raise ValueError("tree_hash of nothing")
    if count == 1:
        return hashes[0]
    if count == 2:
        return keccak256(hashes[0] + hashes[1])
    pw = 2
    while pw < count:
        pw <<= 1
    cnt = pw >> 1
    ints = list(hashes[:2 * cnt - count])
    i = 2 * cnt - count
    while len(ints) < cnt:
        ints.append(keccak256(hashes[i] + hashes[i + 1]))
        i += 2
    while cnt > 2:
        cnt >>= 1
        ints = [keccak256(ints[2 * j] + ints[2 * j + 1]) for j in range(cnt)]
    return keccak256(ints[0] + ints[1])


def miner_tx_hash(miner_tx: bytes) -> bytes:
    """Monero calculate_transaction_hash for a v2 miner tx: prefix hash,
    hash of the RCT base (one 0x00 byte), null prunable hash."""
    return keccak256(keccak256(miner_tx[:-1]) + keccak256(b"\x00") + bytes(32))


@dataclass(frozen=True)
class HashingHead:
    major: int
    minor: int
    timestamp: int
    prev_id: bytes
    nonce: int
    tx_root: bytes
    n_tx: int


def _header_bytes(blob: bytes) -> bytes:
    pos = 0
    _, pos = read_varint(blob, pos)
    _, pos = read_varint(blob, pos)
    _, pos = read_varint(blob, pos)
    _need(blob, pos, 36)
    return bytes(blob[:pos + 36])


def hashing_blob(block_blob: bytes) -> bytes:
    head = parse_block_blob(block_blob)
    root = tree_hash([miner_tx_hash(head.miner_tx)] + list(head.tx_hashes))
    return _header_bytes(block_blob) + root + write_varint(1 + len(head.tx_hashes))


def parse_hashing_blob(blob: bytes) -> HashingHead:
    pos = 0
    major, pos = read_varint(blob, pos)
    minor, pos = read_varint(blob, pos)
    timestamp, pos = read_varint(blob, pos)
    _need(blob, pos, 36 + 32)
    prev_id = bytes(blob[pos:pos + 32]); pos += 32
    nonce = int.from_bytes(blob[pos:pos + 4], "little"); pos += 4
    root = bytes(blob[pos:pos + 32]); pos += 32
    n_tx, pos = read_varint(blob, pos)
    if pos != len(blob):
        raise ValueError("trailing bytes in hashing blob")
    return HashingHead(major, minor, timestamp, prev_id, nonce, root, n_tx)


def block_id(hb: bytes) -> bytes:
    return keccak256(write_varint(len(hb)) + hb)


def check_hash(pow_hash: bytes, difficulty: int) -> bool:
    if len(pow_hash) != 32 or difficulty <= 0:
        return False
    return int.from_bytes(pow_hash, "little") * difficulty < (1 << 256)


def next_difficulty(timestamps: list, cumulative: list, target: int = MONERO_BLOCK_TIME) -> int:
    """Monero difficulty.cpp next_difficulty (v0.18.4.1)."""
    timestamps = list(timestamps[:DIFFICULTY_WINDOW])
    cumulative = list(cumulative[:DIFFICULTY_WINDOW])
    length = len(timestamps)
    if length != len(cumulative):
        raise ValueError("timestamps and cumulative difficulties differ in length")
    if length <= 1:
        return 1
    timestamps.sort()
    if length <= DIFFICULTY_WINDOW - 2 * DIFFICULTY_CUT:
        cut_begin, cut_end = 0, length
    else:
        cut_begin = (length - (DIFFICULTY_WINDOW - 2 * DIFFICULTY_CUT) + 1) // 2
        cut_end = cut_begin + (DIFFICULTY_WINDOW - 2 * DIFFICULTY_CUT)
    time_span = max(1, timestamps[cut_end - 1] - timestamps[cut_begin])
    total_work = cumulative[cut_end - 1] - cumulative[cut_begin]
    if total_work <= 0:
        raise ValueError("non-positive total work")
    res = (total_work * target + time_span - 1) // time_span
    return 0 if res > _MAX128 else res
