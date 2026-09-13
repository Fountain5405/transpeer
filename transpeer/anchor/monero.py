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
    n_tx, pos = read_varint(blob, pos)
    _need(blob, pos, 32 * n_tx)
    if pos + 32 * n_tx != len(blob):
        raise ValueError("trailing bytes in block blob")
    return BlockHead(major, minor, timestamp, prev_id, nonce, height, tx_extra, n_tx)


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
