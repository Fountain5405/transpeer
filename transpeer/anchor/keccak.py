"""Keccak-256 with the original Keccak padding (0x01), which is what
Monero and P2Pool use. hashlib.sha3_256 uses the NIST padding (0x06)
and produces different digests, so it cannot be substituted.

Pure Python; fine for Merkle trees of a few dozen leaves.
"""

_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
# Rotation offsets r[x][y].
_ROT = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]
_MASK = (1 << 64) - 1
_RATE = 136  # bytes, for a 256-bit output


def _rotl(v: int, r: int) -> int:
    return ((v << r) | (v >> (64 - r))) & _MASK if r else v


def _keccak_f(s: list[int]) -> list[int]:
    # Lane (x, y) lives at index x + 5*y.
    for rc in _RC:
        c = [s[x] ^ s[x + 5] ^ s[x + 10] ^ s[x + 15] ^ s[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rotl(c[(x + 1) % 5], 1) for x in range(5)]
        s = [s[i] ^ d[i % 5] for i in range(25)]
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rotl(s[x + 5 * y], _ROT[x][y])
        s = [
            b[i] ^ ((~b[(i % 5 + 1) % 5 + 5 * (i // 5)]) & b[(i % 5 + 2) % 5 + 5 * (i // 5)])
            for i in range(25)
        ]
        s[0] ^= rc
    return s


def keccak256(data: bytes) -> bytes:
    padded = bytearray(data) + b"\x01"
    padded += b"\x00" * ((-len(padded)) % _RATE)
    padded[-1] |= 0x80
    s = [0] * 25
    for off in range(0, len(padded), _RATE):
        block = padded[off:off + _RATE]
        for i in range(_RATE // 8):
            s[i] ^= int.from_bytes(block[8 * i:8 * i + 8], "little")
        s = _keccak_f(s)
    return b"".join(lane.to_bytes(8, "little") for lane in s[:4])
