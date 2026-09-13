"""Monero varint: 7 bits per byte, least significant group first, high
bit set on every byte but the last."""


def write_varint(v: int) -> bytes:
    if v < 0:
        raise ValueError("negative varint")
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def read_varint(data: bytes, pos: int) -> tuple[int, int]:
    """Return (value, position after the varint). Raises ValueError on
    truncation or a varint longer than 10 bytes."""
    v = 0
    shift = 0
    for i in range(10):
        if pos + i >= len(data):
            raise ValueError("truncated varint")
        b = data[pos + i]
        v |= (b & 0x7F) << shift
        if not b & 0x80:
            return v, pos + i + 1
        shift += 7
    raise ValueError("varint too long")
