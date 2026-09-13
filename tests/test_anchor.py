#!/usr/bin/env python3
"""Unit checks for transpeer.anchor: pure modules, no network.

Run:  PYTHONPATH=$PWD .venv/bin/python tests/test_anchor.py
"""

import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

passed = failed = 0


def check(cond, name):
    global passed, failed
    if cond:
        passed += 1
        print(f"  PASS: {name}")
    else:
        failed += 1
        print(f"  FAIL: {name}")


def test_keccak():
    from transpeer.anchor.keccak import keccak256
    from transpeer.anchor import CHAIN_ID
    print("keccak256")
    check(keccak256(b"").hex()
          == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
          "empty input")
    check(keccak256(b"abc").hex()
          == "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
          "abc")
    # Rate boundary: 136 bytes fills one block exactly; 137 spills.
    a = keccak256(b"x" * 136)
    b = keccak256(b"x" * 137)
    check(len(a) == 32 and a != b, "block boundary inputs differ")
    check(keccak256(b"x" * 136) == a, "deterministic")
    check(CHAIN_ID == hashlib.sha256(b"transpeer/anchor/v1").digest(),
          "CHAIN_ID is SHA-256 of transpeer/anchor/v1")


def test_varint():
    from transpeer.anchor.varint import write_varint, read_varint
    print("varint")
    check(write_varint(0) == b"\x00", "0")
    check(write_varint(127) == b"\x7f", "127")
    check(write_varint(128) == b"\x80\x01", "128")
    check(write_varint(0x3F6) == b"\xf6\x07", "0x3F6")
    for v in (0, 1, 127, 128, 300, 0xFFFFFFFF0, 0x7FFFFFFFFFF):
        val, pos = read_varint(b"\xaa" + write_varint(v) + b"\xbb", 1)
        check(val == v and pos == 1 + len(write_varint(v)), f"round trip {v:#x}")


def test_blob():
    from transpeer.anchor.blob import (
        encode_blob, decode_blob, blob_hash, list_body, with_period,
        period_of, is_reserved, BlobError, UnknownBlobVersion,
        PERIOD_SECONDS, MAX_ENTRIES,
    )
    print("list blob")
    entries = [("203.0.114.5", 7337), ("8.8.8.8", 7337), ("8.8.8.8", 7000)]
    b = encode_blob("monero", 12345, entries)
    check(b[:4] == b"TPL1" and b[4] == 1, "magic and version")
    check(b[5] == 6 and b[6:12] == b"monero", "chain name")
    check(int.from_bytes(b[12:20], "little") == 12345, "period at 6+n")
    check(int.from_bytes(b[20:22], "little") == 3, "count at 14+n")
    check(b[22:28] == bytes([8, 8, 8, 8]) + (7000).to_bytes(2, "little"),
          "first entry is lowest (address, port)")
    check(len(b) == 16 + 6 + 6 * 3, "length")
    d = decode_blob(b)
    check(d.chain == "monero" and d.period == 12345, "decode header")
    check(d.entries == (("8.8.8.8", 7000), ("8.8.8.8", 7337), ("203.0.114.5", 7337)),
          "decode entries sorted")
    check(blob_hash(b) == hashlib.sha256(b).digest(), "hash is sha256")
    body = list_body(b)
    check(int.from_bytes(body[12:20], "little") == 0 and body[22:] == b[22:], "body zeroes period")
    check(with_period(body, 12345) == b, "with_period restores")
    check(list_body(with_period(body, 99)) == body, "body is period-invariant")
    check(period_of(1500 * 1000 + 1499) == 1000 and period_of(1500 * 1001) == 1001,
          "period_of floors unix/1500")
    check(PERIOD_SECONDS == 1500 and MAX_ENTRIES == 64, "constants")

    def raises(exc, fn, name):
        try:
            fn()
        except exc:
            check(True, name)
        except Exception as e:  # noqa: BLE001
            check(False, f"{name} (raised {e!r})")
        else:
            check(False, name)

    raises(BlobError, lambda: encode_blob("monero", 1, []), "reject empty list")
    raises(BlobError, lambda: encode_blob("monero", 1, [("8.8.8.8", 1)] * 2), "reject duplicate")
    raises(BlobError, lambda: encode_blob("monero", 1, [("10.1.2.3", 1)]), "reject RFC 1918")
    raises(BlobError, lambda: encode_blob("monero", 1, [("100.64.0.1", 1)]), "reject CGNAT")
    raises(BlobError, lambda: encode_blob("monero", 1, [("198.18.0.1", 1)]), "reject benchmarking")
    raises(BlobError, lambda: encode_blob("monero", 1, [("240.0.0.1", 1)]), "reject 240/4")
    raises(BlobError, lambda: encode_blob("monero", 1, [("0.1.2.3", 1)]), "reject 0/8")
    raises(BlobError, lambda: encode_blob("monero", 1, [("8.8.8.8", 0)]), "reject port 0")
    raises(BlobError, lambda: encode_blob("", 1, [("8.8.8.8", 1)]), "reject empty chain")
    many = [(f"8.8.{i // 256}.{i % 256}", 1) for i in range(65)]
    raises(BlobError, lambda: encode_blob("monero", 1, many), "reject 65 entries")
    check(len(decode_blob(encode_blob("monero", 1, many[:64])).entries) == 64, "64 entries ok")
    check(is_reserved("127.0.0.1") and is_reserved("224.0.0.1") and not is_reserved("1.1.1.1"),
          "is_reserved")
    # Decoder rejects non-canonical bytes.
    unsorted = b[:22] + b[28:34] + b[22:28] + b[34:]
    raises(BlobError, lambda: decode_blob(unsorted), "decode rejects unsorted")
    raises(BlobError, lambda: decode_blob(b + b"\x00"), "decode rejects trailing bytes")
    raises(BlobError, lambda: decode_blob(b[:-1]), "decode rejects truncation")
    raises(UnknownBlobVersion, lambda: decode_blob(b[:4] + b"\x02" + b[5:]), "unknown version")
    raises(BlobError, lambda: decode_blob(b"XXXX" + b[4:]), "bad magic")


def main():
    test_keccak()
    test_varint()
    test_blob()
    print(f"\nResults: {passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
