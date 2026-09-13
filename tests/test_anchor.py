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


def main():
    test_keccak()
    print(f"\nResults: {passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
