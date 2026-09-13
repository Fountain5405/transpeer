# Chain-anchored publication, slices 1 and 2: implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the pure protocol pieces of chain-anchored publication (list blob, P2Pool Merkle tree and tag, blob database, weighting, coverage) and the publisher side (curation, aux-chain JSON-RPC server that a stock P2Pool can merge-mine against, blob endpoints), all behind flags that default off.

**Architecture:** A new package `transpeer/anchor/` holds pure modules with no I/O (keccak, blob, varint/tag, merkle, monero block blob, blobdb, weight) and two networked pieces (publisher, aux RPC server). `Node.run` starts the publisher and the aux RPC server only under `--anchor-publish`; `TranspeerServer` gains `/blob/{hash}` and `/blobs/index`. Nothing existing changes behaviour unless the new flags are given.

**Tech Stack:** Python 3.12 from `.venv` (aiohttp, stdlib `hashlib`, `ipaddress`; no new dependencies, Keccak-256 is implemented in pure Python). Tests are plain scripts with a `check()` tally, as in `tests/test_bucketed.py`.

**Spec:** `docs/spec-chain-anchored-publication.md` (§3 data model, §4.1 curation, §4.2 aux-chain interface, §5 transport, §6.3–6.4 tag and Merkle, §7 weighting, §8 coverage, §17 implementation notes). P2Pool facts verified against v4.18 are recorded in spec §15; source copies used while writing this plan are under the session scratchpad and are not needed to execute it.

## Global Constraints

- Interpreter: `.venv/bin/python` (3.12). Never `python3` (system 3.8). Run tests as `PYTHONPATH=$PWD .venv/bin/python tests/<file>.py`.
- No new runtime dependencies. `pyproject.toml` stays at `aiohttp`, `aiosqlite`.
- Every new behaviour is behind a flag defaulting off: `--anchor-publish` gates the publisher and aux RPC server. Existing tests (`tests/test_two_nodes.py` 24 checks, `tests/test_bucketed.py` 47, `tests/test_scanner.py` 19) must keep passing unchanged after every task.
- Blob format, spec §3.1: magic `TPL1`, version `0x01`, chain-name length byte, name, `period` (8 bytes LE, `floor(unix/1500)`), `count` (2 bytes LE, 1..64), entries of IPv4 (4 bytes network order) + port (2 bytes LE); total ≤ 1024 bytes; entries sorted ascending by (address, port), unique, none in a reserved range. Hash = SHA-256 of the blob bytes.
- Chain id: `SHA-256("transpeer/anchor/v1")`, spec §4.2.
- P2Pool interface constants (spec §15): poll every 500 ms; a chain whose `aux_hash` has not changed for 1800 s is dropped; `aux_diff` must be nonzero; P2Pool remembers the last 8 aux hashes and may call `merge_mining_submit_solution` for any of them.
- Merge-mining tag (spec §6.3): byte `0x03`, one length byte = len(params varint) + 32, params varint, 32-byte root. Params encoding (`PoolBlock::encode_merkle_tree_data`): `(n_bits-1) | ((n_aux_chains-1) << 3) | (nonce << (3+n_bits))` where `n_bits` is the smallest in 1..8 with `(1 << n_bits) >= n_aux_chains`.
- Merkle tree (spec §6.4, P2Pool `merkle.cpp`): Keccak-256 over the 64-byte concatenation of each pair; for a non-power-of-two leaf count the first step pairs leaves from the end until a power of two remains; slot = first 4 bytes, little-endian, of `SHA-256(chain_id ‖ nonce as 4-byte LE ‖ b"m")` modulo `n_aux_chains`.
- Commit after every task with the message trailers:
  ```
  Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01WkpMVTAKW7iLDzgTavyHVW
  ```
- Never edit the worktree `~/transpeer-eclipse` while a Shadow run is active (CLAUDE.md). No run is active at the time of writing; work on `master` in `~/transpeer`.

---

## File structure

| file | responsibility |
|---|---|
| `transpeer/anchor/__init__.py` | package marker, exports `CHAIN_ID` |
| `transpeer/anchor/keccak.py` | Keccak-256 (original padding `0x01`, as Monero and P2Pool use), pure Python |
| `transpeer/anchor/varint.py` | Monero varint read/write |
| `transpeer/anchor/blob.py` | list blob encode/decode/canonical form/hash/period (§3.1) |
| `transpeer/anchor/merkle.py` | P2Pool Merkle tree, proof, verification, aux slot, tag params, tag build/parse (§6.3, §6.4) |
| `transpeer/anchor/monero.py` | Monero block blob parse/build: header, miner tx, `tx_extra` walk (§6.3) |
| `transpeer/anchor/blobdb.py` | `Commitment` record and content-addressed `BlobDB` with bodies stored once (§3.2, §3.3), JSON persistence |
| `transpeer/anchor/weight.py` | `Share`, canonical window walk, blob/transpeer weights, coverage (§7, §8) |
| `transpeer/anchor/publisher.py` | curation from the peer store (§4.1), period rotation, issued-blob ring, solution records (§4.2, §4.3) |
| `transpeer/anchor/auxrpc.py` | aiohttp JSON-RPC server for the three P2Pool methods (§4.2) |
| `transpeer/config.py` | new fields and flags |
| `transpeer/peerstore.py` | `TranspeerEntry.first_seen` |
| `transpeer/server.py` | `/blob/{hash}`, `/blobs/index` (§5) |
| `transpeer/node.py` | start publisher and aux RPC server under `--anchor-publish` |
| `tests/test_anchor.py` | slice 1 unit checks (pure modules) |
| `tests/test_anchor_publish.py` | slice 2 checks: curation, rotation, RPC round trip with a P2Pool-style poller, blob endpoints |
| `README.md`, `CLAUDE.md`, spec §3.2/§17 | documentation |

---

### Task 1: Keccak-256

**Files:**
- Create: `transpeer/anchor/__init__.py`
- Create: `transpeer/anchor/keccak.py`
- Test: `tests/test_anchor.py`

**Interfaces:**
- Produces: `keccak256(data: bytes) -> bytes` (32 bytes). `CHAIN_ID: bytes` in `transpeer/anchor/__init__.py`.

- [ ] **Step 1: Write the failing test**

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=$PWD .venv/bin/python tests/test_anchor.py`
Expected: `ModuleNotFoundError: No module named 'transpeer.anchor'`

- [ ] **Step 3: Write the implementation**

`transpeer/anchor/__init__.py`:

```python
"""Chain-anchored publication of transpeer lists.

Spec: docs/spec-chain-anchored-publication.md. Everything here is
behind --anchor-publish (and, in a later slice, --anchor-read).
"""

import hashlib

# Spec §4.2: the merge-mined chain id the sidecar reports to P2Pool.
CHAIN_ID = hashlib.sha256(b"transpeer/anchor/v1").digest()
```

`transpeer/anchor/keccak.py`:

```python
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `PYTHONPATH=$PWD .venv/bin/python tests/test_anchor.py`
Expected: 5 PASS, `Results: 5 passed, 0 failed`

- [ ] **Step 5: Cross-check against a reference implementation (throwaway)**

Install pycryptodome into the scratchpad only (not the project venv) and compare on random inputs of lengths 0..300:

```bash
S=/tmp/claude-anchor-xcheck; mkdir -p $S && uv pip install --python .venv/bin/python --target $S pycryptodome -q && \
PYTHONPATH=$PWD:$S .venv/bin/python - <<'EOF'
import os
from Crypto.Hash import keccak
from transpeer.anchor.keccak import keccak256
for n in range(0, 301):
    d = os.urandom(n)
    ref = keccak.new(digest_bits=256, data=d).digest()
    assert keccak256(d) == ref, n
print("keccak256 matches pycryptodome on 301 lengths")
EOF
rm -rf $S
```

Expected: the final print line. If `uv` cannot reach the network, skip this step and say so in the commit message; the two fixed vectors in the test are the known Keccak-256 values for the empty string and `abc`.

- [ ] **Step 6: Commit**

```bash
git add transpeer/anchor/__init__.py transpeer/anchor/keccak.py tests/test_anchor.py
git commit -m "anchor: package skeleton, chain id and pure-Python Keccak-256

Keccak with the original 0x01 padding, as Monero and P2Pool use it;
hashlib.sha3_256 pads with 0x06 and differs. Cross-checked against
pycryptodome on random inputs of length 0-300.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01WkpMVTAKW7iLDzgTavyHVW"
```

---

### Task 2: Varint and list blob

**Files:**
- Create: `transpeer/anchor/varint.py`
- Create: `transpeer/anchor/blob.py`
- Modify: `tests/test_anchor.py`

**Interfaces:**
- Produces: `write_varint(v: int) -> bytes`, `read_varint(data: bytes, pos: int) -> tuple[int, int]` (value, new position).
- Produces: `PERIOD_SECONDS = 1500`, `MAX_ENTRIES = 64`, `MAX_BLOB_SIZE = 1024`, `class BlobError(ValueError)`, `class UnknownBlobVersion(BlobError)`, `@dataclass(frozen=True) Blob(chain: str, period: int, entries: tuple[tuple[str, int], ...])`, `encode_blob(chain: str, period: int, entries) -> bytes`, `decode_blob(data: bytes) -> Blob`, `blob_hash(data: bytes) -> bytes`, `list_body(data: bytes) -> bytes`, `with_period(body: bytes, period: int) -> bytes`, `period_of(unix: float) -> int`, `is_reserved(ip: str) -> bool`.

- [ ] **Step 1: Write the failing tests** (add to `tests/test_anchor.py` before `main`, and call them from `main`)

```python
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
```

- [ ] **Step 2: Run to verify failure**

Run: `PYTHONPATH=$PWD .venv/bin/python tests/test_anchor.py`
Expected: `ModuleNotFoundError: No module named 'transpeer.anchor.varint'`

- [ ] **Step 3: Implement**

`transpeer/anchor/varint.py`:

```python
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
```

`transpeer/anchor/blob.py`:

```python
"""The list blob, spec §3.1: a canonical byte string naming up to 64
transpeers, hashed with SHA-256 to make the aux leaf."""

import hashlib
import ipaddress
from dataclasses import dataclass

MAGIC = b"TPL1"
VERSION = 1
PERIOD_SECONDS = 1500
MAX_ENTRIES = 64
MAX_BLOB_SIZE = 1024

_RESERVED = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
    "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
    "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
)]


class BlobError(ValueError):
    """The bytes are not a canonical version-1 blob."""


class UnknownBlobVersion(BlobError):
    """Readers ignore these and do not count the commitment as unavailable."""


@dataclass(frozen=True)
class Blob:
    chain: str
    period: int
    entries: tuple[tuple[str, int], ...]


def is_reserved(ip: str) -> bool:
    a = ipaddress.IPv4Address(ip)
    return any(a in n for n in _RESERVED)


def period_of(unix: float) -> int:
    return int(unix) // PERIOD_SECONDS


def _entry_key(e: tuple[str, int]) -> tuple[int, int]:
    return int(ipaddress.IPv4Address(e[0])), e[1]


def _validate_entries(entries) -> list[tuple[str, int]]:
    if not 1 <= len(entries) <= MAX_ENTRIES:
        raise BlobError(f"count {len(entries)} not in 1..{MAX_ENTRIES}")
    out = []
    for ip, port in entries:
        try:
            ipaddress.IPv4Address(ip)
        except ValueError as e:
            raise BlobError(f"bad address {ip!r}") from e
        if not 1 <= port <= 65535:
            raise BlobError(f"bad port {port}")
        if is_reserved(ip):
            raise BlobError(f"reserved address {ip}")
        out.append((ip, port))
    out.sort(key=_entry_key)
    for a, b in zip(out, out[1:]):
        if a == b:
            raise BlobError(f"duplicate entry {a}")
    return out


def encode_blob(chain: str, period: int, entries) -> bytes:
    name = chain.encode("utf-8")
    if not 1 <= len(name) <= 255:
        raise BlobError("chain name length")
    if period < 0 or period >= 1 << 64:
        raise BlobError("period range")
    ents = _validate_entries(list(entries))
    out = bytearray(MAGIC)
    out.append(VERSION)
    out.append(len(name))
    out += name
    out += period.to_bytes(8, "little")
    out += len(ents).to_bytes(2, "little")
    for ip, port in ents:
        out += ipaddress.IPv4Address(ip).packed
        out += port.to_bytes(2, "little")
    if len(out) > MAX_BLOB_SIZE:
        raise BlobError("blob too large")
    return bytes(out)


def decode_blob(data: bytes) -> Blob:
    if len(data) > MAX_BLOB_SIZE:
        raise BlobError("blob too large")
    if data[:4] != MAGIC:
        raise BlobError("bad magic")
    if len(data) < 6:
        raise BlobError("truncated")
    if data[4] != VERSION:
        raise UnknownBlobVersion(f"version {data[4]}")
    n = data[5]
    if n == 0 or len(data) < 16 + n:
        raise BlobError("truncated header")
    try:
        chain = data[6:6 + n].decode("utf-8")
    except UnicodeDecodeError as e:
        raise BlobError("chain name not UTF-8") from e
    period = int.from_bytes(data[6 + n:14 + n], "little")
    count = int.from_bytes(data[14 + n:16 + n], "little")
    if len(data) != 16 + n + 6 * count:
        raise BlobError("length does not match count")
    raw = []
    for i in range(count):
        off = 16 + n + 6 * i
        raw.append((str(ipaddress.IPv4Address(data[off:off + 4])),
                    int.from_bytes(data[off + 4:off + 6], "little")))
    ents = _validate_entries(raw)
    if ents != raw:
        raise BlobError("entries not in canonical order")
    return Blob(chain, period, tuple(ents))


def blob_hash(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def with_period(body: bytes, period: int) -> bytes:
    n = body[5]
    return body[:6 + n] + period.to_bytes(8, "little") + body[14 + n:]


def list_body(data: bytes) -> bytes:
    """The blob with `period` zeroed: what a publisher's list *is*,
    independent of when it was reissued."""
    return with_period(data, 0)
```

- [ ] **Step 4: Run tests**

Run: `PYTHONPATH=$PWD .venv/bin/python tests/test_anchor.py`
Expected: all PASS, `0 failed`.

- [ ] **Step 5: Commit**

```bash
git add transpeer/anchor/varint.py transpeer/anchor/blob.py tests/test_anchor.py
git commit -m "anchor: list blob (spec 3.1) and Monero varint

Canonical form enforced on encode and decode: sorted unique entries,
reserved ranges rejected, 1-64 entries, exact length. list_body zeroes
the period so a reissued blob is recognised as the same list.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01WkpMVTAKW7iLDzgTavyHVW"
```

---

### Task 3: P2Pool Merkle tree, aux slot and merge-mining tag

**Files:**
- Create: `transpeer/anchor/merkle.py`
- Modify: `tests/test_anchor.py`

**Interfaces:**
- Consumes: `keccak256`, `write_varint`, `read_varint`.
- Produces: `merkle_tree(hashes: list[bytes]) -> list[list[bytes]]`, `merkle_root(hashes) -> bytes | None`, `merkle_proof(tree, leaf: bytes) -> tuple[list[bytes], int] | None`, `verify_merkle_proof(leaf, proof: list[bytes], path: int, root: bytes) -> bool`, `position_from_path(count: int, path: int) -> int`, `aux_slot(chain_id: bytes, nonce: int, n: int) -> int`, `find_aux_nonce(chain_ids: list[bytes]) -> int`, `encode_tree_params(n_aux_chains: int, nonce: int) -> int`, `decode_tree_params(v: int) -> tuple[int, int]`, `build_mm_tag(n_aux_chains, nonce, root) -> bytes`, `MM_TAG = 0x03`, `@dataclass(frozen=True) MergeMiningTag(n_aux_chains: int, nonce: int, root: bytes)`, `parse_tx_extra_mm_tag(extra: bytes) -> MergeMiningTag | None`.

- [ ] **Step 1: Write the failing tests**

```python
def test_merkle():
    from transpeer.anchor.keccak import keccak256
    from transpeer.anchor.merkle import (
        merkle_tree, merkle_root, merkle_proof, verify_merkle_proof,
        position_from_path, aux_slot, find_aux_nonce,
        encode_tree_params, decode_tree_params, build_mm_tag,
        parse_tx_extra_mm_tag, MM_TAG,
    )
    print("merkle")
    # Same leaves as P2Pool tests/src/merkle_tests.cpp TEST(merkle, tree).
    leaves = [keccak256(f"data {i}".encode()) for i in range(10)]
    check(merkle_root([]) is None, "empty root is None")
    check(merkle_root(leaves[:1]) == leaves[0], "single leaf is its own root")
    check(merkle_root(leaves[:2]) == keccak256(leaves[0] + leaves[1]), "two leaves")
    # Six leaves: first step pairs from the end (H0,H1,H(H2|H3),H(H4|H5)).
    l6 = leaves[:6]
    t = merkle_tree(l6)
    check(t[1] == [l6[0], l6[1], keccak256(l6[2] + l6[3]), keccak256(l6[4] + l6[5])],
          "non-power-of-two first step")
    check(len(t) == 4 and len(t[-1]) == 1, "tree height for 6 leaves")
    for n in range(1, 11):
        hs = leaves[:n]
        tree = merkle_tree(hs)
        root = merkle_root(hs)
        ok = tree[-1][0] == root and tree[0] == hs
        for idx, leaf in enumerate(hs):
            pr = merkle_proof(tree, leaf)
            ok = ok and pr is not None
            proof, path = pr
            ok = ok and verify_merkle_proof(leaf, proof, path, root)
            ok = ok and position_from_path(n, path) == idx
            ok = ok and not verify_merkle_proof(leaves[9 - idx] if n < 10 else b"\0" * 32,
                                                 proof, path, root)
        check(ok, f"proofs verify and positions round-trip, {n} leaves")
    check(merkle_proof(merkle_tree(leaves[:4]), b"\1" * 32) is None, "proof of absent leaf")
    # get_aux_slot vectors from P2Pool TEST(merkle, aux_slot): zero id.
    zid = bytes(32)
    exp = {0: 0, 1: 0, 2: 0, 3: 0, 4: 0, 5: 1, 6: 0, 7: 5, 8: 0, 9: 6}
    check(all(aux_slot(zid, 0, n) == s for n, s in exp.items()), "aux_slot small n")
    check(aux_slot(zid, 0, 0xFFFFFFFF) == 2389612776, "aux_slot nonce 0, n max")
    check(aux_slot(zid, 1, 0xFFFFFFFF) == 1080669337, "aux_slot nonce 1, n max")
    ids = [hashlib.sha256(bytes([i])).digest() for i in range(4)]
    nonce = find_aux_nonce(ids)
    check(len({aux_slot(c, nonce, 4) for c in ids}) == 4, "find_aux_nonce gives distinct slots")
    # encode_merkle_tree_data vectors from P2Pool TEST(merkle, params).
    vec = [((1, 0), 0), ((1, 0xFFFFFFFF), 0xFFFFFFFF0), ((127, 0), 0x3F6),
           ((127, 0xFFFFFFFF), 0x3FFFFFFFFF6), ((256, 0), 0x7FF),
           ((256, 0xFFFFFFFF), 0x7FFFFFFFFFF)]
    check(all(encode_tree_params(*a) == v for a, v in vec), "encode_tree_params vectors")
    check(all(decode_tree_params(v) == a for a, v in vec), "decode_tree_params vectors")
    root = merkle_root(leaves[:3])
    tag = build_mm_tag(3, 7, root)
    check(tag[0] == MM_TAG and tag[1] == len(tag) - 2 and tag[-32:] == root, "tag layout")
    extra = b"\x01" + bytes(32) + b"\x02\x03\x00\x00\x00" + tag
    got = parse_tx_extra_mm_tag(extra)
    check(got is not None and (got.n_aux_chains, got.nonce, got.root) == (3, 7, root),
          "parse tag after pubkey and extra nonce")
    check(parse_tx_extra_mm_tag(b"\x01" + bytes(32)) is None, "no tag -> None")
    check(parse_tx_extra_mm_tag(b"\x01" + bytes(32) + b"\x04\x01" + bytes(32) + tag) is not None,
          "tag after additional pubkeys")
    check(parse_tx_extra_mm_tag(tag[:-1]) is None, "truncated tag -> None")
```

- [ ] **Step 2: Run to verify failure**

Expected: `ModuleNotFoundError: No module named 'transpeer.anchor.merkle'`

- [ ] **Step 3: Implement** `transpeer/anchor/merkle.py`

```python
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
```

- [ ] **Step 4: Run tests**

Expected: all PASS, `0 failed`. If any `proofs verify ... N leaves` check fails, compare `merkle_proof` line by line with the C++ `get_merkle_proof` in the docstring's source; do not "fix" by changing `verify_merkle_proof`.

- [ ] **Step 5: Commit**

```bash
git add transpeer/anchor/merkle.py tests/test_anchor.py
git commit -m "anchor: P2Pool Merkle tree, aux slot and merge-mining tag

Transcribed from p2pool v4.18 merkle.cpp / pool_block.h; aux-slot and
tree-params vectors are P2Pool's own (merkle_tests.cpp). Proof paths
round-trip through position_from_path for 1-10 leaves.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01WkpMVTAKW7iLDzgTavyHVW"
```

---

### Task 4: Monero block blob parse and build

**Files:**
- Create: `transpeer/anchor/monero.py`
- Modify: `tests/test_anchor.py`

**Interfaces:**
- Consumes: `read_varint`, `write_varint`, `parse_tx_extra_mm_tag`.
- Produces: `@dataclass(frozen=True) BlockHead(major: int, minor: int, timestamp: int, prev_id: bytes, nonce: int, height: int, tx_extra: bytes, n_tx_hashes: int)`, `parse_block_blob(blob: bytes) -> BlockHead` (raises `ValueError`), `build_block_blob(major, minor, timestamp, prev_id, nonce, height, tx_extra, tx_hashes=()) -> bytes`.

Why: `merge_mining_submit_solution` hands the sidecar the Monero block template blob; the sidecar needs the coinbase `tx_extra` to find the tag root the proof must match (§3.2, §6.3). The builder exists for tests now and the Shadow venue oracle later.

- [ ] **Step 1: Write the failing test**

```python
def test_monero_block():
    from transpeer.anchor.monero import parse_block_blob, build_block_blob
    from transpeer.anchor.merkle import build_mm_tag, parse_tx_extra_mm_tag
    print("monero block blob")
    tag = build_mm_tag(2, 5, b"\x42" * 32)
    extra = b"\x01" + bytes(32) + b"\x02\x04\x00\x00\x00\x00" + tag
    prev = b"\x11" * 32
    blob = build_block_blob(16, 16, 1_700_000_000, prev, 0xDEADBEEF, 3_000_000, extra,
                            tx_hashes=[b"\x22" * 32, b"\x33" * 32])
    h = parse_block_blob(blob)
    check((h.major, h.minor, h.timestamp) == (16, 16, 1_700_000_000), "header varints")
    check(h.prev_id == prev and h.nonce == 0xDEADBEEF, "prev_id and nonce")
    check(h.height == 3_000_000, "height from miner tx input")
    check(h.tx_extra == extra and h.n_tx_hashes == 2, "tx_extra and tx count")
    check(parse_tx_extra_mm_tag(h.tx_extra).root == b"\x42" * 32, "tag reachable")
    check(blob[-64:] == b"\x22" * 32 + b"\x33" * 32, "tx hashes at the end")
    try:
        parse_block_blob(blob[:40])
        check(False, "truncated blob raises")
    except ValueError:
        check(True, "truncated blob raises")
```

- [ ] **Step 2: Run to verify failure**

Expected: `ModuleNotFoundError: No module named 'transpeer.anchor.monero'`

- [ ] **Step 3: Implement** `transpeer/anchor/monero.py`

```python
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
```

- [ ] **Step 4: Run tests**

Expected: all PASS, `0 failed`.

- [ ] **Step 5: Commit**

```bash
git add transpeer/anchor/monero.py tests/test_anchor.py
git commit -m "anchor: Monero block blob codec for the coinbase tag

Enough to reach tx_extra in the template that P2Pool sends with
merge_mining_submit_solution, and to build synthetic blocks for tests
and the simulation oracle.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01WkpMVTAKW7iLDzgTavyHVW"
```

---

### Task 5: Commitment records and the blob database

**Files:**
- Create: `transpeer/anchor/blobdb.py`
- Modify: `tests/test_anchor.py`

**Interfaces:**
- Consumes: `blob_hash`, `list_body`, `with_period`, `decode_blob`.
- Produces:
  ```python
  @dataclass(frozen=True)
  class Commitment:
      hash: bytes; kind: str; venue: str; ref: str; publisher: str
      difficulty: int; timestamp: int
      proof: tuple[bytes, ...] = (); path: int = 0
      def to_dict(self) -> dict; @staticmethod def from_dict(d) -> "Commitment"
  class BlobDB:
      def __init__(self)
      def add(self, blob: bytes, commitment: Commitment, now: int) -> bool   # False if hash mismatch or blob invalid
      def get(self, h: bytes) -> bytes | None
      def commitments(self, h: bytes) -> list[Commitment]
      def index_since(self, since: int, limit: int = 500) -> list[tuple[bytes, int, list[Commitment]]]  # (hash, first_seen, records) sorted by first_seen
      def entries_of(self, h: bytes) -> tuple[tuple[str, int], ...]
      def body_count(self) -> int; def blob_count(self) -> int; def commitment_count(self) -> int
      def has_body_entry(self, addr: str, port: int) -> bool   # for curation continuity, §4.1 rule 5
      def to_json(self) -> dict; @staticmethod def from_json(d) -> "BlobDB"
      def save(self, path: Path); @staticmethod def load(path: Path) -> "BlobDB"
  ```
- Kinds: `"share"`, `"block"` (spec §3.2) and `"template"` (added in Task 14's spec edit: recorded by a publisher from `merge_mining_submit_solution`; carries no weight until the share or block is observed).

- [ ] **Step 1: Write the failing test**

```python
def test_blobdb():
    import tempfile
    from transpeer.anchor.blob import encode_blob, blob_hash, list_body
    from transpeer.anchor.blobdb import BlobDB, Commitment
    print("blob database")
    db = BlobDB()
    b1 = encode_blob("monero", 100, [("8.8.8.8", 7337), ("1.1.1.1", 7337)])
    b2 = encode_blob("monero", 101, [("8.8.8.8", 7337), ("1.1.1.1", 7337)])  # same body
    b3 = encode_blob("monero", 101, [("9.9.9.9", 7337)])
    c1 = Commitment(blob_hash(b1), "share", "venue-a", "share:1", "wallet-x", 1000, 5000)
    check(db.add(b1, c1, now=5001), "add first blob")
    check(not db.add(b1, Commitment(b"\0" * 32, "share", "v", "r", "p", 1, 1), now=5002),
          "reject commitment whose hash mismatches")
    check(not db.add(b1 + b"\x00", Commitment(blob_hash(b1 + b"\x00"), "share", "v", "r", "p", 1, 1), 5002),
          "reject non-canonical blob")
    c2 = Commitment(blob_hash(b2), "block", "", "3000000:aa", "wallet-x", 10 ** 9, 6000, (b"\x01" * 32,), 1)
    check(db.add(b2, c2, now=6001), "add reissue of same body")
    check(db.body_count() == 1 and db.blob_count() == 2 and db.commitment_count() == 2,
          "body stored once, two blobs, two commitments")
    check(db.get(blob_hash(b2)) == b2 and db.get(blob_hash(b1)) == b1, "reconstruct blobs from body+period")
    check(db.get(b"\x07" * 32) is None, "missing hash")
    c1b = Commitment(blob_hash(b1), "share", "venue-a", "share:2", "wallet-x", 1200, 5100)
    check(db.add(b1, c1b, now=5101) and len(db.commitments(blob_hash(b1))) == 2, "second commitment appended")
    check(db.add(b1, c1b, now=5102) and len(db.commitments(blob_hash(b1))) == 2, "duplicate commitment ignored")
    check(db.add(b3, Commitment(blob_hash(b3), "share", "venue-b", "share:9", "w2", 7, 7000), 7001), "third blob")
    idx = db.index_since(5500)
    check([h for h, _, _ in idx] == [blob_hash(b2), blob_hash(b3)], "index_since filters and orders by first_seen")
    check(db.index_since(0, limit=1)[0][0] == blob_hash(b1), "index limit")
    check(db.has_body_entry("1.1.1.1", 7337) and not db.has_body_entry("1.1.1.1", 1), "has_body_entry")
    check(db.entries_of(blob_hash(b3)) == (("9.9.9.9", 7337),), "entries_of")
    # Persistence round trip.
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "anchor_blobs.json"
        db.save(p)
        db2 = BlobDB.load(p)
        check(db2.blob_count() == 3 and db2.get(blob_hash(b2)) == b2, "save/load blobs")
        check(db2.commitments(blob_hash(b2))[0] == c2, "save/load commitment with proof")
        check(BlobDB.load(Path(d) / "missing.json").blob_count() == 0, "load missing file -> empty")
```

- [ ] **Step 2: Run to verify failure**

Expected: `ModuleNotFoundError: No module named 'transpeer.anchor.blobdb'`

- [ ] **Step 3: Implement** `transpeer/anchor/blobdb.py`

```python
"""Content-addressed store of list blobs and their commitment records,
spec §3.2 and §3.3. A body (blob with period zeroed) is stored once;
each blob hash maps to (body hash, period)."""

import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from .blob import BlobError, blob_hash, decode_blob, list_body, with_period

KINDS = ("share", "block", "template")


@dataclass(frozen=True)
class Commitment:
    hash: bytes
    kind: str
    venue: str
    ref: str
    publisher: str
    difficulty: int
    timestamp: int
    proof: tuple[bytes, ...] = ()
    path: int = 0

    def to_dict(self) -> dict:
        return {
            "hash": self.hash.hex(), "kind": self.kind, "venue": self.venue,
            "ref": self.ref, "publisher": self.publisher,
            "difficulty": self.difficulty, "timestamp": self.timestamp,
            "proof": [p.hex() for p in self.proof], "path": self.path,
        }

    @staticmethod
    def from_dict(d: dict) -> "Commitment":
        return Commitment(
            bytes.fromhex(d["hash"]), d["kind"], d["venue"], d["ref"], d["publisher"],
            int(d["difficulty"]), int(d["timestamp"]),
            tuple(bytes.fromhex(p) for p in d.get("proof", [])), int(d.get("path", 0)),
        )


@dataclass
class _BlobRow:
    body_hash: bytes
    period: int
    first_seen: int
    commitments: list[Commitment] = field(default_factory=list)


class BlobDB:
    def __init__(self):
        self._bodies: dict[bytes, bytes] = {}       # body hash -> body bytes
        self._blobs: dict[bytes, _BlobRow] = {}     # blob hash -> row
        self._entries: set[tuple[str, int]] = set()

    def add(self, blob: bytes, commitment: Commitment, now: int) -> bool:
        h = blob_hash(blob)
        if commitment.hash != h or commitment.kind not in KINDS:
            return False
        try:
            decoded = decode_blob(blob)
        except BlobError:
            return False
        row = self._blobs.get(h)
        if row is None:
            body = list_body(blob)
            bh = hashlib.sha256(body).digest()
            self._bodies.setdefault(bh, body)
            row = _BlobRow(bh, decoded.period, now)
            self._blobs[h] = row
            self._entries.update(decoded.entries)
        if commitment not in row.commitments:
            row.commitments.append(commitment)
        return True

    def get(self, h: bytes) -> bytes | None:
        row = self._blobs.get(h)
        if row is None:
            return None
        return with_period(self._bodies[row.body_hash], row.period)

    def commitments(self, h: bytes) -> list[Commitment]:
        row = self._blobs.get(h)
        return list(row.commitments) if row else []

    def entries_of(self, h: bytes) -> tuple[tuple[str, int], ...]:
        b = self.get(h)
        return decode_blob(b).entries if b else ()

    def has_body_entry(self, addr: str, port: int) -> bool:
        return (addr, port) in self._entries

    def index_since(self, since: int, limit: int = 500) -> list[tuple[bytes, int, list[Commitment]]]:
        rows = [(h, r.first_seen, list(r.commitments))
                for h, r in self._blobs.items() if r.first_seen > since]
        rows.sort(key=lambda t: (t[1], t[0]))
        return rows[:limit]

    def body_count(self) -> int:
        return len(self._bodies)

    def blob_count(self) -> int:
        return len(self._blobs)

    def commitment_count(self) -> int:
        return sum(len(r.commitments) for r in self._blobs.values())

    def to_json(self) -> dict:
        return {
            "version": 1,
            "bodies": {k.hex(): v.hex() for k, v in self._bodies.items()},
            "blobs": {
                h.hex(): {
                    "body": r.body_hash.hex(), "period": r.period,
                    "first_seen": r.first_seen,
                    "commitments": [c.to_dict() for c in r.commitments],
                } for h, r in self._blobs.items()
            },
        }

    @staticmethod
    def from_json(d: dict) -> "BlobDB":
        db = BlobDB()
        if d.get("version") != 1:
            return db
        db._bodies = {bytes.fromhex(k): bytes.fromhex(v) for k, v in d["bodies"].items()}
        for h, r in d["blobs"].items():
            row = _BlobRow(bytes.fromhex(r["body"]), int(r["period"]), int(r["first_seen"]),
                           [Commitment.from_dict(c) for c in r["commitments"]])
            db._blobs[bytes.fromhex(h)] = row
            db._entries.update(decode_blob(with_period(db._bodies[row.body_hash], row.period)).entries)
        return db

    def save(self, path: Path) -> None:
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(self.to_json()))
        os.replace(tmp, path)

    @staticmethod
    def load(path: Path) -> "BlobDB":
        if not path.exists():
            return BlobDB()
        return BlobDB.from_json(json.loads(path.read_text()))
```

- [ ] **Step 4: Run tests**

Expected: all PASS, `0 failed`.

- [ ] **Step 5: Commit**

```bash
git add transpeer/anchor/blobdb.py tests/test_anchor.py
git commit -m "anchor: commitment records and content-addressed blob database

Bodies stored once, blobs reconstructed from body plus period (spec
3.3). add() refuses a commitment whose hash does not match the bytes
and any non-canonical blob; verifying the commitment itself is the
caller's job. JSON persistence with atomic replace.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01WkpMVTAKW7iLDzgTavyHVW"
```

---

### Task 6: Weighting and coverage

**Files:**
- Create: `transpeer/anchor/weight.py`
- Modify: `tests/test_anchor.py`

**Interfaces:**
- Consumes: `BlobDB.entries_of`, `CHAIN_ID`.
- Produces:
  ```python
  @dataclass(frozen=True)
  class Share:
      id: bytes; venue: str; height: int; parent: bytes; difficulty: int
      timestamp: int; wallet: str; aux: dict[bytes, bytes]   # chain id -> aux hash
  def canonical_window(shares: dict[bytes, Share], tip: bytes, window: int) -> list[Share]
  def blob_weights(canonical: Iterable[Share], chain_id: bytes = CHAIN_ID) -> dict[bytes, int]
  def transpeer_weights(bw: dict[bytes, int], db: BlobDB) -> dict[tuple[str, int], int]
  def publisher_weights(canonical, chain_id=CHAIN_ID) -> dict[str, int]
  BOOTSTRAP_COVERAGE = 0.5
  def coverage(tagged: int, resolved: int) -> float
  def bootstrapped(tagged: int, resolved: int) -> bool
  ```

- [ ] **Step 1: Write the failing test**

```python
def test_weight():
    from transpeer.anchor import CHAIN_ID
    from transpeer.anchor.blob import encode_blob, blob_hash
    from transpeer.anchor.blobdb import BlobDB, Commitment
    from transpeer.anchor.weight import (
        Share, canonical_window, blob_weights, transpeer_weights,
        publisher_weights, coverage, bootstrapped, BOOTSTRAP_COVERAGE,
    )
    print("weighting and coverage")
    ba = encode_blob("monero", 1, [("1.1.1.1", 7337), ("2.2.2.2", 7337)])
    bb = encode_blob("monero", 1, [("2.2.2.2", 7337), ("3.3.3.3", 7337)])
    ha, hb = blob_hash(ba), blob_hash(bb)
    db = BlobDB()
    db.add(ba, Commitment(ha, "share", "v", "s1", "wa", 1, 1), 1)
    db.add(bb, Commitment(hb, "share", "v", "s2", "wb", 1, 1), 1)

    def mk(i, parent, diff, aux, wallet="w"):
        return Share(bytes([i]) * 32, "v", i, parent, diff, 1000 + i, wallet, aux)
    s = {}
    s[bytes([1]) * 32] = mk(1, bytes(32), 100, {CHAIN_ID: ha}, "wa")
    s[bytes([2]) * 32] = mk(2, bytes([1]) * 32, 200, {CHAIN_ID: hb}, "wb")
    s[bytes([3]) * 32] = mk(3, bytes([2]) * 32, 300, {}, "wc")
    s[bytes([4]) * 32] = mk(4, bytes([3]) * 32, 400, {CHAIN_ID: ha}, "wa")
    s[bytes([9]) * 32] = mk(9, bytes([2]) * 32, 9999, {CHAIN_ID: hb}, "wb")  # off-fork
    win = canonical_window(s, bytes([4]) * 32, window=3)
    check([x.height for x in win] == [4, 3, 2], "walk parents from tip, window 3")
    check([x.height for x in canonical_window(s, bytes([4]) * 32, 10)] == [4, 3, 2, 1],
          "walk stops at unknown parent")
    bw = blob_weights(win)
    check(bw == {ha: 400, hb: 200}, "blob weight sums share difficulty on the canonical fork only")
    tw = transpeer_weights(bw, db)
    check(tw == {("1.1.1.1", 7337): 400, ("2.2.2.2", 7337): 600, ("3.3.3.3", 7337): 200},
          "transpeer weight sums over blobs listing it")
    check(publisher_weights(win) == {"wa": 400, "wb": 200}, "publisher weights (diagnostic)")
    check(blob_weights(win, chain_id=b"\x00" * 32) == {}, "other chain id contributes nothing")
    check(coverage(10, 5) == 0.5 and coverage(0, 0) == 0.0, "coverage ratio")
    check(bootstrapped(10, 5) and not bootstrapped(10, 4) and BOOTSTRAP_COVERAGE == 0.5,
          "bootstrapped at one half")
```

- [ ] **Step 2: Run to verify failure**

Expected: `ModuleNotFoundError: No module named 'transpeer.anchor.weight'`

- [ ] **Step 3: Implement** `transpeer/anchor/weight.py`

```python
"""Difficulty-weighted, venue-additive weighting (spec §7) and the
coverage rule (§8). Pure functions over verified shares."""

from collections import defaultdict
from dataclasses import dataclass
from typing import Iterable

from . import CHAIN_ID
from .blobdb import BlobDB

BOOTSTRAP_COVERAGE = 0.5


@dataclass(frozen=True)
class Share:
    id: bytes
    venue: str
    height: int
    parent: bytes
    difficulty: int
    timestamp: int
    wallet: str
    aux: dict  # chain id (bytes) -> aux hash (bytes)


def canonical_window(shares: dict, tip: bytes, window: int) -> list:
    """Shares on the fork ending at `tip`, newest first, at most
    `window` of them; stops at a parent that is not known."""
    out = []
    cur = shares.get(tip)
    while cur is not None and len(out) < window:
        out.append(cur)
        cur = shares.get(cur.parent)
    return out


def blob_weights(canonical: Iterable[Share], chain_id: bytes = CHAIN_ID) -> dict:
    w: dict = defaultdict(int)
    for s in canonical:
        h = s.aux.get(chain_id)
        if h is not None:
            w[h] += s.difficulty
    return dict(w)


def publisher_weights(canonical: Iterable[Share], chain_id: bytes = CHAIN_ID) -> dict:
    w: dict = defaultdict(int)
    for s in canonical:
        if chain_id in s.aux:
            w[s.wallet] += s.difficulty
    return dict(w)


def transpeer_weights(bw: dict, db: BlobDB) -> dict:
    w: dict = defaultdict(int)
    for h, weight in bw.items():
        for entry in db.entries_of(h):
            w[entry] += weight
    return dict(w)


def coverage(tagged: int, resolved: int) -> float:
    return resolved / tagged if tagged else 0.0


def bootstrapped(tagged: int, resolved: int) -> bool:
    return coverage(tagged, resolved) >= BOOTSTRAP_COVERAGE
```

- [ ] **Step 4: Run tests**

Expected: all PASS, `0 failed`. Then run the three existing suites; expected 24/24, 47/47, 19/19 unchanged.

- [ ] **Step 5: Commit**

```bash
git add transpeer/anchor/weight.py tests/test_anchor.py
git commit -m "anchor: difficulty weighting over the canonical fork and coverage rule

Venues are additive with no per-venue quota (spec 7); coverage is
resolved tagged blocks over all tagged blocks with the bootstrap
threshold at one half (spec 8).

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01WkpMVTAKW7iLDzgTavyHVW"
```

Slice 1 ends here. Everything above is pure and unit tested.

---

### Task 7: Config flags and `TranspeerEntry.first_seen`

**Files:**
- Modify: `transpeer/config.py` (Config fields after `contact`; parser after `--no-scan`; constructor)
- Modify: `transpeer/peerstore.py` (`TranspeerEntry`, `add_transpeer`)
- Modify: `tests/test_bucketed.py` (one check), create `tests/test_anchor_publish.py`

**Interfaces:**
- Produces: Config fields `anchor_publish: bool = False`, `anchor_chain: str = "monero"`, `aux_rpc_bind: str = "127.0.0.1"`, `aux_rpc_port: int = 7338`, `aux_diff: int = 100000`, `anchor_min_age: float = 14.0` (days), `anchor_max_new: float = 0.25`; `TranspeerEntry.first_seen: int = 0` set on first `add_transpeer`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_anchor_publish.py`:

```python
#!/usr/bin/env python3
"""Checks for the publisher side of chain-anchored publication:
curation, period rotation, the aux-chain JSON-RPC server driven by a
P2Pool-style poller, and the blob endpoints. Loopback only, no PoW.

Run:  PYTHONPATH=$PWD .venv/bin/python tests/test_anchor_publish.py
"""

import asyncio
import hashlib
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from transpeer.config import Config  # noqa: E402
from transpeer.peerstore import PeerStore, TranspeerEntry  # noqa: E402

passed = failed = 0


def check(cond, name):
    global passed, failed
    if cond:
        passed += 1
        print(f"  PASS: {name}")
    else:
        failed += 1
        print(f"  FAIL: {name}")


async def test_config_and_first_seen():
    print("config and first_seen")
    c = Config()
    check(c.anchor_publish is False and c.aux_rpc_port == 7338 and c.aux_rpc_bind == "127.0.0.1",
          "anchor flags default off, loopback RPC")
    check(c.anchor_chain == "monero" and c.aux_diff == 100000 and c.anchor_min_age == 14.0
          and c.anchor_max_new == 0.25, "anchor defaults")
    store = PeerStore(Config(in_memory=True, no_verify=True))
    await store.init()
    t0 = int(time.time())
    store.add_transpeer(TranspeerEntry("5.5.5.5", 7337, ["monero"], last_seen=t0))
    e = store.get_transpeer("5.5.5.5", 7337)
    check(e is not None and e.first_seen == t0, "first_seen set on first add")
    store.add_transpeer(TranspeerEntry("5.5.5.5", 7337, ["monero"], last_seen=t0 + 100))
    e = store.get_transpeer("5.5.5.5", 7337)
    check(e.first_seen == t0 and e.last_seen == t0 + 100, "first_seen kept on re-add")
    await store.close()


async def main():
    await test_config_and_first_seen()
    print(f"\nResults: {passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    asyncio.run(main())
```

Before writing the test, read `transpeer/peerstore.py` around `add_transpeer` (about line 540–570) to confirm its signature: if it takes an entry object, the test above is right; if it takes `(addr, port, networks, ...)` keyword arguments, adapt the two `add_transpeer` calls to that signature and keep the assertions.

- [ ] **Step 2: Run to verify failure**

Run: `PYTHONPATH=$PWD .venv/bin/python tests/test_anchor_publish.py`
Expected: FAIL on "anchor flags default off" (AttributeError) or on `first_seen`.

- [ ] **Step 3: Implement**

In `transpeer/config.py`, append to the `Config` dataclass after `contact: str = ""`:

```python
    # Chain-anchored publication (docs/spec-chain-anchored-publication.md).
    anchor_publish: bool = False
    anchor_chain: str = "monero"
    aux_rpc_bind: str = "127.0.0.1"
    aux_rpc_port: int = 7338
    aux_diff: int = 100000
    anchor_min_age: float = 14.0   # days a transpeer must have been known (spec 4.1 rule 1)
    anchor_max_new: float = 0.25   # share of entries allowed without a committed history (rule 5)
```

In `parse_args()`, after the `--no-scan` argument:

```python
    parser.add_argument(
        "--anchor-publish", action="store_true",
        help="Publish this node's curated transpeer list through a local "
        "P2Pool node's merge-mining interface (point p2pool at "
        "--merge-mine AUX_RPC_BIND:AUX_RPC_PORT WALLET). Default off.",
    )
    parser.add_argument("--anchor-chain", default="monero",
                        help="Anchor chain name written into the list blob.")
    parser.add_argument("--aux-rpc-bind", default="127.0.0.1",
                        help="Bind address of the aux-chain JSON-RPC server P2Pool polls.")
    parser.add_argument("--aux-rpc-port", type=int, default=7338,
                        help="Port of the aux-chain JSON-RPC server.")
    parser.add_argument(
        "--aux-diff", type=int, default=100000,
        help="aux_diff reported to P2Pool. Set it to the venue's minimum "
        "share difficulty so every share is reported back with its proof.",
    )
    parser.add_argument("--anchor-min-age", type=float, default=14.0,
                        help="Days a transpeer must have been known before it is published.")
    parser.add_argument("--anchor-max-new", type=float, default=0.25,
                        help="Largest share of published entries without a committed history.")
```

In the `return Config(...)` call add:

```python
        anchor_publish=args.anchor_publish,
        anchor_chain=args.anchor_chain,
        aux_rpc_bind=args.aux_rpc_bind,
        aux_rpc_port=args.aux_rpc_port,
        aux_diff=args.aux_diff,
        anchor_min_age=args.anchor_min_age,
        anchor_max_new=args.anchor_max_new,
```

In `transpeer/peerstore.py`, add to `TranspeerEntry` after `native: dict = field(default_factory=dict)`:

```python
    first_seen: int = 0
```

In `add_transpeer` (around line 540–570), where the existing entry is updated or a new one inserted, ensure: on a new entry `entry.first_seen = entry.last_seen or int(time.time())` when `first_seen` is 0; on an existing entry keep its `first_seen`. Read the function first; the change is two lines. If `to_dict()`/`from_dict()` on `TranspeerEntry` enumerate fields explicitly, add `first_seen` there too.

- [ ] **Step 4: Run tests**

Run: `PYTHONPATH=$PWD .venv/bin/python tests/test_anchor_publish.py` → 4 PASS. Then all three existing suites: 24/24, 47/47, 19/19. `PYTHONPATH=$PWD .venv/bin/python -m transpeer --help | grep anchor` shows the new flags.

- [ ] **Step 5: Commit**

```bash
git add transpeer/config.py transpeer/peerstore.py tests/test_anchor_publish.py
git commit -m "anchor: publisher flags (default off) and TranspeerEntry.first_seen

first_seen is what the curation age rule (spec 4.1 rule 1) needs and
the store did not keep it.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01WkpMVTAKW7iLDzgTavyHVW"
```

---

### Task 8: Curation and the publisher

**Files:**
- Create: `transpeer/anchor/publisher.py`
- Modify: `tests/test_anchor_publish.py`

**Interfaces:**
- Consumes: `PeerStore.get_transpeers() -> list[TranspeerEntry]`, `PeerStore.get_source_trust(addr) -> SourceTrust` with `verified_alive`, `verified_dead` (read `transpeer/peerstore.py:117-154` and `230-234` to confirm names before coding), `TranspeerEntry.{addr, port, first_seen, answered, alive, native}`, `BlobDB.has_body_entry`, `encode_blob`, `blob_hash`, `list_body`, `with_period`, `period_of`.
- Produces:
  ```python
  @dataclass(frozen=True)
  class Solution:
      aux_hash: bytes; height: int; prev_id: bytes; timestamp: int
      root: bytes; proof: tuple[bytes, ...]; path: int; seed_hash: bytes
      address: str; received: int
  class Publisher:
      ISSUED_KEEP = 8 * 24 * 60 * 60 // 1500 + 8   # a week of periods plus P2Pool's ring
      def __init__(self, config: Config, store: PeerStore, db: BlobDB, clock=time.time)
      def curate(self, now: float | None = None) -> list[tuple[str, int]]
      def refresh(self, now: float | None = None) -> bool     # re-curate if due; True if the body changed
      def current(self, now: float | None = None) -> tuple[bytes, bytes] | None  # (aux_hash, blob) or None when nothing to publish
      def lookup(self, aux_hash: bytes) -> bytes | None        # any issued blob
      def record_solution(self, sol: Solution) -> None
      body: bytes | None; body_since: float; address: str; solutions: list[Solution]
  ```

Curation, spec §4.1, applied in this order to `store.get_transpeers()`:
1. History: `now - first_seen >= anchor_min_age * 86400`, `answered >= 1` and `alive` (the last query was answered). (`first_seen == 0` fails.)
2. Quality: with `t = store.get_source_trust(addr)`, if `t.verified_alive + t.verified_dead >= 5` require `verified_alive / (alive + dead) >= 0.8`; with fewer than 5 verifications the rule is not applied (a node started with `--no-verify` has no data).
3. Native: if `entry.native` is non-empty require `any(entry.native.values())`; an empty dict (native probing off) leaves the rule unapplied.
4. Diversity: one entry per `/16`, keeping the highest `answered`.
5. Continuity: if `db.blob_count() > 0`, entries with `db.has_body_entry(addr, port)` are "continuing"; at most `floor(anchor_max_new * total)` non-continuing entries are kept (highest `answered` first). With an empty database every entry counts as continuing.
6. Faithfulness: not available until slice 3 (challenges). Leave a comment naming spec §9.
Finally: sort by `answered` descending, cut to `MAX_ENTRIES`, drop reserved addresses (`is_reserved`), and return sorted by `(addr, port)` as `encode_blob` will order them.

Refresh rule (spec §4.1 last paragraph): re-curate when there is no body, when the body is older than 86400 s, or when any entry of the current body is no longer `alive` in the store. Only replace the body if the curated list differs.

- [ ] **Step 1: Write the failing tests** (add to `tests/test_anchor_publish.py`; call from `main`)

```python
def _add(store, addr, port=7337, first_seen=0, answered=1, alive=True, native=None):
    """Insert a transpeer and set the fields curation reads. Patching the
    stored entry after add_transpeer keeps the test independent of which
    fields add_transpeer copies from its argument."""
    store.add_transpeer(TranspeerEntry(addr, port, ["monero"], last_seen=first_seen + 1))
    e = store.get_transpeer(addr, port)
    e.first_seen = first_seen
    e.answered = answered
    e.alive = alive
    if native is not None:
        e.native = native
    return e


async def test_curation_and_rotation():
    from transpeer.anchor.blob import decode_blob, blob_hash, list_body, PERIOD_SECONDS
    from transpeer.anchor.blobdb import BlobDB, Commitment
    from transpeer.anchor.publisher import Publisher, Solution
    print("curation and rotation")
    now = 2_000_000_000
    old = now - 20 * 86400
    cfg = Config(in_memory=True, no_verify=True, anchor_publish=True)
    store = PeerStore(cfg)
    await store.init()
    db = BlobDB()
    pub = Publisher(cfg, store, db, clock=lambda: now)
    check(pub.current() is None, "nothing to publish from an empty store")
    for addr, kw in [
        ("20.0.0.1", dict(first_seen=old, answered=9)),
        ("20.0.0.2", dict(first_seen=old, answered=5)),          # same /16 as .1, lower answered
        ("21.0.0.1", dict(first_seen=now - 3600, answered=9)),   # too young
        ("22.0.0.1", dict(first_seen=old, answered=0)),          # never answered
        ("23.0.0.1", dict(first_seen=old, answered=3, native={"monero": False})),  # native probe failed
        ("24.0.0.1", dict(first_seen=old, answered=3, native={"monero": True})),
        ("25.0.0.1", dict(first_seen=old, answered=2)),
        ("10.0.0.1", dict(first_seen=old, answered=7)),          # reserved
    ]:
        _add(store, addr, **kw)
    cur = pub.curate()
    check(cur == [("20.0.0.1", 7337), ("24.0.0.1", 7337), ("25.0.0.1", 7337)],
          "history, native, diversity and reserved rules")
    # Continuity: with a committed history, at most a quarter may be new.
    import transpeer.anchor.blob as blobmod
    prior = blobmod.encode_blob("monero", 1, [("20.0.0.1", 7337), ("24.0.0.1", 7337),
                                              ("30.0.0.1", 7337), ("31.0.0.1", 7337)])
    db.add(prior, Commitment(blob_hash(prior), "share", "v", "s", "w", 1, now), now)
    _add(store, "26.0.0.1", first_seen=old, answered=8)
    cur = pub.curate()
    check(("25.0.0.1", 7337) not in cur and ("26.0.0.1", 7337) in cur and len(cur) == 3,
          "continuity keeps at most floor(0.25*n) new entries, highest answered first")
    # Rotation.
    check(pub.refresh() is True, "first refresh sets a body")
    h1, b1 = pub.current()
    check(decode_blob(b1).period == now // PERIOD_SECONDS and h1 == blob_hash(b1), "current blob at this period")
    check(pub.refresh() is False, "refresh within a day with same list changes nothing")
    now += PERIOD_SECONDS
    h2, b2 = pub.current()
    check(h2 != h1 and list_body(b2) == list_body(b1), "next period: new hash, same body")
    check(pub.lookup(h1) == b1 and pub.lookup(h2) == b2, "both issued blobs served")
    check(pub.lookup(b"\0" * 32) is None, "unknown hash")
    # A dead entry forces re-curation.
    store.mark_queried("26.0.0.1", 7337, answered=False)
    check(pub.refresh() is True and ("26.0.0.1", 7337) not in decode_blob(pub.current()[1]).entries,
          "dead entry triggers a new body without it")
    # Solutions are kept.
    sol = Solution(h2, 3_000_000, b"\x11" * 32, now, b"\x22" * 32, (b"\x33" * 32,), 1, b"\x44" * 32, "wallet", now)
    pub.record_solution(sol)
    check(pub.solutions == [sol], "solution recorded")
    await store.close()
```

Note on `mark_queried`: its signature is `mark_queried(addr, port, answered=False)` and it sets `alive`; confirm at `transpeer/peerstore.py:649-657`.

- [ ] **Step 2: Run to verify failure**

Expected: `ModuleNotFoundError: No module named 'transpeer.anchor.publisher'`

- [ ] **Step 3: Implement** `transpeer/anchor/publisher.py`

```python
"""The publisher: curates a list from the peer store (spec §4.1),
issues it as a blob that rotates every period (§3.1, §4.2), serves
every blob it has issued (§4.3) and records the solutions P2Pool
reports."""

import ipaddress
import time
from collections import OrderedDict
from dataclasses import dataclass

from ..config import Config
from ..peerstore import PeerStore
from .blob import MAX_ENTRIES, blob_hash, encode_blob, is_reserved, list_body, period_of, with_period
from .blobdb import BlobDB

BODY_MAX_AGE = 86400       # spec §4.1: at most one new list body per day
QUALITY_MIN_SAMPLES = 5
QUALITY_MIN_RATE = 0.8


@dataclass(frozen=True)
class Solution:
    aux_hash: bytes
    height: int
    prev_id: bytes
    timestamp: int
    root: bytes
    proof: tuple
    path: int
    seed_hash: bytes
    address: str
    received: int


class Publisher:
    ISSUED_KEEP = 8 * 24 * 60 * 60 // 1500 + 8

    def __init__(self, config: Config, store: PeerStore, db: BlobDB, clock=time.time):
        self.config = config
        self.store = store
        self.db = db
        self.clock = clock
        self.body: bytes | None = None
        self.body_since: float = 0.0
        self.address: str = ""
        self.solutions: list[Solution] = []
        self._issued: OrderedDict[bytes, bytes] = OrderedDict()

    # -- curation, spec §4.1 ------------------------------------------------

    def curate(self, now=None) -> list[tuple[str, int]]:
        now = self.clock() if now is None else now
        min_age = self.config.anchor_min_age * 86400
        cands = []
        for e in self.store.get_transpeers():
            if is_reserved(e.addr):
                continue
            # 1. History; and the entry must be reachable now (spec §4.1:
            # a body may change early only because an entry died).
            if e.first_seen <= 0 or now - e.first_seen < min_age or e.answered < 1 or not e.alive:
                continue
            # 2. Quality: only judged once there are enough verifications.
            t = self.store.get_source_trust(e.addr)
            total = t.verified_alive + t.verified_dead
            if total >= QUALITY_MIN_SAMPLES and t.verified_alive / total < QUALITY_MIN_RATE:
                continue
            # 3. Native: only judged when the probe has run.
            if e.native and not any(e.native.values()):
                continue
            cands.append(e)
        # 4. Diversity: one per /16, highest answered wins.
        by16: dict[str, object] = {}
        for e in sorted(cands, key=lambda e: -e.answered):
            key = str(ipaddress.ip_network(f"{e.addr}/16", strict=False))
            by16.setdefault(key, e)
        chosen = sorted(by16.values(), key=lambda e: -e.answered)
        # 5. Continuity: bounded share of entries with no committed history.
        if self.db.blob_count() > 0:
            cont = [e for e in chosen if self.db.has_body_entry(e.addr, e.port)]
            new = [e for e in chosen if not self.db.has_body_entry(e.addr, e.port)]
            allow = int(self.config.anchor_max_new * len(chosen))
            chosen = sorted(cont + new[:allow], key=lambda e: -e.answered)
        # 6. Faithfulness (spec §9): challenges arrive with the reader slice.
        chosen = chosen[:MAX_ENTRIES]
        return sorted(((e.addr, e.port) for e in chosen),
                      key=lambda a: (int(ipaddress.IPv4Address(a[0])), a[1]))

    # -- body and rotation ---------------------------------------------------

    def _entries_alive(self) -> bool:
        if self.body is None:
            return True
        from .blob import decode_blob
        for addr, port in decode_blob(self.body).entries:
            e = self.store.get_transpeer(addr, port)
            if e is None or not e.alive:
                return False
        return True

    def refresh(self, now=None) -> bool:
        now = self.clock() if now is None else now
        due = (self.body is None or now - self.body_since >= BODY_MAX_AGE
               or not self._entries_alive())
        if not due:
            return False
        entries = self.curate(now)
        if not entries:
            return False
        body = list_body(encode_blob(self.config.anchor_chain, 0, entries))
        if body == self.body:
            return False
        self.body = body
        self.body_since = now
        return True

    def current(self, now=None):
        now = self.clock() if now is None else now
        if self.body is None:
            return None
        blob = with_period(self.body, period_of(now))
        h = blob_hash(blob)
        if h not in self._issued:
            self._issued[h] = blob
            while len(self._issued) > self.ISSUED_KEEP:
                self._issued.popitem(last=False)
        return h, blob

    def lookup(self, aux_hash: bytes):
        return self._issued.get(aux_hash)

    def record_solution(self, sol: Solution) -> None:
        self.solutions.append(sol)
```

If `SourceTrust` has different attribute names than `verified_alive` / `verified_dead`, use the real ones; do not add a compatibility shim.

- [ ] **Step 4: Run tests**

Expected: `tests/test_anchor_publish.py` all PASS; existing suites unchanged.

- [ ] **Step 5: Commit**

```bash
git add transpeer/anchor/publisher.py tests/test_anchor_publish.py
git commit -m "anchor: curation from the peer store and period-rotating publisher

Rules 1-5 of spec 4.1 in order; quality and native rules are judged
only where the store has data for them, so a node started with
--no-verify or without native probing still publishes. Bodies change
at most daily or when an entry dies; the hash rotates every 1500 s so
P2Pool's 1800 s expiry never fires. Every issued blob stays servable.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01WkpMVTAKW7iLDzgTavyHVW"
```

---

### Task 9: The aux-chain JSON-RPC server

**Files:**
- Create: `transpeer/anchor/auxrpc.py`
- Modify: `tests/test_anchor_publish.py`

**Interfaces:**
- Consumes: `Publisher.{current, lookup, record_solution, refresh, address}`, `parse_block_blob`, `parse_tx_extra_mm_tag`, `verify_merkle_proof`, `CHAIN_ID`, `BlobDB.add`, `Commitment`.
- Produces: `class AuxRpcServer` with `__init__(self, publisher: Publisher, db: BlobDB, aux_diff: int, clock=time.time)`, `create_app() -> web.Application` (POST on `/` and `/json_rpc`), `handle(request_dict) -> response_dict` (pure dispatch, testable without HTTP), and counters `self.stats = {"get_aux_block": 0, "changed": 0, "submit": 0, "submit_rejected": 0}`.

Behaviour (spec §4.2, P2Pool client verified in `merge_mining_client_json_rpc.cpp`):
- `merge_mining_get_chain_id` → `{"chain_id": CHAIN_ID.hex(), "ticker": "TPL"}`.
- `merge_mining_get_aux_block` with params `address`, `aux_hash`, `height`, `prev_id`: remember `address` in `publisher.address`; call `publisher.refresh()`; `cur = publisher.current()`; if `cur is None` → result `{}`; if `cur[0].hex() == params["aux_hash"]` → result `{}` (unchanged); else `{"aux_blob": blob.hex(), "aux_diff": aux_diff, "aux_hash": hash.hex()}`.
- `merge_mining_submit_solution` with `aux_blob`, `aux_hash`, `blob`, `merkle_proof` (hex list), `path` (int), `seed_hash`: hex-decode; require `publisher.lookup(aux_hash) == aux_blob` bytes; parse the block blob, find the tag in its `tx_extra`, require `verify_merkle_proof(aux_hash, proof, path, tag.root)`; on success record a `Solution` and add the blob to the database with `Commitment(aux_hash, "template", "local", f"template:{height}:{prev_id.hex()}", publisher.address, aux_diff, block.timestamp, proof, path)`; respond `{"status": "accepted"}`. On any failure respond with a JSON-RPC error object `{"code": -1, "message": "<reason>"}` and count `submit_rejected`.
- Unknown method → error code -32601. Malformed JSON → error -32700. Every response carries the request's `id` (default `"0"`) and `"jsonrpc": "2.0"`.

- [ ] **Step 1: Write the failing test**

```python
async def test_aux_rpc():
    from aiohttp import web
    import aiohttp
    from transpeer.anchor import CHAIN_ID
    from transpeer.anchor.blob import blob_hash, decode_blob
    from transpeer.anchor.blobdb import BlobDB
    from transpeer.anchor.auxrpc import AuxRpcServer
    from transpeer.anchor.merkle import (merkle_tree, merkle_root, merkle_proof, aux_slot,
                                         find_aux_nonce, build_mm_tag)
    from transpeer.anchor.monero import build_block_blob
    from transpeer.anchor.publisher import Publisher
    print("aux-chain JSON-RPC")
    now = 2_000_000_000
    old = now - 20 * 86400
    cfg = Config(in_memory=True, no_verify=True, anchor_publish=True, aux_diff=12345)
    store = PeerStore(cfg)
    await store.init()
    for i in range(1, 4):
        _add(store, f"4{i}.0.0.1", first_seen=old, answered=i)
    db = BlobDB()
    pub = Publisher(cfg, store, db, clock=lambda: now)
    rpc = AuxRpcServer(pub, db, aux_diff=12345, clock=lambda: now)

    runner = web.AppRunner(rpc.create_app())
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 17338)
    await site.start()

    async def call(method, params=None, rid="7"):
        req = {"jsonrpc": "2.0", "id": rid, "method": method}
        if params is not None:
            req["params"] = params
        async with aiohttp.ClientSession() as s:
            async with s.post("http://127.0.0.1:17338/", json=req) as r:
                return await r.json()

    r = await call("merge_mining_get_chain_id")
    check(r["id"] == "7" and r["jsonrpc"] == "2.0", "envelope echoes id")
    check(r["result"]["chain_id"] == CHAIN_ID.hex() and r["result"]["ticker"] == "TPL", "chain id")
    params = {"address": "WALLET", "aux_hash": "00" * 32, "height": 3_000_000, "prev_id": "11" * 32}
    r = await call("merge_mining_get_aux_block", params)
    res = r["result"]
    check(set(res) == {"aux_blob", "aux_diff", "aux_hash"} and res["aux_diff"] == 12345, "first poll returns a job")
    blob = bytes.fromhex(res["aux_blob"])
    check(blob_hash(blob).hex() == res["aux_hash"], "aux_hash is sha256 of aux_blob")
    check(len(decode_blob(blob).entries) == 3 and pub.address == "WALLET", "blob from curation; address remembered")
    params["aux_hash"] = res["aux_hash"]
    r = await call("merge_mining_get_aux_block", params)
    check(r["result"] == {}, "unchanged hash -> empty result (P2Pool treats as no change)")
    check(rpc.stats["get_aux_block"] == 2 and rpc.stats["changed"] == 1, "stats")
    # Build a template whose coinbase tag commits to the aux hash and submit a solution.
    aux_hash = bytes.fromhex(res["aux_hash"])
    sidechain_id = hashlib.sha256(b"venue").digest()
    ids = [sidechain_id, CHAIN_ID]
    nonce = find_aux_nonce(ids)
    leaves = [None, None]
    leaves[aux_slot(sidechain_id, nonce, 2)] = hashlib.sha256(b"share").digest()
    leaves[aux_slot(CHAIN_ID, nonce, 2)] = aux_hash
    tree = merkle_tree(leaves)
    proof, path = merkle_proof(tree, aux_hash)
    tag = build_mm_tag(2, nonce, merkle_root(leaves))
    extra = b"\x01" + bytes(32) + b"\x02\x04" + bytes(4) + tag
    tmpl = build_block_blob(16, 16, now, b"\x11" * 32, 0, 3_000_000, extra)
    sub = {"aux_blob": blob.hex(), "aux_hash": aux_hash.hex(), "blob": tmpl.hex(),
           "merkle_proof": [p.hex() for p in proof], "path": path, "seed_hash": "22" * 32}
    r = await call("merge_mining_submit_solution", sub)
    check(r.get("result") == {"status": "accepted"}, "valid solution accepted")
    check(len(pub.solutions) == 1 and pub.solutions[0].height == 3_000_000, "solution recorded")
    recs = db.commitments(aux_hash)
    check(len(recs) == 1 and recs[0].kind == "template" and recs[0].publisher == "WALLET"
          and recs[0].proof == tuple(proof) and recs[0].path == path, "template commitment stored with proof")
    check(db.get(aux_hash) == blob, "blob now in the database")
    bad = dict(sub, path=path ^ 1)
    r = await call("merge_mining_submit_solution", bad)
    check("error" in r and rpc.stats["submit_rejected"] == 1, "wrong path rejected")
    bad = dict(sub, aux_hash="ab" * 32)
    r = await call("merge_mining_submit_solution", bad)
    check("error" in r, "unknown aux_hash rejected")
    # Rotation through the RPC: next period yields a new hash for the same body.
    now += 1500
    r = await call("merge_mining_get_aux_block", params)
    check(r["result"]["aux_hash"] != res["aux_hash"]
          and bytes.fromhex(r["result"]["aux_blob"])[22:] == blob[22:], "period rotation through RPC")
    r = await call("no_such_method")
    check(r["error"]["code"] == -32601, "unknown method")
    async with aiohttp.ClientSession() as s:
        async with s.post("http://127.0.0.1:17338/", data=b"{not json") as resp:
            r = await resp.json()
    check(r["error"]["code"] == -32700, "parse error")
    await runner.cleanup()
    await store.close()
```

- [ ] **Step 2: Run to verify failure**

Expected: `ModuleNotFoundError: No module named 'transpeer.anchor.auxrpc'`

- [ ] **Step 3: Implement** `transpeer/anchor/auxrpc.py`

```python
"""The aux-chain JSON-RPC server P2Pool polls (spec §4.2). Three
methods, verified against p2pool v4.18 merge_mining_client_json_rpc.cpp:
P2Pool polls every 500 ms, treats an empty result or an unchanged
aux_hash as "no change", drops the chain after 1800 s without a hash
change, and may submit a solution for any of its last 8 aux hashes."""

import json
import logging
import time

from aiohttp import web

from . import CHAIN_ID
from .blobdb import BlobDB, Commitment
from .merkle import parse_tx_extra_mm_tag, verify_merkle_proof
from .monero import parse_block_blob
from .publisher import Publisher, Solution

log = logging.getLogger("transpeer.anchor.auxrpc")


class AuxRpcServer:
    def __init__(self, publisher: Publisher, db: BlobDB, aux_diff: int, clock=time.time):
        self.publisher = publisher
        self.db = db
        self.aux_diff = aux_diff
        self.clock = clock
        self.stats = {"get_aux_block": 0, "changed": 0, "submit": 0, "submit_rejected": 0}

    # -- dispatch -----------------------------------------------------------

    def handle(self, req: dict) -> dict:
        rid = req.get("id", "0")
        method = req.get("method")
        params = req.get("params") or {}
        try:
            if method == "merge_mining_get_chain_id":
                result = {"chain_id": CHAIN_ID.hex(), "ticker": "TPL"}
            elif method == "merge_mining_get_aux_block":
                result = self._get_aux_block(params)
            elif method == "merge_mining_submit_solution":
                result = self._submit_solution(params)
            else:
                return {"jsonrpc": "2.0", "id": rid,
                        "error": {"code": -32601, "message": "method not found"}}
        except _Reject as e:
            return {"jsonrpc": "2.0", "id": rid, "error": {"code": -1, "message": str(e)}}
        return {"jsonrpc": "2.0", "id": rid, "result": result}

    def _get_aux_block(self, params: dict) -> dict:
        self.stats["get_aux_block"] += 1
        addr = params.get("address")
        if isinstance(addr, str) and addr:
            self.publisher.address = addr
        self.publisher.refresh()
        cur = self.publisher.current()
        if cur is None:
            return {}
        h, blob = cur
        if params.get("aux_hash") == h.hex():
            return {}
        self.stats["changed"] += 1
        return {"aux_blob": blob.hex(), "aux_diff": self.aux_diff, "aux_hash": h.hex()}

    def _submit_solution(self, params: dict) -> dict:
        self.stats["submit"] += 1
        try:
            aux_hash = bytes.fromhex(params["aux_hash"])
            aux_blob = bytes.fromhex(params["aux_blob"])
            blob = bytes.fromhex(params["blob"])
            proof = tuple(bytes.fromhex(p) for p in params["merkle_proof"])
            path = int(params["path"])
            seed_hash = bytes.fromhex(params.get("seed_hash", ""))
        except (KeyError, ValueError, TypeError) as e:
            return self._reject(f"malformed params: {e}")
        if self.publisher.lookup(aux_hash) != aux_blob:
            return self._reject("unknown aux_hash or blob mismatch")
        try:
            head = parse_block_blob(blob)
        except ValueError as e:
            return self._reject(f"bad block blob: {e}")
        tag = parse_tx_extra_mm_tag(head.tx_extra)
        if tag is None:
            return self._reject("no merge-mining tag in coinbase")
        if not verify_merkle_proof(aux_hash, list(proof), path, tag.root):
            return self._reject("merkle proof does not reach the tag root")
        now = int(self.clock())
        sol = Solution(aux_hash, head.height, head.prev_id, head.timestamp, tag.root,
                       proof, path, seed_hash, self.publisher.address, now)
        self.publisher.record_solution(sol)
        self.db.add(aux_blob, Commitment(
            aux_hash, "template", "local",
            f"template:{head.height}:{head.prev_id.hex()}",
            self.publisher.address, self.aux_diff, head.timestamp, proof, path,
        ), now)
        log.info("aux solution accepted at height %d for %s", head.height, aux_hash.hex()[:16])
        return {"status": "accepted"}

    def _reject(self, reason: str):
        self.stats["submit_rejected"] += 1
        log.warning("aux solution rejected: %s", reason)
        raise _Reject(reason)

    # -- HTTP ---------------------------------------------------------------

    async def handle_http(self, request: web.Request) -> web.Response:
        try:
            req = json.loads(await request.read())
            if not isinstance(req, dict):
                raise ValueError("not an object")
        except ValueError:
            return web.json_response({"jsonrpc": "2.0", "id": "0",
                                      "error": {"code": -32700, "message": "parse error"}})
        return web.json_response(self.handle(req))

    def create_app(self) -> web.Application:
        app = web.Application()
        app.router.add_post("/", self.handle_http)
        app.router.add_post("/json_rpc", self.handle_http)
        return app


class _Reject(Exception):
    pass
```

- [ ] **Step 4: Run tests**

Expected: `tests/test_anchor_publish.py` all PASS. If "valid solution accepted" fails, print the rejection reason from the response before touching any code; the usual cause is a leaf order mismatch between the test's `leaves` and the slot rule.

- [ ] **Step 5: Commit**

```bash
git add transpeer/anchor/auxrpc.py tests/test_anchor_publish.py
git commit -m "anchor: aux-chain JSON-RPC server for P2Pool --merge-mine

Three methods as P2Pool's client sends them. submit_solution is
verified against the tag in the template's coinbase before it is
recorded as a 'template' commitment; the publisher keeps every issued
blob so a solution for any of P2Pool's last 8 hashes is accepted.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01WkpMVTAKW7iLDzgTavyHVW"
```

---

### Task 10: Blob endpoints on the transpeer port

**Files:**
- Modify: `transpeer/server.py` (`__init__`, `create_app`, two handlers)
- Modify: `tests/test_anchor_publish.py`

**Interfaces:**
- Consumes: `Publisher.lookup`, `BlobDB.get`, `BlobDB.index_since`, `Commitment.to_dict`.
- Produces: `TranspeerServer.__init__(..., network_names=None, blobdb: BlobDB | None = None, publisher: Publisher | None = None)`; `GET /blob/{hash}` → `application/octet-stream` bytes or 404; `GET /blobs/index?since=<unix>&limit=<n>` → `{"blobs": [{"hash": hex, "first_seen": int, "commitments": [...]}], "next_since": int | null}`; both 404 with `{"error": "anchor not configured"}` when neither a publisher nor a database is attached. No handshake proof-of-work on these routes (spec §5), but the existing per-remote rate limit applies.

- [ ] **Step 1: Write the failing test**

```python
async def test_blob_endpoints():
    import aiohttp
    from aiohttp import web
    from transpeer.server import TranspeerServer
    from transpeer.anchor.blob import blob_hash, encode_blob
    from transpeer.anchor.blobdb import BlobDB, Commitment
    from transpeer.anchor.publisher import Publisher
    print("blob endpoints")
    now = 2_000_000_000
    cfg = Config(in_memory=True, no_verify=True, anchor_publish=True, port=17337, bind="127.0.0.1")
    store = PeerStore(cfg)
    await store.init()
    db = BlobDB()
    pub = Publisher(cfg, store, db, clock=lambda: now)
    _add(store, "50.0.0.1", first_seen=now - 20 * 86400, answered=4)
    pub.refresh()
    h_issued, b_issued = pub.current()
    b_db = encode_blob("monero", 5, [("51.0.0.1", 7337)])
    db.add(b_db, Commitment(blob_hash(b_db), "share", "v", "s1", "w", 10, now - 50), now - 40)
    srv = TranspeerServer(cfg, store, "test_anchor", time.time(), network_names=["monero"],
                          blobdb=db, publisher=pub)
    runner = web.AppRunner(srv.create_app())
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 17337)
    await site.start()
    base = "http://127.0.0.1:17337"
    async with aiohttp.ClientSession() as s:
        async with s.get(f"{base}/blob/{h_issued.hex()}") as r:
            body = await r.read()
            check(r.status == 200 and body == b_issued and r.content_type == "application/octet-stream",
                  "issued blob served as bytes")
        async with s.get(f"{base}/blob/{blob_hash(b_db).hex()}") as r:
            check(r.status == 200 and await r.read() == b_db, "database blob served")
        async with s.get(f"{base}/blob/{'ab' * 32}") as r:
            check(r.status == 404, "unknown hash 404")
        async with s.get(f"{base}/blob/zz") as r:
            check(r.status == 400, "malformed hash 400")
        async with s.get(f"{base}/blobs/index?since=0") as r:
            j = await r.json()
            check(r.status == 200 and [b["hash"] for b in j["blobs"]] == [blob_hash(b_db).hex()]
                  and j["blobs"][0]["commitments"][0]["ref"] == "s1", "index lists committed blobs only")
        async with s.get(f"{base}/blobs/index?since={now}") as r:
            j = await r.json()
            check(j["blobs"] == [] and j["next_since"] is None, "index since now is empty")
    await runner.cleanup()
    # Unconfigured server answers 404 on both routes.
    srv2 = TranspeerServer(cfg, store, "test_plain", time.time(), network_names=["monero"])
    runner = web.AppRunner(srv2.create_app())
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 17339)
    await site.start()
    async with aiohttp.ClientSession() as s:
        async with s.get("http://127.0.0.1:17339/blob/" + "00" * 32) as r:
            check(r.status == 404, "no anchor: /blob 404")
        async with s.get("http://127.0.0.1:17339/blobs/index") as r:
            check(r.status == 404, "no anchor: /blobs/index 404")
    await runner.cleanup()
    await store.close()
```

- [ ] **Step 2: Run to verify failure**

Expected: `TypeError: __init__() got an unexpected keyword argument 'blobdb'`.

- [ ] **Step 3: Implement**

In `transpeer/server.py`, change `__init__` (line 79) to accept and store the two optional objects:

```python
    def __init__(self, config: Config, store: PeerStore, node_id: str, start_time: float,
                 network_names: list[str] | None = None,
                 blobdb=None, publisher=None):
        ...existing body unchanged...
        self.blobdb = blobdb
        self.publisher = publisher
```

Add two handlers next to `handle_transpeers`:

```python
    # -- chain-anchored publication, spec §5 -------------------------------
    # Content-addressed data: no handshake proof-of-work, rate limit only.

    def _anchor_ready(self) -> bool:
        return self.blobdb is not None or self.publisher is not None

    async def handle_blob(self, request: web.Request) -> web.Response:
        if not self._anchor_ready():
            return web.json_response({"error": "anchor not configured"}, status=404)
        if not self._check_rate_limit(request.remote):
            return web.json_response({"error": "rate limited"}, status=429)
        try:
            h = bytes.fromhex(request.match_info["hash"])
            if len(h) != 32:
                raise ValueError
        except ValueError:
            return web.json_response({"error": "bad hash"}, status=400)
        blob = self.publisher.lookup(h) if self.publisher else None
        if blob is None and self.blobdb is not None:
            blob = self.blobdb.get(h)
        if blob is None:
            return web.json_response({"error": "unknown blob"}, status=404)
        return web.Response(body=blob, content_type="application/octet-stream")

    async def handle_blobs_index(self, request: web.Request) -> web.Response:
        if not self._anchor_ready():
            return web.json_response({"error": "anchor not configured"}, status=404)
        if not self._check_rate_limit(request.remote):
            return web.json_response({"error": "rate limited"}, status=429)
        try:
            since = int(request.query.get("since", "0"))
            limit = max(1, min(int(request.query.get("limit", "500")), 500))
        except ValueError:
            return web.json_response({"error": "bad query"}, status=400)
        rows = self.blobdb.index_since(since, limit) if self.blobdb is not None else []
        blobs = [{"hash": h.hex(), "first_seen": fs, "commitments": [c.to_dict() for c in cs]}
                 for h, fs, cs in rows]
        next_since = rows[-1][1] if len(rows) == limit else None
        return web.json_response({"blobs": blobs, "next_since": next_since})
```

Register in `create_app`:

```python
        app.router.add_get("/blob/{hash}", self.handle_blob)
        app.router.add_get("/blobs/index", self.handle_blobs_index)
```

- [ ] **Step 4: Run tests**

Expected: `tests/test_anchor_publish.py` all PASS; `tests/test_two_nodes.py` 24/24. A 429 on one of the loopback requests means the existing per-remote rate limiter (`_check_rate_limit`) is stricter than the test's request count; raise the test's port or spread requests over a short sleep rather than loosening the limiter.

- [ ] **Step 5: Commit**

```bash
git add transpeer/server.py tests/test_anchor_publish.py
git commit -m "anchor: /blob/{hash} and /blobs/index on the transpeer port

Content-addressed, so no handshake PoW (spec 5); 404 unless the node
runs with an anchor database or publisher attached.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01WkpMVTAKW7iLDzgTavyHVW"
```

---

### Task 11: Node wiring and persistence

**Files:**
- Modify: `transpeer/node.py` (`__init__`, `run`, new `_anchor_loop`)
- Modify: `tests/test_anchor_publish.py`

**Interfaces:**
- Consumes: `BlobDB.load/save`, `Publisher`, `AuxRpcServer`, `TranspeerServer(blobdb=, publisher=)`.
- Produces: `Node.blobdb`, `Node.publisher`, `Node.auxrpc` (all `None` unless `config.anchor_publish`); `Node._anchor_loop()` runs every 60 s: `publisher.refresh()`, then `blobdb.save(path)` if the database changed since the last save (compare `blob_count()` and total commitment count), path `config.data_dir / "anchor_blobs.json"`, skipped when `config.in_memory`. The aux RPC site is started on `(config.aux_rpc_bind, config.aux_rpc_port)` before the loops, and logged.

- [ ] **Step 1: Write the failing test**

```python
async def test_node_wiring():
    import tempfile
    import aiohttp
    from transpeer.node import Node
    print("node wiring")
    with tempfile.TemporaryDirectory() as d:
        cfg = Config(port=17340, bind="127.0.0.1", data_dir=Path(d), networks=["monero"],
                     no_verify=True, no_pow=True, scan_rate=0.0, anchor_publish=True,
                     aux_rpc_bind="127.0.0.1", aux_rpc_port=17341, aux_diff=77)
        node = Node(cfg)
        check(node.publisher is None and node.auxrpc is None, "anchor objects created in run(), not __init__")
        task = asyncio.create_task(node.run())
        for _ in range(50):
            await asyncio.sleep(0.1)
            if node.auxrpc is not None and node.server is not None:
                break
        await asyncio.sleep(0.3)
        async with aiohttp.ClientSession() as s:
            async with s.post("http://127.0.0.1:17341/", json={"jsonrpc": "2.0", "id": "1",
                                                                "method": "merge_mining_get_chain_id"}) as r:
                j = await r.json()
                check(j["result"]["ticker"] == "TPL", "aux RPC reachable through Node")
            async with s.post("http://127.0.0.1:17341/", json={"jsonrpc": "2.0", "id": "1",
                              "method": "merge_mining_get_aux_block",
                              "params": {"address": "W", "aux_hash": "00" * 32, "height": 1, "prev_id": "00" * 32}}) as r:
                j = await r.json()
                check(j["result"] == {}, "empty store publishes nothing")
            async with s.get("http://127.0.0.1:17340/blobs/index") as r:
                check(r.status == 200 and (await r.json())["blobs"] == [], "index served by the node")
        check((Path(d) / "anchor_blobs.json").exists() or node.blobdb.blob_count() == 0,
              "no save needed for an empty database")
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):  # noqa: BLE001
            pass
    # Without the flag nothing is started.
    node2 = Node(Config(port=17342, in_memory=True, no_verify=True, no_pow=True, scan_rate=0.0))
    check(node2.publisher is None and node2.blobdb is None, "flag off: no anchor objects")
```

Read `transpeer/node.py:48-95` (`run`) before editing; the test relies on `run()` being cancellable and on `Config(scan_rate=0.0)` disabling the scanner, which is how `--no-scan` is expressed. `run()` also starts the daemon-extraction loop, which will find no monerod on the test machine; if that loop raises instead of logging and retrying, that is a pre-existing bug to report, not something to paper over in this task.

- [ ] **Step 2: Run to verify failure**

Expected: `AttributeError: 'Node' object has no attribute 'publisher'`.

- [ ] **Step 3: Implement**

In `Node.__init__` after `self._daemon_peer_probed = {}`:

```python
        # Chain-anchored publication (--anchor-publish); built in run().
        self.blobdb = None
        self.publisher = None
        self.auxrpc = None
        self._anchor_saved = (0, 0)
```

In `Node.run`, after `self.config.native_ports = {...}` and before `self.server = TranspeerServer(...)`:

```python
        if self.config.anchor_publish:
            from .anchor.blobdb import BlobDB
            from .anchor.publisher import Publisher
            from .anchor.auxrpc import AuxRpcServer
            self._anchor_path = self.config.data_dir / "anchor_blobs.json"
            self.blobdb = BlobDB() if self.config.in_memory else BlobDB.load(self._anchor_path)
            self.publisher = Publisher(self.config, self.store, self.blobdb)
            self.auxrpc = AuxRpcServer(self.publisher, self.blobdb, self.config.aux_diff)
            log.info("Anchor publisher on: %d blobs loaded, aux RPC on %s:%d, aux_diff %d",
                     self.blobdb.blob_count(), self.config.aux_rpc_bind,
                     self.config.aux_rpc_port, self.config.aux_diff)
```

Pass them to the server:

```python
        self.server = TranspeerServer(
            self.config, self.store, self.node_id, self.start_time,
            network_names=list(self._networks.keys()),
            blobdb=self.blobdb, publisher=self.publisher,
        )
```

After the HTTP site starts and before `asyncio.gather(...)`:

```python
            if self.auxrpc is not None:
                aux_runner = web.AppRunner(self.auxrpc.create_app())
                await aux_runner.setup()
                await web.TCPSite(aux_runner, self.config.aux_rpc_bind, self.config.aux_rpc_port).start()
                log.info("Aux-chain RPC listening on %s:%d", self.config.aux_rpc_bind, self.config.aux_rpc_port)
```

Add `self._anchor_loop()` to the `gather` list, and the method:

```python
    async def _anchor_loop(self):
        """Re-curate the published list and persist the blob database."""
        if self.publisher is None:
            return
        while True:
            try:
                if self.publisher.refresh():
                    log.info("Anchor list body changed: %d entries",
                             len(self.publisher.curate()))
                if not self.config.in_memory:
                    state = (self.blobdb.blob_count(), self.blobdb.commitment_count())
                    if state != self._anchor_saved and state != (0, 0):
                        self.blobdb.save(self._anchor_path)
                        self._anchor_saved = state
            except Exception:  # noqa: BLE001
                log.exception("anchor loop")
            await asyncio.sleep(60)
```

- [ ] **Step 4: Run tests**

Expected: `tests/test_anchor_publish.py` all PASS; the three existing suites unchanged.

- [ ] **Step 5: Commit**

```bash
git add transpeer/node.py tests/test_anchor_publish.py
git commit -m "anchor: start publisher and aux RPC under --anchor-publish

Objects exist only with the flag; the blob database persists to
data_dir/anchor_blobs.json from a 60 s loop that also re-curates.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01WkpMVTAKW7iLDzgTavyHVW"
```

---

### Task 12: P2Pool-style poller and end-to-end check

**Files:**
- Create: `sim/mm_poller.py` (reusable by the Shadow oracle in slice 4 and for a manual check against a real node)
- Modify: `tests/test_anchor_publish.py`

**Interfaces:**
- Produces: `class MergeMiningPoller` with `__init__(self, url: str, address: str, interval: float = 0.5, expire: float = 1800.0, clock=time.time, sleep=asyncio.sleep)`, `async run_once(session) -> bool` (one poll; returns True when the job changed; mirrors P2Pool: sends `aux_hash` of the current job, keeps the last 8 (hash, blob) pairs, records `last_updated` only on change, sets `self.expired = clock() - last_updated >= expire`), `async submit(session, blob_bytes, merkle_proof, path, seed_hash, aux_hash=None) -> dict`, attributes `chain_id`, `aux_hash`, `aux_blob`, `aux_diff`, `previous: collections.deque(maxlen=8)`, `last_updated`, `polls`, `changes`. A `main()` that polls a URL from the command line and prints each change, for use against a live sidecar.

- [ ] **Step 1: Write the failing test** (append to `tests/test_anchor_publish.py`)

```python
async def test_poller_end_to_end():
    from aiohttp import web
    import aiohttp
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "sim"))
    from mm_poller import MergeMiningPoller
    from transpeer.anchor import CHAIN_ID
    from transpeer.anchor.blobdb import BlobDB
    from transpeer.anchor.auxrpc import AuxRpcServer
    from transpeer.anchor.merkle import merkle_tree, merkle_root, merkle_proof, build_mm_tag
    from transpeer.anchor.monero import build_block_blob
    from transpeer.anchor.publisher import Publisher
    print("P2Pool-style poller end to end")
    clock = {"t": 2_000_000_000.0}
    cfg = Config(in_memory=True, no_verify=True, anchor_publish=True, aux_diff=5)
    store = PeerStore(cfg)
    await store.init()
    _add(store, "60.0.0.1", first_seen=int(clock["t"]) - 20 * 86400, answered=2)
    db = BlobDB()
    pub = Publisher(cfg, store, db, clock=lambda: clock["t"])
    rpc = AuxRpcServer(pub, db, aux_diff=5, clock=lambda: clock["t"])
    runner = web.AppRunner(rpc.create_app())
    await runner.setup()
    await web.TCPSite(runner, "127.0.0.1", 17343).start()
    poller = MergeMiningPoller("http://127.0.0.1:17343/", "WALLET", clock=lambda: clock["t"])
    async with aiohttp.ClientSession() as s:
        check(await poller.run_once(s) is True and poller.chain_id == CHAIN_ID.hex(), "first poll: chain id and job")
        first = poller.aux_hash
        check(await poller.run_once(s) is False and poller.aux_hash == first, "second poll: unchanged")
        # 1799 s later, still the same period? No: periods are 1500 s, so the hash changed.
        clock["t"] += 1600
        check(await poller.run_once(s) is True and poller.aux_hash != first and not poller.expired,
              "hash rotates before P2Pool's 1800 s expiry")
        # A solution for the *previous* hash (P2Pool's ring) is accepted.
        prev_hash, prev_blob = poller.previous[-2]
        leaves = [bytes.fromhex(prev_hash)]
        tag = build_mm_tag(1, 0, merkle_root(leaves))
        tmpl = build_block_blob(16, 16, int(clock["t"]), b"\x11" * 32, 0, 3_000_001,
                                b"\x01" + bytes(32) + tag)
        proof, path = merkle_proof(merkle_tree(leaves), leaves[0])
        r = await poller.submit(s, tmpl, proof, path, b"\x22" * 32, aux_hash=prev_hash)
        check(r.get("result") == {"status": "accepted"}, "solution for a previous hash accepted (single-leaf tree)")
        check(poller.polls == 3 and poller.changes == 2, "poller counters")
    await runner.cleanup()
    await store.close()
```

- [ ] **Step 2: Run to verify failure**

Expected: `ModuleNotFoundError: No module named 'mm_poller'`.

- [ ] **Step 3: Implement** `sim/mm_poller.py`

```python
#!/usr/bin/env python3
"""A P2Pool-style merge-mining client: polls a sidecar's aux-chain
JSON-RPC the way p2pool v4.18 does (every 500 ms, sends the current
aux_hash, treats an empty result or the same hash as no change, keeps
the last 8 jobs, expires a chain whose hash is unchanged for 1800 s).

Used by tests, by the Shadow venue oracle, and by hand:
    .venv/bin/python sim/mm_poller.py http://127.0.0.1:7338/ WALLET
"""

import asyncio
import collections
import sys
import time

import aiohttp

NUM_PREVIOUS_HASHES = 8
EXPIRE_TIME = 1800.0
POLL_INTERVAL = 0.5


class MergeMiningPoller:
    def __init__(self, url: str, address: str, interval: float = POLL_INTERVAL,
                 expire: float = EXPIRE_TIME, clock=time.time, sleep=asyncio.sleep):
        self.url = url
        self.address = address
        self.interval = interval
        self.expire = expire
        self.clock = clock
        self.sleep = sleep
        self.chain_id: str | None = None
        self.aux_hash = "00" * 32
        self.aux_blob = ""
        self.aux_diff = 0
        self.previous = collections.deque(maxlen=NUM_PREVIOUS_HASHES)
        self.last_updated = 0.0
        self.expired = False
        self.polls = 0
        self.changes = 0
        self.height = 0
        self.prev_id = "00" * 32

    async def _call(self, session, method, params=None):
        req = {"jsonrpc": "2.0", "id": "0", "method": method}
        if params is not None:
            req["params"] = params
        async with session.post(self.url, json=req) as r:
            return await r.json()

    async def run_once(self, session) -> bool:
        if self.chain_id is None:
            r = await self._call(session, "merge_mining_get_chain_id")
            self.chain_id = r["result"]["chain_id"]
        self.polls += 1
        r = await self._call(session, "merge_mining_get_aux_block", {
            "address": self.address, "aux_hash": self.aux_hash,
            "height": self.height, "prev_id": self.prev_id,
        })
        res = r.get("result") or {}
        changed = bool(res) and res.get("aux_hash") != self.aux_hash
        if changed:
            self.aux_hash = res["aux_hash"]
            self.aux_blob = res["aux_blob"]
            self.aux_diff = int(res["aux_diff"])
            self.previous.append((self.aux_hash, self.aux_blob))
            self.last_updated = self.clock()
            self.changes += 1
        self.expired = self.last_updated > 0 and self.clock() - self.last_updated >= self.expire
        return changed

    async def submit(self, session, blob: bytes, merkle_proof, path: int, seed_hash: bytes,
                     aux_hash: str | None = None) -> dict:
        aux_hash = aux_hash or self.aux_hash
        aux_blob = next((b for h, b in self.previous if h == aux_hash), self.aux_blob)
        return await self._call(session, "merge_mining_submit_solution", {
            "aux_blob": aux_blob, "aux_hash": aux_hash, "blob": blob.hex(),
            "merkle_proof": [p.hex() for p in merkle_proof], "path": path,
            "seed_hash": seed_hash.hex(),
        })

    async def run(self, session):
        while True:
            if await self.run_once(session):
                print(f"{time.strftime('%H:%M:%S')} job {self.aux_hash[:16]} diff {self.aux_diff} "
                      f"blob {len(self.aux_blob) // 2} B", flush=True)
            if self.expired:
                print("chain expired: no hash change for 1800 s", flush=True)
            await self.sleep(self.interval)


async def _main(argv):
    url, address = argv[1], argv[2]
    async with aiohttp.ClientSession() as s:
        await MergeMiningPoller(url, address).run(s)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(2)
    asyncio.run(_main(sys.argv))
```

- [ ] **Step 4: Run tests**

Expected: `tests/test_anchor_publish.py` all PASS; the other suites unchanged.

- [ ] **Step 5: Commit**

```bash
git add sim/mm_poller.py tests/test_anchor_publish.py
git commit -m "anchor: P2Pool-style merge-mining poller and end-to-end check

Mirrors p2pool v4.18's client (500 ms poll, unchanged-hash short
circuit, 8-job ring, 1800 s expiry). Shows the period rotation lands
before expiry and that a solution for a previous job is accepted.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01WkpMVTAKW7iLDzgTavyHVW"
```

---

### Task 13: Documentation

**Files:**
- Modify: `README.md` (flags section: add the anchor flags and a short "Publishing through P2Pool" paragraph), `CLAUDE.md` (Protocol code bullet: add `--anchor-publish` to the flags-default-off list), `docs/spec-chain-anchored-publication.md` (§3.2 add the `template` kind; §17 fix the fixtures sentence), `docs/manuscript.md` (§13 commit table row).

- [ ] **Step 1: README**

Locate the flags list (search for `--native-vouchers`) and append, in the same style:

```
- `--anchor-publish`: publish this node's curated transpeer list through a
  local P2Pool node's merge-mining interface (spec:
  docs/spec-chain-anchored-publication.md). Start p2pool with
  `--merge-mine 127.0.0.1:7338 <WALLET>`. Related: `--aux-rpc-bind`,
  `--aux-rpc-port` (7338), `--aux-diff` (set to the venue's minimum share
  difficulty), `--anchor-chain` (monero), `--anchor-min-age` (14 days),
  `--anchor-max-new` (0.25). Default off; nothing changes without it.
```

And a paragraph under the protocol overview:

```
### Publishing through P2Pool

With `--anchor-publish` the node runs a small JSON-RPC server that
P2Pool treats as a merge-mined chain. The node's curated transpeer
list (a blob of at most 64 addresses) is hashed, and the hash rides as
an aux leaf in every share the P2Pool node builds and in every Monero
block it finds. The blob is served at `/blob/{hash}` and indexed at
`/blobs/index`. Readers of these commitments (the newcomer path) are
not yet implemented; see the specification's §17 for the build order.
```

- [ ] **Step 2: CLAUDE.md**

In the "Protocol code" bullet, change the flag list to include `--anchor-publish`:

```
- Defense policies are behind flags that default off (`--bucketed`,
  `--vouchers`, `--tried-table`, `--handoff-reserve`, `--native-vouchers`,
  `--subnet-prefix`, `--anchor-publish`). ...
```

- [ ] **Step 3: Spec**

In §3.2, after the `proof` row of the table, add a paragraph:

```
A fourth kind, `template`, is recorded only by a publisher, from
P2Pool's `merge_mining_submit_solution`: the proof is against the tag
in the Monero block template P2Pool was mining, before the share or
block that carries it has been observed. Template records carry no
weight (§7) and are upgraded to `share` or `block` when the reader
resolves the corresponding share or block.
```

In §17, replace the "Byte-level fixtures" paragraph with:

```
**Byte-level fixtures.** Slice 1 pins the aux-slot and tree-parameter
vectors from P2Pool's `tests/src/merkle_tests.cpp` at v4.18 and the
Merkle algorithm transcribed from `src/merkle.cpp`; P2Pool's own
Python merge-mining stub, `tests/src/mm_server.py`, fixed the JSON
shapes. A live tagged Monero block is the remaining cross-check and
belongs to slice 3, where the coinbase fetch exists.
```

- [ ] **Step 4: Manuscript commit table**

Append a row to the commit table in §13 after the last one, in its format, for the commit that will close slice 2 (fill the hash after Task 14's final commit): "chain-anchored publication, slices 1–2: blob, Merkle, blob DB, weighting, publisher, aux RPC, blob endpoints (no measurements)".

- [ ] **Step 5: Run all suites once more**

```
PYTHONPATH=$PWD .venv/bin/python tests/test_anchor.py
PYTHONPATH=$PWD .venv/bin/python tests/test_anchor_publish.py
PYTHONPATH=$PWD .venv/bin/python tests/test_two_nodes.py
PYTHONPATH=$PWD .venv/bin/python tests/test_bucketed.py
PYTHONPATH=$PWD .venv/bin/python tests/test_scanner.py
```
Expected: `0 failed` on all five; the last three at 24, 47, 19 passed.

- [ ] **Step 6: Commit**

```bash
git add README.md CLAUDE.md docs/spec-chain-anchored-publication.md docs/manuscript.md
git commit -m "docs: anchor publisher flags, template commitment kind, fixture note

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01WkpMVTAKW7iLDzgTavyHVW"
```

Then fill the manuscript commit-table hash with this commit's hash in a follow-up `docs:` commit if the table requires the hash of the closing commit.

---

### Task 14: Manual check against the real client (optional, outside tests)

Not a code task. If a P2Pool binary is at hand on a machine with a monerod (testnet or stagenet), run:

```
.venv/bin/python -m transpeer --anchor-publish --anchor-min-age 0 --in-memory --no-verify --no-scan
p2pool --host 127.0.0.1 --wallet <ADDR> --merge-mine 127.0.0.1:7338 <ADDR> --loglevel 4
```

and watch P2Pool's log for the chain id, the aux job, and whether it logs "merge mining data is outdated" (it must not, since the hash rotates every 1500 s). Record the outcome in `.claude/HANDOFF.md`. This is the spec §17 testnet check; it is the only step that cannot run on the Zenith box today.

---

## Self-review

**Spec coverage.** §3.1 → Task 2; §3.2, §3.3 → Task 5 (+ `template` kind, Task 13); §4.1 → Task 8 (rule 6 deferred to slice 3, stated); §4.2 → Tasks 9, 12; §4.3 → Task 8 `_issued` ring plus Task 10 `/blob`; §5 `/blob`, `/blobs/index` → Task 10 (anchor headers, coinbase and venue share endpoints are reader-side, slice 3); §6.3 tag → Tasks 3, 4; §6.4 → Task 3; §7, §8 → Task 6; §14 flags-off → Tasks 7, 11; §17 → this plan. Not in this plan by design: §6.2, §6.5–6.7, §9, §10, §12 mitigations, the observer client.

**Placeholders.** None; every step carries code or exact commands. Two steps ask the executor to read a function before editing (`add_transpeer`, `run`) because the plan quotes its shape, not its full body; the edits are specified.

**Type consistency.** `Commitment(hash, kind, venue, ref, publisher, difficulty, timestamp, proof=(), path=0)` is used identically in Tasks 5, 6, 8, 9, 10. `Publisher.current()` returns `(aux_hash, blob)` or `None` in Tasks 8, 9, 10, 11. `BlobDB.index_since(since, limit)` returns `(hash, first_seen, commitments)` triples in Tasks 5, 10, 11. `Solution` fields match between Tasks 8 and 9. `MergeMiningPoller.previous` holds `(hash_hex, blob_hex)` pairs in Task 12.
