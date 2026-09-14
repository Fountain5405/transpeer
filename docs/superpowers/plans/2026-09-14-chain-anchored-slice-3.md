# Chain-Anchored Publication, Slice 3 (the reader) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A transpeer node can, under `--anchor-read`, verify the anchor chain from a checkpoint, resolve merge-mining tags to P2Pool shares and transpeer list blobs, weight transpeers by the work that published them, seed its store with the result, gossip verified blobs, challenge other transpeers for the blobs they should serve, and rank published reporters first.

**Architecture:** Everything new lives in `transpeer/anchor/` as pure verification modules (Monero hashing and difficulty, header chain, share parser, proof-of-work backends) plus stores, an HTTP client for the §5 endpoints, a `Reader` that runs the §6–§8 newcomer path, a `Challenger` (§9), a P2Pool observer client (§6.5) and a monerod source. `server.py` gains the anchor and venue endpoints; `peerstore.py` gains `published`/`unfaithful` tags and the ranking change; `node.py` wires loops behind flags that default off. The proof-of-work hash is pluggable: SHA-256 under `--anchor-sim-pow`, RandomX in production.

**Tech Stack:** Python 3.12 (`.venv/bin/python`), aiohttp, aiosqlite, standard library only. Tests are plain scripts with a `check(cond, name)` helper and a PASS/FAIL summary, like `tests/test_anchor.py`.

**Spec:** `docs/spec-chain-anchored-publication.md`, sections 5–9 and 17.1 (slice 3 decisions). Verified source excerpts from P2Pool v4.18 and Monero v0.18.4.1 are in the scratchpad `excerpts/` directory named in each task's brief; implementers transcribe from them, never from memory.

## Global Constraints

- Run everything with `.venv/bin/python` (3.12); the system python is 3.8. From the worktree: `cd ~/transpeer-reader && PYTHONPATH=$PWD .venv/bin/python tests/<file>.py`.
- New flags default **off**: `--anchor-read`, `--anchor-sim-pow`, `--anchor-checkpoint`, `--anchor-venues`, `--anchor-monerod`, `--anchor-observe`, `--anchor-window-days` (default 7). With every anchor flag off, `tests/test_bucketed.py` (47), `tests/test_two_nodes.py` (24), `tests/test_scanner.py` (19), `tests/test_anchor.py` (106) and `tests/test_anchor_publish.py` (118) must keep passing unchanged. Do not touch the `--scan-legacy` behaviour or any scanning default.
- Keccak-256 is `transpeer.anchor.keccak.keccak256` (0x01 padding). Never `hashlib.sha3_256`.
- Varints are `transpeer.anchor.varint.read_varint(buf, pos) -> (value, new_pos)` and `write_varint(value) -> bytes`.
- No new third-party dependencies. RandomX is optional at runtime (Task 3).
- New tests bind loopback ports 17350–17369 only (17337–17343 belong to `tests/test_anchor_publish.py`).
- Commit after every task with a message that explains *why*; end every commit message with the two trailers `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>` and `Claude-Session: https://claude.ai/code/session_01WkpMVTAKW7iLDzgTavyHVW`. Stage by path; never `git add -A`.
- The user's real name must never appear anywhere in the repo. Git identity is already configured; do not change it.
- Every function that consumes bytes from the network validates lengths before slicing and raises `ValueError` (or a subclass) on malformed input; callers catch `ValueError`, never bare `Exception`.

---

### Task 1: Inclusive `/blobs/index` cursor

**Files:**
- Modify: `transpeer/anchor/blobdb.py` (`index_since`)
- Modify: `transpeer/server.py` (`handle_blobs_index`)
- Test: `tests/test_anchor_read.py` (new file; all slice-3 tests go here)

**Interfaces:**
- Consumes: `BlobDB.index_since(since, limit)`; `handle_blobs_index` query params `since`, `limit`.
- Produces: `BlobDB.index_since(since: int, limit: int = 500, after: bytes = b"") -> list[tuple[bytes, int, list[Commitment]]]` returning rows with `(first_seen, hash) > (since, after)` in `(first_seen, hash)` order; the endpoint accepts `after=<hex>` and returns `next_since` and `next_after` (both null when the page is not full).

- [ ] **Step 1: Create the test file with the harness and the failing cursor test**

```python
#!/usr/bin/env python3
"""Checks for the reader side of chain-anchored publication (slice 3).

Run:  PYTHONPATH=$PWD .venv/bin/python tests/test_anchor_read.py
"""

import asyncio
import hashlib
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from transpeer.anchor.blob import encode_blob  # noqa: E402
from transpeer.anchor.blobdb import BlobDB, Commitment  # noqa: E402

passed = failed = 0


def check(cond, name):
    global passed, failed
    if cond:
        passed += 1
        print(f"  PASS: {name}")
    else:
        failed += 1
        print(f"  FAIL: {name}")


def _commit(h, kind="share", ref="r"):
    return Commitment(h, kind, "v", ref, "pub", 1000, 1)


def test_index_cursor():
    print("blobs/index cursor")
    db = BlobDB()
    from transpeer.anchor.blob import blob_hash
    blobs = [encode_blob("monero", 100 + i, [("10.0.0.1", 7337 + i)]) for i in range(3)]
    for b in blobs:
        db.add(b, _commit(blob_hash(b)), now=500)      # same first_seen for all three
    page1 = db.index_since(0, limit=2)
    check(len(page1) == 2, "first page has two rows")
    last_seen, last_hash = page1[-1][1], page1[-1][0]
    page2 = db.index_since(last_seen, limit=2, after=last_hash)
    check(len(page2) == 1, "second page has the third row")
    seen = {r[0] for r in page1} | {r[0] for r in page2}
    check(seen == {blob_hash(b) for b in blobs}, "no row skipped across the page boundary")
    check(db.index_since(500, limit=10) == [], "since is inclusive only with a hash cursor")


if __name__ == "__main__":
    test_index_cursor()
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
```

- [ ] **Step 2: Run it and see the `after` keyword fail**

Run: `PYTHONPATH=$PWD .venv/bin/python tests/test_anchor_read.py`
Expected: `TypeError: index_since() got an unexpected keyword argument 'after'`

- [ ] **Step 3: Implement the cursor**

In `blobdb.py` replace `index_since`:

```python
    def index_since(self, since: int, limit: int = 500, after: bytes = b""
                    ) -> list[tuple[bytes, int, list[Commitment]]]:
        """Rows after the cursor (since, after) in (first_seen, hash) order.
        With an empty `after` this is the old strictly-greater rule; with a
        hash it resumes exactly where the previous page ended, so rows
        that share a timestamp across a page boundary are not skipped."""
        rows = [(h, r.first_seen, list(r.commitments))
                for h, r in self._blobs.items()
                if r.first_seen > since or (after and r.first_seen == since and h > after)]
        rows.sort(key=lambda t: (t[1], t[0]))
        return rows[:limit]
```

In `server.py` `handle_blobs_index`, parse `after`:

```python
        try:
            since = int(request.query.get("since", "0"))
            limit = max(1, min(int(request.query.get("limit", "500")), 500))
            after = bytes.fromhex(request.query.get("after", ""))
            if after and len(after) != 32:
                raise ValueError
        except ValueError:
            return web.json_response({"error": "bad query"}, status=400)
        rows = self.blobdb.index_since(since, limit, after) if self.blobdb is not None else []
        blobs = [{"hash": h.hex(), "first_seen": fs, "commitments": [c.to_dict() for c in cs]}
                 for h, fs, cs in rows]
        full = len(rows) == limit
        return web.json_response({
            "blobs": blobs,
            "next_since": rows[-1][1] if full else None,
            "next_after": rows[-1][0].hex() if full else None,
        })
```

- [ ] **Step 4: Run the new test and the publish suite**

Run: `PYTHONPATH=$PWD .venv/bin/python tests/test_anchor_read.py && PYTHONPATH=$PWD .venv/bin/python tests/test_anchor_publish.py | tail -1`
Expected: 4 passed; `118 passed, 0 failed`.

- [ ] **Step 5: Commit**

```bash
git add transpeer/anchor/blobdb.py transpeer/server.py tests/test_anchor_read.py
git commit -m "Inclusive (first_seen, hash) cursor for /blobs/index

The exclusive next_since skipped rows sharing a timestamp across a page
boundary; gossip (slice 3) reads pages, so fix it first."
```

---

### Task 2: Monero hashing and difficulty

**Files:**
- Modify: `transpeer/anchor/monero.py`
- Test: `tests/test_anchor_read.py`

**Interfaces:**
- Consumes: `parse_block_blob`, `build_block_blob`, `BlockHead` (existing), `keccak256`, varints.
- Produces (all in `transpeer/anchor/monero.py`):
  - `BlockHead` gains `miner_tx: bytes` (the miner transaction bytes including the trailing RCT byte) and `tx_hashes: tuple[bytes, ...]`.
  - `tree_hash(hashes: list[bytes]) -> bytes` — Monero `tree_hash` (`excerpts/monero_hashing.txt`, lines "tree-hash.c").
  - `miner_tx_hash(miner_tx: bytes) -> bytes` — `keccak256(keccak256(miner_tx[:-1]) + keccak256(b"\x00") + bytes(32))`.
  - `hashing_blob(block_blob: bytes) -> bytes` — header bytes (major, minor, timestamp varints, prev_id, nonce) + `tree_hash([miner_tx_hash] + tx_hashes)` + `write_varint(1 + len(tx_hashes))`.
  - `parse_hashing_blob(blob: bytes) -> HashingHead(major, minor, timestamp, prev_id, nonce, tx_root, n_tx)`; raises `ValueError` on trailing bytes.
  - `block_id(hashing_blob: bytes) -> bytes` — `keccak256(write_varint(len(hb)) + hb)` (Monero `get_object_hash`).
  - `check_hash(pow_hash: bytes, difficulty: int) -> bool` — `int.from_bytes(pow_hash, "little") * difficulty < (1 << 256)`.
  - `next_difficulty(timestamps: list[int], cumulative: list[int], target: int = 120) -> int` — transcription of Monero `next_difficulty` with `DIFFICULTY_WINDOW=720, DIFFICULTY_CUT=60` (`excerpts/monero_difficulty.txt`): truncate both lists to the first 720, if length ≤ 1 return 1, sort timestamps, cut, `time_span = max(1, ts[cut_end-1] - ts[cut_begin])`, `total_work = cum[cut_end-1] - cum[cut_begin]`, result `(total_work * target + time_span - 1) // time_span`, and 0 if it exceeds `(1 << 128) - 1`.
  - Constants `DIFFICULTY_WINDOW = 720`, `DIFFICULTY_LAG = 15`, `DIFFICULTY_CUT = 60`, `DIFFICULTY_BLOCKS_COUNT = 735`, `BLOCK_FUTURE_TIME_LIMIT = 7200`, `MONERO_BLOCK_TIME = 120`.

- [ ] **Step 1: Write failing tests**

Append to `tests/test_anchor_read.py` (and call from `__main__`):

```python
def test_monero_hashing():
    print("monero hashing")
    from transpeer.anchor.keccak import keccak256
    from transpeer.anchor.monero import (
        build_block_blob, parse_block_blob, tree_hash, miner_tx_hash, hashing_blob,
        parse_hashing_blob, block_id, check_hash, next_difficulty,
    )
    from transpeer.anchor.varint import write_varint
    h = [hashlib.sha256(bytes([i])).digest() for i in range(6)]
    k = keccak256
    check(tree_hash(h[:1]) == h[0], "tree_hash n=1")
    check(tree_hash(h[:2]) == k(h[0] + h[1]), "tree_hash n=2")
    check(tree_hash(h[:3]) == k(h[0] + k(h[1] + h[2])), "tree_hash n=3")
    check(tree_hash(h[:4]) == k(k(h[0] + h[1]) + k(h[2] + h[3])), "tree_hash n=4")
    check(tree_hash(h[:5]) == k(k(h[0] + h[1]) + k(h[2] + k(h[3] + h[4]))), "tree_hash n=5")
    check(tree_hash(h[:6]) == k(k(h[0] + h[1]) + k(k(h[2] + h[3]) + k(h[4] + h[5]))), "tree_hash n=6")
    blob = build_block_blob(16, 16, 1700000000, bytes(32), 7, 3000000, b"\x01" + bytes(32), tx_hashes=h[:3])
    head = parse_block_blob(blob)
    check(head.tx_hashes == tuple(h[:3]) and head.miner_tx[-1] == 0, "BlockHead exposes miner_tx and tx_hashes")
    mth = miner_tx_hash(head.miner_tx)
    check(mth == k(k(head.miner_tx[:-1]) + k(b"\x00") + bytes(32)), "miner tx three-part hash")
    hb = hashing_blob(blob)
    hh = parse_hashing_blob(hb)
    check(hh.timestamp == 1700000000 and hh.nonce == 7 and hh.n_tx == 4
          and hh.tx_root == tree_hash([mth] + h[:3]), "hashing blob round trip")
    check(block_id(hb) == k(write_varint(len(hb)) + hb), "block id is keccak of length-prefixed hashing blob")
    check(check_hash(bytes(32), 1) and check_hash(b"\xff" * 32, 1) is False, "check_hash edges")
    lim = (1 << 256) // 1000
    check(check_hash((lim - 1).to_bytes(32, "little"), 1000) and not check_hash(lim.to_bytes(32, "little"), 1000),
          "check_hash boundary at difficulty 1000")
    ts = [120 * i for i in range(735)]
    cum = [1000 * (i + 1) for i in range(735)]
    check(next_difficulty(ts, cum) == 1000, "constant 120 s spacing keeps difficulty")
    check(next_difficulty(ts[:1], cum[:1]) == 1, "single block gives 1")
    check(next_difficulty([240 * i for i in range(735)], cum) == 500, "double spacing halves difficulty")
    check(next_difficulty([120 * i for i in range(100)], [1000 * (i + 1) for i in range(100)]) == 1000,
          "short window (no cut) still works")
```

- [ ] **Step 2: Run, expect ImportError on `tree_hash`**

- [ ] **Step 3: Implement**

Add to `BlockHead` the two fields (append after `n_tx_hashes`, defaults `b""` and `()` so existing positional constructions keep working), record `miner_start = pos` before `version, pos = read_varint(...)` in `parse_block_blob`, and after the RCT byte set `miner_tx = bytes(blob[miner_start:pos])`; collect `tx_hashes` in the final loop. Then add:

```python
HASH_SIZE = 32
DIFFICULTY_WINDOW = 720
DIFFICULTY_LAG = 15
DIFFICULTY_CUT = 60
DIFFICULTY_BLOCKS_COUNT = DIFFICULTY_WINDOW + DIFFICULTY_LAG
BLOCK_FUTURE_TIME_LIMIT = 7200
MONERO_BLOCK_TIME = 120
_MAX128 = (1 << 128) - 1


def tree_hash(hashes: list[bytes]) -> bytes:
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


def next_difficulty(timestamps: list[int], cumulative: list[int], target: int = MONERO_BLOCK_TIME) -> int:
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
```

(`keccak256` is imported from `.keccak`.) Note the 1 vs 0 result in the `length <= 1` branch is Monero's, keep it.

- [ ] **Step 4: Run test file and `tests/test_anchor.py` (106) and `tests/test_anchor_publish.py` (118)** — all green.

- [ ] **Step 5: Commit** — `git add transpeer/anchor/monero.py tests/test_anchor_read.py`, message "Monero tree hash, miner tx hash, hashing blob, block id, difficulty rule (slice 3)".

---

### Task 3: Proof-of-work backends

**Files:**
- Create: `transpeer/anchor/powhash.py`
- Test: `tests/test_anchor_read.py`

**Interfaces:**
- Produces:
  - `class PowBackend(Protocol): name: str; def hash(self, blob: bytes, height: int, seed_hash: bytes) -> bytes`
  - `class Sha256Pow: name = "sha256"` — `hashlib.sha256(blob).digest()`; ignores height and seed.
  - `class RandomXPow` — constructed by `randomx_backend() -> PowBackend`; imports `randomx` (the `pyrandomx`/`randomx` binding, module name `randomx`, API `randomx.RandomX(seed_hash, full_mem=False).hash(blob)`) lazily; `randomx_backend()` raises `PowUnavailable(RuntimeError)` with the message `"RandomX binding not installed; use --anchor-sim-pow for simulation"` when the import fails. Height is used only to log; the seed hash is what selects the dataset (the caller passes the seed hash it received with the header, or zeros).
  - `def backend_for(config) -> PowBackend` — `Sha256Pow()` if `config.anchor_sim_pow` else `randomx_backend()`.
  - `def mine(make_blob, difficulty: int, pow: PowBackend, height: int = 0, seed_hash: bytes = bytes(32), max_nonce: int = 1 << 32) -> tuple[int, bytes]` — calls `make_blob(nonce)` for nonce 0.. until `check_hash(pow.hash(blob, height, seed_hash), difficulty)`; returns `(nonce, blob)`; raises `ValueError` if exhausted. Test and oracle helper.

- [ ] **Step 1: Test**

```python
def test_pow_backends():
    print("pow backends")
    from transpeer.anchor.powhash import Sha256Pow, mine, randomx_backend, PowUnavailable, backend_for
    from transpeer.anchor.monero import check_hash
    from transpeer.config import Config
    pow = Sha256Pow()
    nonce, blob = mine(lambda n: b"hdr" + n.to_bytes(4, "little"), 2000, pow)
    check(check_hash(pow.hash(blob, 0, bytes(32)), 2000), "mine finds a nonce meeting difficulty 2000")
    check(blob[3:7] == nonce.to_bytes(4, "little"), "mine returns the blob for its nonce")
    try:
        randomx_backend()
        check(True, "randomx binding present")
    except PowUnavailable as e:
        check("anchor-sim-pow" in str(e), "randomx_backend names the sim flag when unavailable")
    check(backend_for(Config(anchor_sim_pow=True)).name == "sha256", "backend_for picks sha256 under the sim flag")
```

(`Config.anchor_sim_pow` is added in this task: field `anchor_sim_pow: bool = False` and argparse `--anchor-sim-pow`, help "Simulation only: SHA-256 in place of RandomX for anchor-chain and share proof-of-work.")

- [ ] **Step 2: Run, expect ImportError.** **Step 3: Implement as specified.** **Step 4: Run; all suites green.** **Step 5: Commit** "Pluggable proof-of-work backend: SHA-256 under --anchor-sim-pow, RandomX in production".

---

### Task 4: Header chain verification

**Files:**
- Create: `transpeer/anchor/headers.py`
- Test: `tests/test_anchor_read.py`

**Interfaces:**
- Consumes: Task 2 (`parse_hashing_blob`, `block_id`, `check_hash`, `next_difficulty`, constants), Task 3 (`PowBackend`).
- Produces:
  - `@dataclass(frozen=True) class HeaderRow: height: int; blob: bytes; difficulty: int` (`blob` is the hashing blob).
  - `@dataclass class Checkpoint: height: int; hash: bytes`; `parse_checkpoint("HEIGHT:HEXHASH") -> Checkpoint` (ValueError otherwise).
  - `class HeaderError(ValueError)`.
  - `@dataclass class ChainView: first: int; ids: list[bytes]; timestamps: list[int]; difficulties: list[int]; cumulative: list[int]; blobs: list[bytes]` with `tip_height`, `tip_id`, `work` (= cumulative[-1]), `height_of(id) -> int | None`, `id_at(height)`, `timestamp_at(height)`.
  - `def verify_headers(rows: list[HeaderRow], checkpoint: Checkpoint, pow: PowBackend, now: int, rng=random.Random(), sample: float = 0.05, recent: int = 720, seed_hash_for=lambda height: bytes(32)) -> ChainView`.
  - `def best_view(views: list[ChainView]) -> ChainView | None` — greatest `work`; ties by lower tip id bytes.
  - `STALE_TIP = 1800`.

Rules of `verify_headers` (spec §6.2 and §17.1), in order, each failure raising `HeaderError` with a message naming the height:
1. `rows` non-empty, contiguous heights ascending, `rows[0].height <= checkpoint.height <= rows[-1].height`, and `rows[0].height <= max(0, checkpoint.height - DIFFICULTY_BLOCKS_COUNT)` unless `checkpoint.height < DIFFICULTY_BLOCKS_COUNT` (then it must be 0).
2. Each blob parses; `prev_id` of row *i* equals `block_id` of row *i−1* (linkage); `block_id` at `checkpoint.height` equals `checkpoint.hash`.
3. Timestamps: each ≤ `now + BLOCK_FUTURE_TIME_LIMIT`; each ≥ the median of the previous 60 timestamps when 60 are available (Monero `check_block_timestamp`).
4. Difficulty: for rows at or before the checkpoint use `row.difficulty` as served (must be ≥ 1). For rows after the checkpoint compute `next_difficulty(ts_window, cum_window)` where the windows are the timestamps and cumulative difficulties of the up-to-735 blocks immediately before this height, oldest first (Monero `get_difficulty_for_next_block`), and require equality with `row.difficulty`. When fewer than 735 previous blocks exist in `rows` (only possible if `rows[0].height == 0`), use what exists. Cumulative difficulty of a row is the running sum from `rows[0]` (the first row's cumulative is its own difficulty).
5. Proof-of-work: for every row in the last `recent` rows and for each earlier row with probability `sample` (via `rng.random() < sample`), require `check_hash(pow.hash(blob, height, seed_hash_for(height)), row.difficulty)`.
6. Stale tip: `now - timestamps[-1] > STALE_TIP` → `HeaderError("stale tip")`.

- [ ] **Step 1: Test** — build a synthetic chain with a helper (put the helper at module level in the test file; Tasks 5–8 reuse it):

```python
def make_chain(n, pow, start_ts=1_700_000_000, difficulty=50, spacing=120, first=0, prev=bytes(32)):
    """n hashing blobs with valid linkage and PoW at constant difficulty."""
    from transpeer.anchor.monero import build_block_blob, hashing_blob, block_id
    from transpeer.anchor.powhash import mine
    from transpeer.anchor.headers import HeaderRow
    rows, blobs = [], []
    for i in range(n):
        h = first + i
        ts = start_ts + spacing * i
        def mk(nonce, h=h, ts=ts, prev=prev):
            return hashing_blob(build_block_blob(16, 16, ts, prev, nonce, h, b"\x01" + bytes(32)))
        _, hb = mine(mk, difficulty, pow, h)
        rows.append(HeaderRow(h, hb, difficulty))
        blobs.append(hb)
        prev = block_id(hb)
    return rows


def test_headers():
    print("header chain")
    import random
    from transpeer.anchor.headers import (verify_headers, Checkpoint, parse_checkpoint, HeaderError,
                                          HeaderRow, best_view)
    from transpeer.anchor.monero import block_id
    from transpeer.anchor.powhash import Sha256Pow
    pow = Sha256Pow()
    rows = make_chain(40, pow)
    cp = Checkpoint(10, block_id(rows[10].blob))
    now = 1_700_000_000 + 120 * 39 + 60
    v = verify_headers(rows, cp, pow, now, rng=random.Random(1))
    check(v.tip_height == 39 and v.tip_id == block_id(rows[-1].blob), "view tip")
    check(v.work == 50 * 40 and v.height_of(cp.hash) == 10, "cumulative work and lookup")
    check(parse_checkpoint(f"10:{cp.hash.hex()}") == cp, "parse_checkpoint")
    bad = list(rows); bad[20] = HeaderRow(20, rows[20].blob, 51)
    try:
        verify_headers(bad, cp, pow, now); check(False, "difficulty mismatch after checkpoint rejected")
    except HeaderError as e:
        check("20" in str(e), "difficulty mismatch names the height")
    try:
        verify_headers(rows, Checkpoint(10, bytes(32)), pow, now); check(False, "checkpoint mismatch rejected")
    except HeaderError:
        check(True, "checkpoint mismatch rejected")
    try:
        verify_headers(rows, cp, pow, now + 4000); check(False, "stale tip rejected")
    except HeaderError as e:
        check("stale" in str(e), "stale tip rejected")
    fake = rows[:30] + [HeaderRow(30, rows[30].blob[:-1] + b"\x01", 50)]
    try:
        verify_headers(fake, cp, pow, now); check(False, "tampered blob rejected")
    except HeaderError:
        check(True, "tampered blob rejected (PoW or linkage)")
    longer = make_chain(45, pow)
    v2 = verify_headers(longer, Checkpoint(10, block_id(longer[10].blob)), pow, now + 600, rng=random.Random(1))
    check(best_view([v, v2]) is v2, "best_view picks the most work")
```

Note: with constant spacing and difficulty the recomputed difficulty after the checkpoint equals 50 only when the window is short enough that `next_difficulty` returns the served value — the test chain has 40 rows, so every post-checkpoint window has < 600 entries and no cut; `total_work * 120 / time_span` = `50 * k * 120 / (120 * k)` = 50. Keep the chain at constant spacing.

- [ ] **Step 2: Run, expect ImportError.** **Step 3: Implement `headers.py` to the rules above** (about 120 lines; keep each rule a private function). **Step 4: Run; green.** **Step 5: Commit** "Anchor header chain verification: linkage, checkpoint, difficulty rule, PoW sampling, stale tip".

---

### Task 5: P2Pool share codec

**Files:**
- Create: `transpeer/anchor/share.py`
- Test: `tests/test_anchor_read.py`

**Interfaces:**
- Consumes: `keccak256`, varints, `merkle.py` (`aux_slot`, `verify_merkle_proof`, `decode_tree_params`, `encode_tree_params`, `merkle_tree`, `merkle_proof`, `merkle_root`), Task 2 (`tree_hash`, `miner_tx_hash`, `check_hash`), Task 3.
- Produces:
  - Constants copied from `excerpts/p2p_framing.txt` and `excerpts/share_format.txt`: `MAX_BLOCK_SIZE = 128 * 1024 - 5`, `HARDFORK_SUPPORTED_VERSION = 16`, `MINER_REWARD_UNLOCK_TIME = 60`, `EXTRA_NONCE_SIZE = 4`, `EXTRA_NONCE_MAX_SIZE = 14`, `TX_VERSION = 2`, `TXIN_GEN = 0xFF`, `TXOUT_TO_TAGGED_KEY = 3`, `TX_EXTRA_TAG_PUBKEY = 1`, `TX_EXTRA_NONCE = 2`, `TX_EXTRA_MERGE_MINING_TAG = 3`, `BASE_BLOCK_REWARD = 600000000000`, `MAX_OUTPUT_VALUE = (1 << 56) - 1`, `MAX_UNCLES_PER_BLOCK = 5`, `MAX_SIDECHAIN_HEIGHT = 31556952000`, `CRYPTONOTE_MAX_BLOCK_NUMBER = 500000000`, `MERGE_MINING_MAX_CHAINS = 256`, `LOG2_MERGE_MINING_MAX_CHAINS = 8`, `MAX_CUMULATIVE_DIFFICULTY = 13019633956666736640 + (1710 << 64)`.
  - `VENUES = {"main": bytes([34,175,...]), "mini": bytes([57,130,...]), "nano": bytes([171,248,...])}` — the three 32-byte consensus ids from `excerpts/p2p_framing.txt` (side_chain.cpp lines 1-64), and `VENUE_PORTS = {"main": 37889, "mini": 37888, "nano": 37890}`, `VENUE_WINDOW = 2160`, `VENUE_BLOCK_TIME = {"main": 10, "mini": 10, "nano": 30}`.
  - `class ShareError(ValueError)`.
  - `@dataclass(frozen=True) class ParsedShare`: `id`, `raw`, `major`, `minor`, `timestamp`, `prev_id`, `nonce`, `txin_gen_height`, `outputs: tuple[tuple[int, bytes, int], ...]` (reward, eph key, view tag), `tx_pubkey`, `extra_nonce`, `n_aux_chains`, `aux_nonce`, `merkle_root`, `tx_hashes: tuple[bytes, ...]`, `spend_pub`, `view_pub`, `txkey_sec_seed`, `parent`, `uncles: tuple[bytes, ...]`, `height` (sidechain), `difficulty`, `cumulative_difficulty`, `merkle_proof: tuple[bytes, ...]`, `aux: dict[bytes, tuple[bytes, int]]` (chain id → (aux hash, aux difficulty)), `extra_buf: bytes` (16), `hashing_blob: bytes`, `wallet: str` (`spend_pub.hex() + view_pub.hex()`).
  - `def parse_share(data: bytes, consensus_id: bytes) -> ParsedShare` — full (non-compact, non-pruned) `PoolBlock::deserialize` transcribed from `excerpts/share_format.txt` with these differences: `num_outputs == 0` (pruned) → `ShareError("pruned share")`; the network major version and `get_cached_next_difficulty` checks are skipped; the tx-key checks (`get_tx_keys`, `check_keys`) are skipped (spec §17.1); the share id is recomputed exactly as the `keccak_custom` lambda does: Keccak over the main-chain bytes with the 4 nonce bytes, the 4 extra-nonce bytes and the 32 Merkle-root bytes replaced by zeros, followed by the side-chain bytes, followed by `consensus_id`; then `verify_merkle_proof(id, proof, path, root)` where `path` is derived from the aux slot — use `merkle.verify_merkle_proof` with the *index/count* semantics: implement a local `_verify_proof_by_index(leaf, proof, index, count, root)` transcribed from P2Pool `verify_merkle_proof(h, proof, index, count, root)` (`merkle.cpp`; the excerpt has `merkle_hash_full_tree`, and the index form is: `if count == 1: return proof empty and h == root; if count == 2: return len(proof)==1 and keccak(h+p0 if index==0 else p0+h) == root; else cnt = pow2_below(count); k = cnt*2-count; if index >= k: index -= k; j = (index ^ 1) + k; ...` — implementers: transcribe `get_root_from_proof` from the P2Pool `merkle.cpp` in the scratchpad `p2pool/merkle.cpp`, lines after `merkle_hash_full_tree`, and compare with the root).
  - `def verify_share_pow(share: ParsedShare, pow: PowBackend, seed_hash: bytes = bytes(32)) -> bool` — `check_hash(pow.hash(share.hashing_blob, share.txin_gen_height, seed_hash), share.difficulty)`.
  - `def transpeer_aux(share: ParsedShare, chain_id=CHAIN_ID) -> bytes | None` — the aux hash for our chain, or None.
  - `def build_share(*, consensus_id, txin_gen_height, prev_id, timestamp, parent, height, difficulty, cumulative_difficulty, aux: dict[bytes, tuple[bytes, int]], spend_pub=bytes(32), view_pub=bytes(32), seed=bytes(32), uncles=(), tx_hashes=(), outputs=((BASE_BLOCK_REWARD, bytes(32), 0),), tx_pubkey=b"\x01"*32, extra_nonce=0, nonce=0, major=16, minor=16, extra_buf=bytes(16)) -> bytes` — the encoder (`serialize_mainchain_data` + `serialize_sidechain_data`) used by tests, the venue oracle and the P2Pool double. It computes the share id (root zeroed), builds the aux tree with leaves = `{consensus_id: share_id} ∪ aux`, finds `aux_nonce` with `find_aux_nonce`, places leaves by `aux_slot` (n = number of leaves), computes the root and the share's proof, writes the tag with `encode_tree_params(n, aux_nonce)`, then serialises. `mine_share(build_kwargs, pow) -> bytes` loops `nonce` until `verify_share_pow` passes.
  - `def share_id_of(data: bytes, consensus_id: bytes) -> bytes` — convenience (parse and return id).

Hashing blob of a share (`get_pow_hash` in the excerpt): header bytes (major, minor, timestamp varint, prev_id, nonce), then `tree_hash([miner_tx_hash(miner_tx)] + tx_hashes)`, then `write_varint(1 + len(tx_hashes))`; `miner_tx` is everything from `TX_VERSION` through the trailing `0x00` byte inclusive.

- [ ] **Step 1: Test**

```python
def test_share_codec():
    print("share codec")
    from transpeer.anchor import CHAIN_ID
    from transpeer.anchor.share import (build_share, parse_share, verify_share_pow, mine_share, ShareError,
                                        transpeer_aux, VENUES, MAX_BLOCK_SIZE)
    from transpeer.anchor.merkle import verify_merkle_proof, aux_slot, parse_tx_extra_mm_tag
    from transpeer.anchor.powhash import Sha256Pow
    pow = Sha256Pow()
    venue = VENUES["mini"]
    blob_hash = hashlib.sha256(b"blob").digest()
    kw = dict(consensus_id=venue, txin_gen_height=3000000, prev_id=bytes(32), timestamp=1_700_000_000,
              parent=bytes(32), height=0, difficulty=300, cumulative_difficulty=300,
              aux={CHAIN_ID: (blob_hash, 100000)})
    raw = mine_share(kw, pow)
    s = parse_share(raw, venue)
    check(s.height == 0 and s.difficulty == 300 and s.parent == bytes(32), "sidechain fields")
    check(transpeer_aux(s) == blob_hash and s.aux[CHAIN_ID][1] == 100000, "aux map carries our blob hash and difficulty")
    check(s.n_aux_chains == 2, "two aux chains: venue and transpeer")
    check(verify_share_pow(s, pow), "share PoW meets its difficulty")
    check(len(raw) < MAX_BLOCK_SIZE, "size bound")
    try:
        parse_share(raw, VENUES["main"]); check(False, "wrong consensus id rejected")
    except ShareError:
        check(True, "wrong consensus id changes the share id and fails the aux proof")
    try:
        parse_share(raw[:-1], venue); check(False, "truncated share rejected")
    except ShareError:
        check(True, "truncated share rejected")
    tampered = bytearray(raw); tampered[-1] ^= 1
    try:
        parse_share(bytes(tampered), venue); check(False, "tampered extra buf rejected")
    except ShareError:
        check(True, "tampered bytes change the share id and fail the aux proof")
    # A share on top of it, with two uncles sorted, and no transpeer aux
    raw2 = mine_share(dict(kw, parent=s.id, height=1, cumulative_difficulty=600, aux={}), pow)
    s2 = parse_share(raw2, venue)
    check(s2.parent == s.id and transpeer_aux(s2) is None and s2.n_aux_chains == 1, "child share, venue only")
    check(s2.merkle_proof == () and s2.merkle_root == s2.id, "single leaf: root is the share id")
```

- [ ] **Step 2: Run, expect ImportError.** **Step 3: Implement `share.py`** transcribing the parser from the excerpt line by line (keep the excerpt's order of fields and checks; every `return __LINE__` becomes `raise ShareError("<what failed>")`). **Step 4: Run; green.** **Step 5: Commit** "P2Pool share codec: full PoolBlock parser, share id, aux proof, PoW check, encoder for tests and oracle".

---

### Task 6: Anchor and share stores

**Files:**
- Create: `transpeer/anchor/stores.py`
- Test: `tests/test_anchor_read.py`

**Interfaces:**
- Consumes: Task 4 (`HeaderRow`, `ChainView`), Task 5 (`ParsedShare`, `parse_share`).
- Produces:
  - `class AnchorStore(path: Path | None)`: `headers: dict[int, HeaderRow]`, `blocks: dict[int, bytes]` (block blobs for the coverage window), `view: ChainView | None`; methods `put_headers(rows)`, `header_rows(from_height, count) -> list[HeaderRow]` (contiguous from `from_height`, stops at a gap), `put_block(height, blob)`, `block(height) -> bytes | None`, `tip_height() -> int | None`, `prune(keep_from_height)`, `save()`, `load()` (JSON: hex blobs; skip when `path` is None).
  - `class ShareStore(venue: bytes, path: Path | None)`: `add(share: ParsedShare) -> bool` (False if present), `get(id) -> ParsedShare | None`, `raw(id) -> bytes | None`, `by_root(root) -> ParsedShare | None`, `walk(from_id, count) -> list[ParsedShare]` (the share, then parents while known, at most `count`), `tip() -> ParsedShare | None` (highest cumulative difficulty), `prune(tip_height, window=2160)` removes shares with `height < tip_height - 4 * window`, `count()`. On disk: `path/<id hex>` raw bytes written on `add`, index rebuilt by `load(consensus_id)` parsing every file (files that fail to parse are deleted).
  - `def venue_dir(data_dir: Path, venue: bytes) -> Path` = `data_dir / "venues" / venue.hex()`.

- [ ] **Step 1: Test** — round trips through a `tempfile.TemporaryDirectory()`: put 5 header rows, save, load, `header_rows(2, 10)` returns 3; ShareStore add/get/by_root/walk over the two shares from Task 5's `mine_share`, reload from disk, `prune` removes an old share, tampered file on disk is dropped at load.
- [ ] **Step 2–5:** run, implement, run all suites, commit "Anchor header/block store and per-venue share store with on-disk raw shares".

---

### Task 7: Anchor and venue endpoints, and the fetch client

**Files:**
- Modify: `transpeer/server.py` (`TranspeerServer.__init__` gains `anchor_store=None, share_stores: dict[bytes, ShareStore] | None = None`; new handlers; routes)
- Create: `transpeer/anchor/fetch.py`
- Test: `tests/test_anchor_read.py`

**Interfaces:**
- Produces, on the transpeer port, all rate-limited, no handshake PoW, 404 with `{"error": "anchor not configured"}` when the store is absent:
  - `GET /anchor/{chain}/headers?from=H&count=N` → `{"chain": chain, "tip": tip_height, "headers": [{"height": h, "blob": hex, "difficulty": d}, ...]}`; `count` clamped to 1..720; `chain` must equal `config.anchor_chain` else 404.
  - `GET /anchor/{chain}/coinbase/{height}` → block blob as `application/octet-stream`, 404 if absent.
  - `GET /venue/{id}/share/{share_id}` → raw share bytes, 404 if absent; 400 on bad hex.
  - `GET /venue/{id}/shares?from=ID&count=N` → `{"shares": [hex, ...]}` from `ShareStore.walk`, `count` clamped 1..64.
  - `GET /venue/{id}/share_by_root/{root}` → raw share bytes or 404.
  - `class AnchorClient(config)` in `fetch.py` with aiohttp session per call (like `TranspeerClient`), 10 s timeout, User-Agent from `config.user_agent`-style header (`transpeer.config.user_agent(config.contact)`): `fetch_headers(addr, port, chain, from_height, count) -> list[HeaderRow]`, `fetch_tip(addr, port, chain) -> int | None`, `fetch_block(addr, port, chain, height) -> bytes | None`, `fetch_share(addr, port, venue, share_id) -> bytes | None`, `fetch_shares(addr, port, venue, from_id, count) -> list[bytes]`, `fetch_share_by_root(addr, port, venue, root) -> bytes | None`, `fetch_blob(addr, port, h) -> bytes | None` (verifies `blob_hash(body) == h`, else None), `fetch_index(addr, port, since, after) -> tuple[list[dict], int | None, bytes | None]`. Every method returns the empty value on any `aiohttp.ClientError`, `asyncio.TimeoutError`, `ValueError`.

- [ ] **Step 1: Test** — start a `TranspeerServer` with `Config(in_memory=True, no_verify=True, anchor_chain="monero")`, an `AnchorStore(None)` holding the Task 4 chain and one block blob, a `ShareStore` with the Task 5 shares, on port 17350; exercise every endpoint through `AnchorClient` and assert the round trips, the clamps (`count=5000` → 720 headers max; ask for 800 rows from a 40-row chain and get 40), the 404s, and `fetch_blob` returning None for a body whose hash does not match (serve a wrong body via a second tiny aiohttp app on 17351).
- [ ] **Step 2–5:** run, implement, run all suites, commit "Anchor and venue endpoints on the transpeer port, and the fetch client".

---

### Task 8: The reader

**Files:**
- Create: `transpeer/anchor/reader.py`
- Modify: `transpeer/config.py` (flags), `transpeer/peerstore.py` (`TranspeerEntry.published: bool = False`, `unfaithful: bool = False`, persisted with two `ALTER TABLE transpeers ADD COLUMN ... INTEGER NOT NULL DEFAULT 0` migrations after the existing `first_seen` one; `set_published(addr, port, flag)`, `set_unfaithful(addr, port, flag)`, both async, saving the row)
- Test: `tests/test_anchor_read.py`

**Interfaces:**
- Consumes: everything above; `BlobDB`, `weight.py`, `PeerStore`.
- Produces:
  - Config fields and flags: `anchor_read: bool = False` (`--anchor-read`), `anchor_checkpoint: str = ""` (`--anchor-checkpoint HEIGHT:HASH`), `anchor_venues: str = ""` (`--anchor-venues NAME_OR_HEX,...`; empty means main, mini, nano), `anchor_window_days: float = 7.0` (`--anchor-window-days`), `anchor_monerod: str = ""`, `anchor_observe: str = ""` (parsed in Tasks 12–13, declared here). `--anchor-read` without `--anchor-checkpoint` is an argparse error.
  - `def venues_from_config(config) -> dict[bytes, str]` — consensus id → name; names resolve through `share.VENUES`, 64-hex strings are ids.
  - `@dataclass class ReaderState: tagged: int = 0; resolved: int = 0; coverage: float = 0.0; bootstrapped: bool = False; tip_height: int | None = None; venues: dict[bytes, bytes] = field(default_factory=dict)` (venue → canonical tip share id); `weights: dict[tuple[str, int], int]`; `published: list[tuple[str, int]]`; `last_sync: float = 0.0`.
  - `class Reader(config, store: PeerStore, blobdb: BlobDB, anchor: AnchorStore, shares: dict[bytes, ShareStore], client: AnchorClient, pow: PowBackend, clock=time.time, rng=None)` with:
    - `async sync(sources: list[tuple[str, int]]) -> ReaderState` — the newcomer path:
      1. **Headers.** For each source (at most 5, in the given order): `fetch_tip`, then `fetch_headers` in pages of 720 from `max(0, checkpoint.height - 735)` (or from the local store's tip − 735 when a verified view exists and its tip is newer than the checkpoint) to the tip; `verify_headers` with `now=clock()`; keep the resulting `ChainView` per source; `best_view` wins and is stored (`anchor.put_headers`, `anchor.view`). A source whose headers fail is logged at WARNING and skipped. No view → return the state unchanged with `bootstrapped=False`.
      2. **Coverage window.** `window_from = tip_height - int(anchor_window_days * 86400 / 120)`. For each height in `[window_from, tip]` lacking a block blob, `fetch_block` from the sources in turn; verify `hashing_blob(blob) == view.blobs[height - view.first]` (this checks the coinbase against the header's tree root); store it. Parse the tag with `parse_tx_extra_mm_tag(parse_block_blob(blob).tx_extra)`; tagged blocks go into `tagged: dict[height, MergeMiningTag]`.
      3. **Venue leaves.** For each tagged block newest first, for each configured venue whose slot `aux_slot(venue, tag.nonce, tag.n_aux_chains)` is unused so far: if the share store has `by_root(tag.root)` use it, else `fetch_share_by_root` from the sources; `parse_share(raw, venue)`; require `share.merkle_root == tag.root`, `share.n_aux_chains == tag.n_aux_chains`, `share.aux_nonce == tag.nonce`, `verify_share_pow`; store it. The first (newest) such share per venue is the venue's canonical tip. A tagged block resolved for some venue counts in `resolved`.
      4. **Canonical fork.** For each venue with a tip: `walk` locally, and while the walk is shorter than `VENUE_WINDOW` and the last share's parent is unknown and not zero, `fetch_shares(from=parent, count=64)` from the sources, parsing and verifying each (parse, PoW, `parent`/`height` consistent: child.height == parent.height + 1) before storing; stop when a batch adds nothing.
      5. **Blobs.** For each canonical share with `transpeer_aux(share)`, if `blobdb.get(h)` is None: `fetch_blob` from the sources; `decode_blob` (drop on `BlobError`); `blobdb.add(blob, Commitment(h, "share", venue.hex(), share.id.hex(), share.wallet, share.difficulty, share.timestamp), now)`.
      6. **Weights.** Convert canonical shares to `weight.Share(id, venue.hex(), height, parent, difficulty, timestamp, wallet, {cid: h for cid, (h, _) in aux.items()})`; `blob_weights` per venue summed (`transpeer_weights` over the merged dict); `coverage(tagged, resolved)`, `bootstrapped`.
      7. **Seeding.** `published = top 64 by weight`; for each, `store.add_transpeer(TranspeerEntry(addr, port, last_seen=now))` if unknown, then `store.set_published(addr, port, True)`; entries previously published but no longer in the list get `False`. Return the state (also kept as `self.state`).
    - `async gossip(addr, port) -> int` — pages `/blobs/index` from the cursor kept per `(addr, port)` in `self._cursors`; for each row lacking locally: `fetch_blob`; for each commitment: `share` kind → `fetch_share(addr, port, venue, ref)`, parse, PoW, `transpeer_aux == row hash`; `block` kind → `ref` is `"HEIGHT:HEXID"`, require the local block blob at that height (fetch from this transpeer if missing and verify against the view), tag present, `verify_merkle_proof(hash, proof, path, tag.root)`; `template` → skip. Store the blob with each verified commitment; returns the number of new rows stored. Cursor advances only when the page was fully processed.
    - `verified_hashes(min_age: int) -> list[bytes]` — blob hashes the reader has stored with at least one verified commitment older than `min_age` seconds (for Task 11).
    - `bootstrapped` property.
- Log one line `READER_STATE tagged=%d resolved=%d coverage=%.2f bootstrapped=%s tip=%s venues=%d published=%d` per sync (simulation metric).

- [ ] **Step 1: Test** — an end-to-end fixture on loopback (port 17352 for the serving node, 17353 for the reading node's own server is not needed): build with `Sha256Pow` a 40-block anchor chain where blocks 30–39 carry merge-mining tags whose leaves are a mini-venue share id and one of two list blobs (blob A lists `("10.1.0.1", 7337)`, blob B lists `("10.2.0.1", 7337)`); mint a mini share chain of 12 shares (heights 0..11) where shares 2–11 commit to blob A and blob B alternately... keep it simple: shares 0–5 commit A, 6–11 commit B, difficulty 300 each; the share whose root goes into the tag at block 39 is share 11, at block 38 share 10, etc. (blocks 30–39 ↔ shares 2–11). Serve from a `TranspeerServer` + `AnchorStore` + `ShareStore` + `BlobDB` as Task 7 did. Then a `Reader` with an in-memory `PeerStore`, `Checkpoint(5, id)`, `anchor_window_days` such that the window covers blocks 30–39 (`(40-30) * 120 / 86400`), `sync([("127.0.0.1", 17352)])`. Assert: `state.tagged == 10`, `state.resolved == 10`, `bootstrapped`, canonical tip is share 11, weights `{("10.1.0.1",7337): 300*6, ("10.2.0.1",7337): 300*6}`, both entries `published` in the store, blobdb holds A and B with `share` commitments. Then `gossip`: add a third blob C with a `share` commitment to the serving node's BlobDB (mint share 12 committing C on top of 11 and add it to the ShareStore) and assert `gossip` stores C with its commitment, and that a row with a `template` commitment only is not stored.

Building this fixture is the largest piece of test code in the plan; put it in a helper `build_world(pow)` returning a dict (`rows`, `blocks`, `shares`, `blobs`) so Tasks 10–13 reuse it.

- [ ] **Step 2–5:** run, implement, run all suites, commit "The reader: newcomer path over headers, tags, shares and blobs; weights, coverage, seeding; blob gossip".

---

### Task 9: Store tags in the hand-off ranking

**Files:**
- Modify: `transpeer/peerstore.py` (`Peer.published_vouchers: set`, `add_peer`, `_rank_key`, `_represent`, `get_transpeers_for_query`, `get_transpeers_for_gossip`, `_pick_eviction`)
- Test: `tests/test_anchor_read.py`

**Interfaces:**
- Under `config.anchor_read` (and `config.vouchers`): when a peer is reported by a transpeer whose `TranspeerEntry.published` is True, its bucket goes into `peer.published_vouchers` as well as `vouchers`. `_rank_key` becomes `(len(published_vouchers), <existing key>)`. In `_represent`, the pass over unrepresented buckets iterates published buckets first (a bucket is published if any published transpeer is in it), then the rest. `get_transpeers_for_query` and `get_transpeers_for_gossip` sort unfaithful entries last; `_pick_eviction` returns an unfaithful entry's bucket first when one exists. With `anchor_read` False nothing changes (assert by running `tests/test_bucketed.py`).

- [ ] **Step 1: Test** — `Config(in_memory=True, vouchers=True, anchor_read=True, anchor_checkpoint="0:" + "00"*32)`; two transpeers in different /16s, one published; each reports one distinct peer; `get_peers("monero", verified_only=False)` lists the published reporter's peer first although both have one voucher; flip published and the order flips. Unfaithful: three transpeers, mark one unfaithful, `get_transpeers_for_query(3)` puts it last; `_pick_eviction` prefers its bucket.
- [ ] **Step 2–5:** run, implement, run **all** suites (bucketed must stay 47/47), commit "Published reporters rank first, unfaithful transpeers last, under --anchor-read".

---

### Task 10: Node wiring and scan-stop

**Files:**
- Modify: `transpeer/node.py`, `transpeer/scanner.py`, `transpeer/client.py`
- Test: `tests/test_anchor_read.py`

**Interfaces:**
- `Scanner.__init__` gains `idle_fn=None`; `current_rate` uses `idle = idle_fn() if idle_fn else live >= target`.
- `TranspeerClient.__init__` gains `after_query=None`; `query_transpeer` awaits `after_query(entry)` after a successful query (before `return True`), catching and logging exceptions.
- `Node.run` under `config.anchor_read`: builds `BlobDB` (shared with the publisher when both flags are on), `AnchorStore(data_dir / "anchor_chain.json" or None)`, one `ShareStore` per configured venue, `AnchorClient`, `backend_for(config)` (a `PowUnavailable` at start-up is fatal with its message), `Reader`; passes `anchor_store` and `share_stores` to `TranspeerServer`; sets `scanner idle_fn = lambda: reader.bootstrapped`; sets `client.after_query = reader.gossip_entry` (wrapper taking the entry); adds `_reader_loop` (first sync immediately, then every 60 s; sources = live transpeers first, then all known, up to 5; save stores after each sync when not in memory).
- `Node` exposes `self.reader`.

- [ ] **Step 1: Test** — `test_node_wiring_read`: construct `Node(Config(in_memory=True, no_verify=True, anchor_read=True, anchor_sim_pow=True, anchor_checkpoint=..., port=17354, scan_rate=0))`, run `node.run()` as a task for 1 s, assert `node.reader is not None`, `node.scanner.current_rate()` is the cold rate while not bootstrapped, and the `/anchor/monero/headers` endpoint answers on 17354 (empty list, tip null). Cancel the task.
- [ ] **Step 2–5:** run, implement, run all suites, commit "Wire the reader into the node: reader loop, gossip after query, scan-stop by coverage".

---

### Task 11: Faithfulness challenges

**Files:**
- Create: `transpeer/anchor/challenge.py`
- Modify: `transpeer/node.py` (`_challenge_loop`), `transpeer/anchor/publisher.py` (curation rule 6: skip `unfaithful` entries)
- Test: `tests/test_anchor_read.py`

**Interfaces:**
- `class Challenger(store, reader, client: AnchorClient, clock=time.time, rng=None)`; constants `PER_HOUR = 8`, `MIN_AGE = 600`, `FAIL_LIMIT = 3`, `FAIL_WINDOW = 86400`, `MIN_UPTIME = 600`.
  - `async round()`: for each transpeer entry with `alive` and `uptime >= MIN_UPTIME` (uptime is `TranspeerEntry.uptime`, a new int field filled by `probe_transpeer` from the `/transpeer` response, default 0, not persisted), sample up to `PER_HOUR` hashes from `reader.verified_hashes(MIN_AGE)` not yet asked of this transpeer this hour; `fetch_blob`; None → failure. Failures per transpeer are timestamps in a deque; prune older than `FAIL_WINDOW`; `>= FAIL_LIMIT` → `store.set_unfaithful(True)`; a transpeer with no failure in the window gets `set_unfaithful(False)`. A hash every challenged transpeer failed in this round is added to `self.lost` and never sampled again.
  - `stats` dict: `challenged`, `failed`, `marked`, `lost`.
- Node: `_challenge_loop` runs `round()` every 3600 s when `reader` exists.
- Publisher `curate`: `if getattr(e, "unfaithful", False): continue` as rule 6.

- [ ] **Step 1: Test** — serving node from Task 8's world on 17355 (serves blobs A, B) and a second server on 17356 that returns 404 for everything (`BlobDB()` empty); Reader state faked with `verified_hashes` returning `[A, B]`; entries for both, `alive=True`, `uptime=1000`; run `round()` three times with a clock stepping 1 h; the 404 node becomes unfaithful, the good one not; `lost` stays empty; then make both fail a hash (remove it from the good node's DB) and assert it lands in `lost` with no new mark.
- [ ] **Step 2–5:** run, implement, run all suites (publish suite must stay 118), commit "Faithfulness challenges (spec §9): sampled blob fetches, unfaithful mark, lost hashes".

---

### Task 12: P2Pool observer client and its double

**Files:**
- Create: `transpeer/anchor/p2p.py`, `sim/p2pool_double.py`
- Modify: `transpeer/node.py` (`_observe_loop`), `transpeer/config.py` (parse `--anchor-observe`)
- Test: `tests/test_anchor_read.py`

**Interfaces (wire facts from `excerpts/p2p_framing.txt` and `excerpts/p2p_protocol.txt`):**
- Stream framing: no length prefix; a message is one id byte followed by a fixed payload, except `BLOCK_RESPONSE`, `BLOCK_BROADCAST`, `BLOCK_BROADCAST_COMPACT`, `AUX_JOB_DONATION`, `MONERO_BLOCK_BROADCAST` whose payload is a little-endian `uint32` size then that many bytes (size ≤ `MAX_BLOCK_SIZE`). Ids: `HANDSHAKE_CHALLENGE=0` (8-byte challenge + 8-byte peer id), `HANDSHAKE_SOLUTION=1` (32-byte hash + 8-byte salt), `LISTEN_PORT=2` (int32 LE), `BLOCK_REQUEST=3` (32-byte id; zero id = tip), `BLOCK_RESPONSE=4`, `BLOCK_BROADCAST=5`, `PEER_LIST_REQUEST=6` (no payload), `PEER_LIST_RESPONSE=7` (1 count byte ≤ 16, then 19 bytes per peer: v6 flag, 16-byte address with IPv4 in the last 4 bytes after the `ipv4_prefix`, 2-byte port LE; the pseudo-peer 255.255.255.255:65535 carries protocol and software version and is skipped), `BLOCK_BROADCAST_COMPACT=8`, `BLOCK_NOTIFY=9` (32 bytes), `AUX_JOB_DONATION=10`, `MONERO_BLOCK_BROADCAST=11`.
- Handshake: on connect both sides send `HANDSHAKE_CHALLENGE`. On receiving the peer's challenge, compute `solution = keccak256(challenge + consensus_id + salt)` for increasing 8-byte little-endian salts until `int.from_bytes(solution[24:32], "little") * 10000 < 2**64` (the initiator's proof-of-work), send `HANDSHAKE_SOLUTION(solution, salt)`. On receiving their solution, check `keccak256(our_challenge + consensus_id + their_salt) == their_solution`; else disconnect. Peer id: 8 random non-zero bytes. `LISTEN_PORT` is **not** sent (§17.1 amendment in Task 14: the observer is never advertised); after the handshake send `BLOCK_REQUEST(zero)` then `PEER_LIST_REQUEST`.
- `class P2PoolClient(host, port, consensus_id, on_share=None, timeout=10)`: `async connect()`, `async request_block(share_id) -> bytes | None` (empty response → None), `async request_peers() -> list[tuple[str, int]]`, `async close()`; a reader task dispatches incoming messages: broadcasts (full) are passed to `on_share(raw)`; compact broadcasts, notifies, donations and Monero broadcasts are skipped by size; an incoming `PEER_LIST_REQUEST` is answered with a zero-count `PEER_LIST_RESPONSE`; an incoming `BLOCK_REQUEST` is answered with an empty `BLOCK_RESPONSE` (size 0). Requests are serialised with a queue of pending futures matched in order, as P2Pool does.
- `sim/p2pool_double.py`: `class P2PoolDouble(consensus_id, shares: dict[bytes, bytes], tip: bytes, peers: list[tuple[str,int]])` — an asyncio server speaking the same bytes from the responder's side (challenge, solution without PoW, verify the client's PoW and hash, `BLOCK_REQUEST` → `BLOCK_RESPONSE` with the share or size 0, zero id → tip; `PEER_LIST_REQUEST` → first reply includes the version pseudo-peer then up to 16 peers). `start(port)`, `stop()`. Also usable by the slice-4 oracle.
- Node: under `--anchor-observe host:port,...` (each paired with a venue by the port's default mapping `VENUE_PORTS`, or `venue@host:port` explicitly), `_observe_loop` keeps one client per address, requests the tip every 60 s, walks parents until known, verifies with `parse_share` + `verify_share_pow`, stores; reconnects with 60 s backoff on failure.

- [ ] **Step 1: Test** — `P2PoolDouble` on 17357 with the Task 5 shares; `P2PoolClient` connects (handshake with PoW), `request_block(zero)` returns the tip raw bytes, `request_block(unknown)` returns None, `request_peers()` returns the configured peers without the pseudo-peer, a broadcast pushed by the double reaches `on_share`; the double rejects a client whose consensus id differs (connection closed, `connect()` raises `ConnectionError`).
- [ ] **Step 2–5:** run, implement, run all suites, commit "P2Pool observer client (handshake, peer list, block request) and a Python double for tests and the oracle".

---

### Task 13: monerod source

**Files:**
- Create: `transpeer/anchor/monerod.py`
- Modify: `transpeer/node.py` (`_anchor_source_loop`)
- Test: `tests/test_anchor_read.py`

**Interfaces:**
- `class MonerodSource(url, session_factory=aiohttp.ClientSession)`: JSON-RPC at `url + "/json_rpc"`: `async height() -> int` (`get_block_count` → `count - 1`), `async block_blob(height) -> bytes` (`get_block` with `{"height": h}` → `result.blob` hex), `async headers_range(start, end) -> list[dict]` (`get_block_headers_range` → `result.headers`, each with `height`, `difficulty`, `cumulative_difficulty`, `timestamp`, `hash`), `async header_rows(start, end) -> list[HeaderRow]` (block blob per height → `hashing_blob`, difficulty from the range call, and a consistency check that `block_id(hashing_blob)` equals the served `hash`, else `ValueError`).
- Node: under `--anchor-monerod URL`, `_anchor_source_loop` every 120 s: tip from monerod; fetch rows for heights the store lacks from `max(0, checkpoint - 735)` (paged 100 at a time), `verify_headers` on the merged rows (a failing verification logs and drops the new rows), then block blobs for the coverage window; the reader's `sync` then finds a local view and only fetches what is missing.

- [ ] **Step 1: Test** — a fake monerod aiohttp app on 17358 answering the three methods from Task 8's world (`get_block_count`, `get_block`, `get_block_headers_range`); `header_rows(0, 39)` equals the world's rows; a wrong `hash` in the range reply raises `ValueError`.
- [ ] **Step 2–5:** run, implement, run all suites, commit "monerod JSON-RPC source for the anchor store (unverified against a real daemon)".

---

### Task 14: Documentation

**Files:**
- Modify: `README.md` (a "Reading the anchor" subsection after "Publishing through P2Pool": every new flag with its default, the checkpoint format, the sim-only flag, the observer and monerod sources being unverified, and the data written under `data_dir`), `docs/spec-chain-anchored-publication.md` (§17.1: amend the observer paragraph to say `LISTEN_PORT` is not sent and why; add the `next_after` cursor field name to the gossip paragraph; add a "Verification status of slice 3" paragraph listing what only the testnet check can confirm), `docs/manuscript.md` (§13 commit table row for slice 3 with hash `TBD`, filled by the controller at the end), `CLAUDE.md` (add `--anchor-read` to the flags-default-off list), `.claude/HANDOFF.md` is left to the controller.
- Test: none; run every suite once more and record the counts in the README subsection.

- [ ] **Step 1: Write the docs.** **Step 2: Run all suites; paste the counts.** **Step 3: Commit** "docs: reader flags, slice 3 verification status, manuscript commit row".

---

## Self-review

**Spec coverage.** §5 endpoints: Tasks 1 (index cursor), 7 (anchor, venue), 8 (gossip). §6.1 checkpoint and venue ids: Tasks 4, 5, 8. §6.2 headers: Task 4. §6.3 coinbases and tags: Tasks 2, 8. §6.4 leaves: Tasks 5, 8. §6.5 shares, canonical fork, observer protocol: Tasks 5, 8, 12. §6.6 freshness: Task 4 (stale tip) and Task 8 (no view → not bootstrapped). §6.7 fallback to old commitments: **not in this plan**; the reader marks `bootstrapped=False` and keeps syncing, which is the mandatory behaviour; the optional fallback is deferred to slice 4 when the oracle can exercise it. §7 weighting and tags: Tasks 8, 9. §8 coverage and scan-stop: Tasks 8, 10. §9 challenges: Task 11. §17.1 sim PoW: Task 3; monerod: Task 13.

**Placeholders.** Tasks 6, 7, 9–13 give interfaces and test behaviour in prose rather than full code; the implementers are builders working from those interfaces, and each task names its excerpt file. Task 5's proof-by-index helper points at the P2Pool source in the scratchpad rather than reproducing it.

**Type consistency.** `HeaderRow(height, blob, difficulty)` is used identically in Tasks 4, 6, 7, 13. `ParsedShare.id/parent/height/difficulty/timestamp/wallet/aux` feed `weight.Share` in Task 8 through the conversion written there. `AnchorClient` method names in Task 7 are the ones Tasks 8 and 11 call. `TranspeerEntry.published/unfaithful/uptime` are declared in Tasks 8 and 11 and used in Tasks 9–11.
