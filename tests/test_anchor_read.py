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
    blobs = [encode_blob("monero", 100 + i, [("20.0.0.1", 7337 + i)]) for i in range(3)]
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
    check(check_hash(bytes(32), 1) and check_hash(b"\xff" * 32, 2) is False, "check_hash edges")
    lim = ((1 << 256) + 999) // 1000
    check(check_hash((lim - 1).to_bytes(32, "little"), 1000) and not check_hash(lim.to_bytes(32, "little"), 1000),
          "check_hash boundary at difficulty 1000")
    ts = [120 * i for i in range(735)]
    cum = [1000 * (i + 1) for i in range(735)]
    check(next_difficulty(ts, cum) == 1000, "constant 120 s spacing keeps difficulty")
    check(next_difficulty(ts[:1], cum[:1]) == 1, "single block gives 1")
    check(next_difficulty([240 * i for i in range(735)], cum) == 500, "double spacing halves difficulty")
    check(next_difficulty([120 * i for i in range(100)], [1000 * (i + 1) for i in range(100)]) == 1000,
          "short window (no cut) still works")


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
    fake = rows[:30] + make_chain(1, pow, first=30, prev=bytes(32), start_ts=1_700_000_000 + 120 * 30)
    try:
        verify_headers(fake, cp, pow, now); check(False, "broken linkage rejected")
    except HeaderError:
        check(True, "broken linkage rejected")
    longer = make_chain(45, pow)
    v2 = verify_headers(longer, Checkpoint(10, block_id(longer[10].blob)), pow, now + 600, rng=random.Random(1))
    check(best_view([v, v2]) is v2, "best_view picks the most work")


if __name__ == "__main__":
    test_index_cursor()
    test_monero_hashing()
    test_pow_backends()
    test_headers()
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
