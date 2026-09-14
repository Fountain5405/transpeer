#!/usr/bin/env python3
"""Checks for the reader side of chain-anchored publication (slice 3).

Run:  PYTHONPATH=$PWD .venv/bin/python tests/test_anchor_read.py
"""

import asyncio
import hashlib
import sys
import tempfile
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


def test_share_codec():
    print("share codec")
    from transpeer.anchor import CHAIN_ID
    from transpeer.anchor.share import (build_share, parse_share, verify_share_pow, mine_share, ShareError,
                                        transpeer_aux, VENUES, MAX_BLOCK_SIZE, MAX_OUTPUT_VALUE)
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
    # 300 outputs at MAX_OUTPUT_VALUE each sum past 2**64: P2Pool's uint64 total_reward
    # wraps and rejects this; parse_share must reject it too, not silently accept it.
    raw3 = build_share(**dict(kw, outputs=[(MAX_OUTPUT_VALUE, bytes(32), 0)] * 300))
    try:
        parse_share(raw3, venue); check(False, "uint64 reward overflow rejected")
    except ShareError:
        check(True, "uint64 reward overflow rejected")


def test_stores():
    print("anchor and share stores")
    from transpeer.anchor import CHAIN_ID
    from transpeer.anchor.headers import HeaderRow
    from transpeer.anchor.share import VENUES, parse_share, mine_share
    from transpeer.anchor.powhash import Sha256Pow
    from transpeer.anchor.stores import AnchorStore, ShareStore, venue_dir
    pow = Sha256Pow()

    # AnchorStore: header round trip through disk
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "anchor.json"
        store = AnchorStore(path)
        rows = make_chain(5, pow)
        store.put_headers(rows)
        for r in rows:
            store.put_block(r.height, r.blob)
        check(store.tip_height() == 4, "tip_height is the highest header")
        store.save()

        store2 = AnchorStore(path)
        store2.load()
        got = store2.header_rows(2, 10)
        check(len(got) == 3, "header_rows returns the contiguous tail from height 2")
        check(got[0].height == 2 and got[-1].height == 4, "header_rows heights")
        check(store2.block(2) == rows[2].blob, "block blob round trips")
        check(store2.block(99) is None, "missing block is None")

        store2.prune(3)
        check(store2.tip_height() == 4 and store2.header_rows(3, 10)[0].height == 3
              and store2.header_rows(0, 10) == [],
              "prune drops headers below keep_from_height")

        missing = AnchorStore(Path(tmp) / "nope.json")
        missing.load()
        check(missing.tip_height() is None and missing.view is None,
              "missing/unparsable file loads empty")

    # in-memory only: save/load are no-ops
    mem = AnchorStore(None)
    mem.put_headers(rows)
    mem.save()
    mem.load()
    check(mem.tip_height() == 4, "path=None store keeps state without touching disk")

    # ShareStore: build two chained shares
    venue = VENUES["mini"]
    blob_hash = hashlib.sha256(b"blob").digest()
    kw = dict(consensus_id=venue, txin_gen_height=3000000, prev_id=bytes(32), timestamp=1_700_000_000,
              parent=bytes(32), height=0, difficulty=300, cumulative_difficulty=300,
              aux={CHAIN_ID: (blob_hash, 100000)})
    raw1 = mine_share(kw, pow)
    s1 = parse_share(raw1, venue)
    raw2 = mine_share(dict(kw, parent=s1.id, height=1, cumulative_difficulty=600, aux={}), pow)
    s2 = parse_share(raw2, venue)

    with tempfile.TemporaryDirectory() as tmp:
        data_dir = Path(tmp)
        vdir = venue_dir(data_dir, venue)
        check(vdir == data_dir / "venues" / venue.hex(), "venue_dir layout")
        store = ShareStore(venue, vdir)
        check(store.add(s1) is True, "add returns True for a new share")
        check(store.add(s1) is False, "add returns False when already present")
        check(store.add(s2) is True, "add second share")
        check(store.get(s1.id) == s1, "get by id")
        check(store.raw(s1.id) == raw1, "raw returns the original bytes")
        check(store.by_root(s1.merkle_root) == s1, "by_root looks up by merkle root")
        check(store.tip() == s2, "tip is the highest cumulative difficulty")
        walked = store.walk(s2.id, 10)
        check(walked == [s2, s1], "walk follows parent to parent, stopping at unknown parent")
        check(store.walk(s2.id, 1) == [s2], "walk stops at count")
        check(store.count() == 2, "count")

        reloaded = ShareStore(venue, vdir)
        reloaded.load()
        check(reloaded.count() == 2, "load rebuilds the index from disk")
        check(reloaded.get(s1.id) == s1 and reloaded.get(s2.id) == s2, "reloaded shares parse identically")

        # tamper with one file on disk: load must drop it, not raise
        bad_path = vdir / s1.id.hex()
        data = bytearray(bad_path.read_bytes())
        data[-1] ^= 1
        bad_path.write_bytes(bytes(data))
        reloaded2 = ShareStore(venue, vdir)
        reloaded2.load()
        check(reloaded2.count() == 1 and reloaded2.get(s1.id) is None,
              "tampered file fails to parse and is deleted at load")
        check(not bad_path.exists(), "tampered file removed from disk")

        # prune removes shares below the window
        old = ShareStore(venue, None)
        old.add(s1); old.add(s2)
        old.prune(tip_height=10000, window=1)
        check(old.count() == 0, "prune drops shares below tip_height - 4*window")


if __name__ == "__main__":
    test_index_cursor()
    test_monero_hashing()
    test_pow_backends()
    test_headers()
    test_share_codec()
    test_stores()
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
