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

        import random
        from transpeer.anchor.headers import Checkpoint, verify_headers
        from transpeer.anchor.monero import block_id
        cp = Checkpoint(2, block_id(rows[2].blob))
        now = 1_700_000_000 + 120 * 4 + 60
        v = verify_headers(rows, cp, pow, now, rng=random.Random(1))
        store.view = v
        store.save()

        store2 = AnchorStore(path)
        store2.load()
        check(store2.view is not None
              and store2.view.tip_height == v.tip_height
              and store2.view.tip_id == v.tip_id
              and store2.view.work == v.work
              and store2.view.first == v.first,
              "loaded view matches saved view's tip/work/first")
        check(store2.view.timestamps == v.timestamps and store2.view.blobs == v.blobs
              and store2.view.difficulties == v.difficulties and store2.view.cumulative == v.cumulative,
              "loaded view carries all per-block fields")
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


async def test_endpoints_and_client():
    print("anchor/venue endpoints and fetch client")
    import aiohttp
    from aiohttp import web
    from transpeer.config import Config
    from transpeer.peerstore import PeerStore
    from transpeer.server import TranspeerServer
    from transpeer.anchor import CHAIN_ID
    from transpeer.anchor.blob import blob_hash, encode_blob
    from transpeer.anchor.blobdb import BlobDB, Commitment
    from transpeer.anchor.headers import HeaderRow
    from transpeer.anchor.powhash import Sha256Pow
    from transpeer.anchor.share import VENUES, mine_share, parse_share
    from transpeer.anchor.stores import AnchorStore, ShareStore
    from transpeer.anchor.fetch import AnchorClient

    pow = Sha256Pow()
    cfg = Config(in_memory=True, no_verify=True, anchor_chain="monero",
                 port=17350, bind="127.0.0.1")
    store = PeerStore(cfg)
    await store.init()

    anchor_store = AnchorStore(None)
    rows = make_chain(40, pow)
    anchor_store.put_headers(rows)
    anchor_store.put_block(0, rows[0].blob)

    venue = VENUES["mini"]
    blob_h = hashlib.sha256(b"venue-blob").digest()
    kw = dict(consensus_id=venue, txin_gen_height=3000000, prev_id=bytes(32),
              timestamp=1_700_000_000, parent=bytes(32), height=0, difficulty=300,
              cumulative_difficulty=300, aux={CHAIN_ID: (blob_h, 100000)})
    raw1 = mine_share(kw, pow)
    s1 = parse_share(raw1, venue)
    raw2 = mine_share(dict(kw, parent=s1.id, height=1, cumulative_difficulty=600, aux={}), pow)
    s2 = parse_share(raw2, venue)
    share_store = ShareStore(venue, None)
    share_store.add(s1)
    share_store.add(s2)

    db = BlobDB()
    now = 2_000_000_000
    b_db = encode_blob("monero", 5, [("20.0.0.1", 7337)])
    db.add(b_db, Commitment(blob_hash(b_db), "share", "v", "s1", "w", 10, now - 50), now - 40)

    srv = TranspeerServer(cfg, store, "test_anchor_read", time.time(),
                          network_names=["monero"], blobdb=db,
                          anchor_store=anchor_store, share_stores={venue: share_store})
    runner = web.AppRunner(srv.create_app())
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 17350)
    await site.start()

    # Second, unrelated app serving a body whose hash won't match what we ask for.
    async def wrong_body(request):
        return web.Response(body=b"not the blob you are looking for",
                             content_type="application/octet-stream")
    wrong_app = web.Application()
    wrong_app.router.add_get("/blob/{hash}", wrong_body)
    wrong_runner = web.AppRunner(wrong_app)
    await wrong_runner.setup()
    wrong_site = web.TCPSite(wrong_runner, "127.0.0.1", 17351)
    await wrong_site.start()

    client = AnchorClient(cfg)
    try:
        headers = await client.fetch_headers("127.0.0.1", 17350, "monero", 0, 5)
        check(len(headers) == 5 and headers[0].height == 0 and headers[0].blob == rows[0].blob
              and headers[0].difficulty == rows[0].difficulty, "fetch_headers round trip")

        big = await client.fetch_headers("127.0.0.1", 17350, "monero", 0, 5000)
        check(len(big) == 40, "count clamped to available rows (40 of 40)")

        clamp = await client.fetch_headers("127.0.0.1", 17350, "monero", 0, 800)
        check(len(clamp) <= 40, "count=800 against a 40-row chain still returns 40")

        tip = await client.fetch_tip("127.0.0.1", 17350, "monero")
        check(tip == 39, "fetch_tip")

        wrong_chain = await client.fetch_tip("127.0.0.1", 17350, "bitcoin")
        check(wrong_chain is None, "wrong chain name 404s -> None")

        block = await client.fetch_block("127.0.0.1", 17350, "monero", 0)
        check(block == rows[0].blob, "fetch_block round trip")

        missing_block = await client.fetch_block("127.0.0.1", 17350, "monero", 1)
        check(missing_block is None, "missing block -> None")

        share = await client.fetch_share("127.0.0.1", 17350, venue, s1.id)
        check(share == raw1, "fetch_share round trip")

        missing_share = await client.fetch_share("127.0.0.1", 17350, venue, bytes(32))
        check(missing_share is None, "unknown share -> None")

        bad_venue = await client.fetch_share("127.0.0.1", 17350, VENUES["main"], s1.id)
        check(bad_venue is None, "unserved venue -> None")

        shares = await client.fetch_shares("127.0.0.1", 17350, venue, s2.id, 10)
        check(shares == [raw2, raw1], "fetch_shares walks parent chain")

        one = await client.fetch_shares("127.0.0.1", 17350, venue, s2.id, 1)
        check(one == [raw2], "fetch_shares count clamp")

        by_root = await client.fetch_share_by_root("127.0.0.1", 17350, venue, s1.merkle_root)
        check(by_root == raw1, "fetch_share_by_root round trip")

        missing_root = await client.fetch_share_by_root("127.0.0.1", 17350, venue, bytes(32))
        check(missing_root is None, "unknown root -> None")

        blob = await client.fetch_blob("127.0.0.1", 17350, blob_hash(b_db))
        check(blob == b_db, "fetch_blob round trip")

        bad_hash_blob = await client.fetch_blob("127.0.0.1", 17351, blob_hash(b_db))
        check(bad_hash_blob is None, "fetch_blob rejects a body whose hash doesn't match")

        async with aiohttp.ClientSession() as s:
            async with s.get(f"http://127.0.0.1:17350/venue/{venue.hex()}/share/zz") as r:
                check(r.status == 400, "bad share hex 400 (venue is served)")

        idx_rows, next_since, next_after = await client.fetch_index("127.0.0.1", 17350, 0)
        check(len(idx_rows) == 1 and idx_rows[0]["hash"] == blob_hash(b_db).hex(), "fetch_index returns raw dicts")
        check(next_since is None and next_after is None, "fetch_index: no more pages")
    finally:
        await runner.cleanup()
        await wrong_runner.cleanup()

    # Unconfigured server: 404 on anchor/venue routes.
    srv2 = TranspeerServer(cfg, store, "test_anchor_read2", time.time(),
                           network_names=["monero"])
    runner2 = web.AppRunner(srv2.create_app())
    await runner2.setup()
    site2 = web.TCPSite(runner2, "127.0.0.1", 17352)
    await site2.start()
    try:
        async with aiohttp.ClientSession() as s:
            async with s.get("http://127.0.0.1:17352/anchor/monero/headers") as r:
                j = await r.json()
                check(r.status == 404 and j["error"] == "anchor not configured", "no anchor: headers 404")
            async with s.get("http://127.0.0.1:17352/anchor/monero/coinbase/0") as r:
                check(r.status == 404, "no anchor: coinbase 404")
            async with s.get(f"http://127.0.0.1:17352/venue/{venue.hex()}/share/{'00' * 32}") as r:
                check(r.status == 404, "no venue: share 404")
            async with s.get(f"http://127.0.0.1:17352/venue/zz/share/{'00' * 32}") as r:
                check(r.status == 400, "bad venue hex 400")
    finally:
        await runner2.cleanup()

    await store.close()


def build_world(pow):
    """A 40-block anchor chain (checkpoint at height 5) whose blocks 30-39
    carry merge-mining tags, and a 12-share mini-venue chain (shares 0-5
    commit blob A, 6-11 commit blob B) whose share `2 + i` is tagged at
    block `30 + i`. Reused by tasks 10-13."""
    from transpeer.anchor import CHAIN_ID
    from transpeer.anchor.blob import blob_hash as _blob_hash, encode_blob
    from transpeer.anchor.headers import Checkpoint
    from transpeer.anchor.merkle import build_mm_tag
    from transpeer.anchor.monero import build_block_blob, hashing_blob, block_id, check_hash
    from transpeer.anchor.headers import HeaderRow
    from transpeer.anchor.share import VENUES, mine_share, parse_share

    venue = VENUES["mini"]
    blob_a = encode_blob("monero", 1, [("20.1.0.1", 7337)])
    blob_b = encode_blob("monero", 1, [("20.2.0.1", 7337)])
    hash_a = _blob_hash(blob_a)
    hash_b = _blob_hash(blob_b)

    shares = []
    parent = bytes(32)
    for i in range(12):
        h = hash_a if i < 6 else hash_b
        kw = dict(consensus_id=venue, txin_gen_height=30, prev_id=bytes(32),
                  timestamp=1_700_000_000 + 10 * i, parent=parent, height=i,
                  difficulty=300, cumulative_difficulty=300 * (i + 1),
                  aux={CHAIN_ID: (h, 100000)})
        raw = mine_share(kw, pow)
        share = parse_share(raw, venue)
        shares.append(share)
        parent = share.id

    rows = []
    blocks = {}
    prev = bytes(32)
    start_ts = 1_700_000_000
    difficulty = 50
    for height in range(40):
        ts = start_ts + 120 * height
        if 30 <= height <= 39:
            tag_share = shares[2 + (height - 30)]
            tag = build_mm_tag(tag_share.n_aux_chains, tag_share.aux_nonce, tag_share.merkle_root)
            tx_extra = b"\x01" + bytes(32) + tag
        else:
            tx_extra = b"\x01" + bytes(32)

        nonce = 0
        while True:
            block = build_block_blob(16, 16, ts, prev, nonce, height, tx_extra)
            hb = hashing_blob(block)
            if check_hash(pow.hash(hb, height, bytes(32)), difficulty):
                break
            nonce += 1
        rows.append(HeaderRow(height, hb, difficulty))
        blocks[height] = block
        prev = block_id(hb)

    checkpoint = Checkpoint(5, block_id(rows[5].blob))
    return {
        "rows": rows, "blocks": blocks, "shares": shares,
        "blobs": {"A": blob_a, "B": blob_b}, "hash_a": hash_a, "hash_b": hash_b,
        "venue": venue, "checkpoint": checkpoint,
    }


async def test_reader():
    print("reader: sync and gossip")
    from aiohttp import web
    from transpeer.config import Config
    from transpeer.peerstore import PeerStore
    from transpeer.server import TranspeerServer
    from transpeer.anchor import CHAIN_ID
    from transpeer.anchor.blob import blob_hash as _blob_hash, encode_blob
    from transpeer.anchor.blobdb import BlobDB, Commitment
    from transpeer.anchor.fetch import AnchorClient
    from transpeer.anchor.powhash import Sha256Pow
    from transpeer.anchor.reader import Reader
    from transpeer.anchor.share import mine_share, parse_share
    from transpeer.anchor.stores import AnchorStore, ShareStore

    pow = Sha256Pow()
    world = build_world(pow)
    rows, blocks, shares = world["rows"], world["blocks"], world["shares"]
    blob_a, blob_b = world["blobs"]["A"], world["blobs"]["B"]
    hash_a, hash_b = world["hash_a"], world["hash_b"]
    venue = world["venue"]
    checkpoint = world["checkpoint"]
    now = 1_700_000_000 + 120 * 39 + 60

    srv_anchor = AnchorStore(None)
    srv_anchor.put_headers(rows)
    for h, blob in blocks.items():
        srv_anchor.put_block(h, blob)

    srv_shares = ShareStore(venue, None)
    for s in shares:
        srv_shares.add(s)

    srv_db = BlobDB()
    srv_db.add(blob_a, Commitment(hash_a, "template", "v", "", "pub", 0, 0), now - 100)
    srv_db.add(blob_b, Commitment(hash_b, "template", "v", "", "pub", 0, 0), now - 100)

    cfg = Config(in_memory=True, no_verify=True, anchor_chain="monero",
                port=17353, bind="127.0.0.1")
    srv_store = PeerStore(cfg)
    await srv_store.init()

    srv = TranspeerServer(cfg, srv_store, "test_reader_srv", time.time(),
                          network_names=["monero"], blobdb=srv_db,
                          anchor_store=srv_anchor, share_stores={venue: srv_shares})
    runner = web.AppRunner(srv.create_app())
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 17353)
    await site.start()

    r_store = None
    try:
        window_days = (40 - 30) * 120 / 86400
        rcfg = Config(in_memory=True, no_verify=True, anchor_chain="monero",
                      anchor_checkpoint=f"5:{checkpoint.hash.hex()}",
                      anchor_window_days=window_days, port=17390, bind="127.0.0.1")
        r_store = PeerStore(rcfg)
        await r_store.init()
        r_db = BlobDB()
        r_anchor = AnchorStore(None)
        client = AnchorClient(rcfg)
        reader = Reader(rcfg, r_store, r_db, r_anchor, {}, client, pow, clock=lambda: now)

        state = await reader.sync([("127.0.0.1", 17353)])
        check(state.tagged == 10, "10 tagged blocks in the coverage window")
        check(state.resolved == 10, "all 10 tags resolved")
        check(state.bootstrapped, "bootstrapped")
        check(state.venues.get(venue) == shares[11].id, "canonical tip is share 11")
        check(state.weights == {("20.1.0.1", 7337): 1800, ("20.2.0.1", 7337): 1800},
              "weights sum to 300*6 per blob")
        e_a = r_store.get_transpeer("20.1.0.1", 7337)
        e_b = r_store.get_transpeer("20.2.0.1", 7337)
        check(e_a is not None and e_a.published and e_b is not None and e_b.published,
              "both entries published in the store")
        check(r_db.get(hash_a) == blob_a and r_db.get(hash_b) == blob_b, "blobdb holds A and B")
        check(any(c.kind == "share" for c in r_db.commitments(hash_a))
              and any(c.kind == "share" for c in r_db.commitments(hash_b)),
              "share commitments recorded for A and B")

        # gossip: blob C (share commitment, minted on top of share 11) and blob D
        # (template only, never verifiable) both new to the reader.
        blob_c = encode_blob("monero", 1, [("20.3.0.1", 7337)])
        hash_c = _blob_hash(blob_c)
        raw12 = mine_share(dict(
            consensus_id=venue, txin_gen_height=30, prev_id=bytes(32),
            timestamp=1_700_000_000 + 10 * 12, parent=shares[11].id, height=12,
            difficulty=300, cumulative_difficulty=300 * 13,
            aux={CHAIN_ID: (hash_c, 100000)}), pow)
        share12 = parse_share(raw12, venue)
        srv_shares.add(share12)
        srv_db.add(blob_c, Commitment(hash_c, "share", venue.hex(), share12.id.hex(),
                                      share12.wallet, share12.difficulty, share12.timestamp),
                  now - 10)

        blob_d = encode_blob("monero", 1, [("20.4.0.1", 7337)])
        hash_d = _blob_hash(blob_d)
        srv_db.add(blob_d, Commitment(hash_d, "template", "v", "", "pub", 0, 0), now - 10)

        n = await reader.gossip("127.0.0.1", 17353)
        check(n >= 1, "gossip reports new rows stored")
        check(r_db.get(hash_c) == blob_c, "gossip fetched and verified blob C")
        check(any(c.kind == "share" for c in r_db.commitments(hash_c)),
              "C stored with its verified share commitment")
        check(r_db.get(hash_d) is None, "row with a template-only commitment is not stored")
    finally:
        await runner.cleanup()
        await srv_store.close()
        if r_store is not None:
            await r_store.close()


async def test_reader_hostile_headers():
    print("reader: hostile header source cannot hang the paging loop")
    from aiohttp import web
    from transpeer.config import Config
    from transpeer.peerstore import PeerStore
    from transpeer.anchor.blobdb import BlobDB
    from transpeer.anchor.fetch import AnchorClient
    from transpeer.anchor.powhash import Sha256Pow
    from transpeer.anchor.reader import Reader
    from transpeer.anchor.stores import AnchorStore

    async def headers_handler(request):
        # Always the same 720 rows starting at height 0, whatever `from`
        # was, and a tip far past anything ever served.
        rows = [{"height": i, "blob": "00" * 40, "difficulty": 50} for i in range(720)]
        return web.json_response({"chain": "monero", "tip": 5000, "headers": rows})

    app = web.Application()
    app.router.add_get("/anchor/{chain}/headers", headers_handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 17355)
    await site.start()

    cfg = Config(in_memory=True, no_verify=True, anchor_chain="monero",
                anchor_checkpoint=f"5:{'00' * 32}", port=17391, bind="127.0.0.1")
    store = PeerStore(cfg)
    await store.init()
    try:
        client = AnchorClient(cfg)
        reader = Reader(cfg, store, BlobDB(), AnchorStore(None), {}, client, Sha256Pow())
        state = await asyncio.wait_for(reader.sync([("127.0.0.1", 17355)]), timeout=10)
        check(not state.bootstrapped, "hostile header source: sync returns, not bootstrapped")
    finally:
        await runner.cleanup()
        await store.close()


async def test_reader_hostile_fork():
    print("reader: hostile share source cannot extend the fork walk")
    from aiohttp import web
    from transpeer.config import Config
    from transpeer.peerstore import PeerStore
    from transpeer.anchor import CHAIN_ID
    from transpeer.anchor.blob import blob_hash as _blob_hash, encode_blob
    from transpeer.anchor.blobdb import BlobDB
    from transpeer.anchor.fetch import AnchorClient
    from transpeer.anchor.headers import Checkpoint, HeaderRow
    from transpeer.anchor.merkle import build_mm_tag
    from transpeer.anchor.monero import build_block_blob, hashing_blob, block_id, check_hash
    from transpeer.anchor.powhash import Sha256Pow
    from transpeer.anchor.reader import Reader
    from transpeer.anchor.share import VENUES, mine_share, parse_share
    from transpeer.anchor.stores import AnchorStore

    pow = Sha256Pow()
    venue = VENUES["mini"]
    blob = encode_blob("monero", 1, [("20.5.0.1", 7337)])
    h_blob = _blob_hash(blob)
    dangling_parent = hashlib.sha256(b"dangling-parent").digest()

    kw = dict(consensus_id=venue, txin_gen_height=3, prev_id=bytes(32), timestamp=1_700_000_000,
              parent=dangling_parent, height=100, difficulty=300, cumulative_difficulty=30100,
              aux={CHAIN_ID: (h_blob, 100000)})
    tip_share = parse_share(mine_share(kw, pow), venue)

    # 64 individually-valid shares (parse and PoW both check out) a
    # hostile source serves for every /venue/{id}/shares request,
    # regardless of `from`: unrelated to the fork it is supposed to walk.
    junk_shares = []
    jparent = bytes(32)
    for i in range(64):
        jkw = dict(consensus_id=venue, txin_gen_height=3, prev_id=bytes(32),
                  timestamp=1_700_000_000 + i, parent=jparent, height=i,
                  difficulty=300, cumulative_difficulty=300 * (i + 1), aux={})
        jshare = parse_share(mine_share(jkw, pow), venue)
        junk_shares.append(jshare)
        jparent = jshare.id

    # Tiny anchor chain: 3 blocks, checkpoint at the tip, tag at height 2.
    rows, blocks = [], {}
    prev = bytes(32)
    start_ts = 1_700_000_000
    difficulty = 50
    for height in range(3):
        ts = start_ts + 120 * height
        if height == 2:
            tag = build_mm_tag(tip_share.n_aux_chains, tip_share.aux_nonce, tip_share.merkle_root)
            tx_extra = b"\x01" + bytes(32) + tag
        else:
            tx_extra = b"\x01" + bytes(32)
        nonce = 0
        while True:
            block = build_block_blob(16, 16, ts, prev, nonce, height, tx_extra)
            hb = hashing_blob(block)
            if check_hash(pow.hash(hb, height, bytes(32)), difficulty):
                break
            nonce += 1
        rows.append(HeaderRow(height, hb, difficulty))
        blocks[height] = block
        prev = block_id(hb)
    checkpoint = Checkpoint(2, block_id(rows[2].blob))

    async def anchor_headers(request):
        frm = int(request.query.get("from", 0))
        count = int(request.query.get("count", len(rows)))
        page = [r for r in rows if r.height >= frm][:count]
        return web.json_response({
            "chain": "monero", "tip": rows[-1].height,
            "headers": [{"height": r.height, "blob": r.blob.hex(), "difficulty": r.difficulty}
                        for r in page],
        })

    async def anchor_coinbase(request):
        height = int(request.match_info["height"])
        blob = blocks.get(height)
        if blob is None:
            return web.json_response({"error": "unknown"}, status=404)
        return web.Response(body=blob, content_type="application/octet-stream")

    async def venue_share_by_root(request):
        root = bytes.fromhex(request.match_info["root"])
        if root == tip_share.merkle_root:
            return web.Response(body=tip_share.raw, content_type="application/octet-stream")
        return web.json_response({"error": "unknown"}, status=404)

    async def venue_shares_hostile(request):
        return web.json_response({"shares": [s.raw.hex() for s in junk_shares]})

    app = web.Application()
    app.router.add_get("/anchor/{chain}/headers", anchor_headers)
    app.router.add_get("/anchor/{chain}/coinbase/{height}", anchor_coinbase)
    app.router.add_get(f"/venue/{venue.hex()}/share_by_root/{{root}}", venue_share_by_root)
    app.router.add_get(f"/venue/{venue.hex()}/shares", venue_shares_hostile)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 17356)
    await site.start()

    cfg = Config(in_memory=True, no_verify=True, anchor_chain="monero",
                anchor_checkpoint=f"2:{checkpoint.hash.hex()}",
                anchor_venues="mini", anchor_window_days=1.0,
                port=17392, bind="127.0.0.1")
    store = PeerStore(cfg)
    await store.init()
    now = start_ts + 120 * 2 + 60
    try:
        client = AnchorClient(cfg)
        r_db = BlobDB()
        reader = Reader(cfg, store, r_db, AnchorStore(None), {}, client, pow, clock=lambda: now)
        state = await asyncio.wait_for(reader.sync([("127.0.0.1", 17356)]), timeout=10)
        check(state.bootstrapped, "sync terminates and bootstraps despite the hostile fork source")
        check(state.venues.get(venue) == tip_share.id, "canonical tip is the resolved share")
        venue_store = reader.shares[venue]
        window = venue_store.walk(tip_share.id, 2160)
        check(window == [tip_share],
              "canonical window contains only the anchored share, none of the junk")
        check(all(venue_store.get(s.id) is None for s in junk_shares),
              "none of the hostile source's unrelated shares were stored")
    finally:
        await runner.cleanup()
        await store.close()


async def test_store_tags_ranking():
    print("store tags: published vouchers rank first, unfaithful ranked/evicted last")
    from transpeer.config import Config
    from transpeer.peerstore import Peer, PeerStore, TranspeerEntry

    now = int(time.time())
    cfg = Config(in_memory=True, vouchers=True, anchor_read=True,
                 anchor_checkpoint="0:" + "00" * 32, no_verify=True)
    store = PeerStore(cfg)
    await store.init()
    try:
        tp1 = "20.1.0.1"  # will be published
        tp2 = "21.1.0.1"  # not published
        await store.add_transpeer(TranspeerEntry(addr=tp1, port=7337, last_seen=now))
        await store.add_transpeer(TranspeerEntry(addr=tp2, port=7337, last_seen=now))
        await store.set_published(tp1, 7337, True)

        peer1 = Peer(network="monero", addr="20.2.0.1", port=18080, last_seen=now, verified=True)
        peer2 = Peer(network="monero", addr="21.2.0.1", port=18080, last_seen=now, verified=True)
        await store.add_peer(peer1, source_addr=tp1)
        await store.add_peer(peer2, source_addr=tp2)

        peers = store.get_peers("monero", verified_only=False)
        check(peers[0].addr == peer1.addr,
              "published reporter's peer ranks first despite equal voucher counts")

        # Flip which transpeer is published: re-report (the next real report
        # would refresh published_vouchers the same way) and the order flips.
        await store.set_published(tp1, 7337, False)
        await store.set_published(tp2, 7337, True)
        await store.add_peer(peer1, source_addr=tp1)
        await store.add_peer(peer2, source_addr=tp2)
        peers = store.get_peers("monero", verified_only=False)
        check(peers[0].addr == peer2.addr, "flipping published flips the ranking order")

        # Unfaithful: three transpeers in distinct buckets, mark one unfaithful.
        # Fresh store so tp1/tp2's untouched last_queried can't crowd this out.
        store2 = PeerStore(cfg)
        await store2.init()
        tp_a, tp_b, tp_c = "20.3.0.1", "21.3.0.1", "20.4.0.1"
        for addr in (tp_a, tp_b, tp_c):
            await store2.add_transpeer(TranspeerEntry(addr=addr, port=7337, last_seen=now))
        await store2.set_unfaithful(tp_b, 7337, True)

        for addr in (tp_a, tp_b, tp_c):
            store2.mark_queried(addr, 7337, answered=False)
        q = store2.get_transpeers_for_query(3)
        check(len(q) == 3 and q[-1].addr == tp_b, "unfaithful entry ranked last in the query batch")

        victim_key = store2._pick_eviction(incoming_bucket="99.0.0.0/16")
        victim = store2._transpeers.get(victim_key)
        check(victim is not None and victim.unfaithful,
              "_pick_eviction prefers the unfaithful transpeer's bucket")

        # Fallback: the only unfaithful entry's bucket equals incoming_bucket
        # (no "elsewhere" candidate) -> its own bucket is still picked.
        own_bucket = store2._bucket_of(tp_b)
        fallback_key = store2._pick_eviction(incoming_bucket=own_bucket)
        check(fallback_key == store2._transpeers[f"{tp_b}:7337"].key,
              "eviction fallback still picks the sole unfaithful entry when its "
              "bucket equals the incoming bucket")
        await store2.close()
    finally:
        await store.close()


async def test_query_batch_bucketed_anchor_read():
    print("bucketed query batch: unfaithful membership under --anchor-read vs default")
    from transpeer.config import Config
    from transpeer.peerstore import PeerStore, TranspeerEntry

    now = int(time.time())
    # Three transpeers in three distinct /16 buckets, plus a fourth sharing
    # the first's bucket. The first is marked unfaithful.
    t1 = "20.1.0.1"   # bucket A, unfaithful
    t2 = "21.1.0.1"   # bucket B
    t3 = "22.1.0.1"   # bucket C
    t4 = "20.1.0.2"   # bucket A, same as t1

    async def build(cfg):
        store = PeerStore(cfg)
        await store.init()
        for addr in (t1, t2, t3, t4):
            await store.add_transpeer(TranspeerEntry(addr=addr, port=7337, last_seen=now))
        await store.set_unfaithful(t1, 7337, True)
        return store

    cfg_on = Config(in_memory=True, vouchers=True, bucketed=True, anchor_read=True,
                    anchor_checkpoint="0:" + "00" * 32, no_verify=True)
    store_on = await build(cfg_on)
    try:
        q3 = store_on.get_transpeers_for_query(3)
        check(len(q3) == 3 and t1 not in {t.addr for t in q3},
              "anchor_read on: unfaithful entry absent from a batch of 3 "
              "when 3 faithful entries from distinct buckets exist")
        q4 = store_on.get_transpeers_for_query(4)
        check(len(q4) == 4 and q4[-1].addr == t1,
              "anchor_read on: unfaithful entry present and last with limit=4")
    finally:
        await store_on.close()

    cfg_off = Config(in_memory=True, vouchers=True, bucketed=True, anchor_read=False,
                      anchor_checkpoint="0:" + "00" * 32, no_verify=True)
    store_off = await build(cfg_off)
    try:
        q3_off = store_off.get_transpeers_for_query(3)
        addrs_off = {t.addr for t in q3_off}
        check(len(q3_off) == 3 and t1 in addrs_off,
              "anchor_read off: previous membership rule keeps the early-break "
              "round-robin, ignoring the unfaithful flag")
    finally:
        await store_off.close()


async def test_node_wiring_read():
    import aiohttp
    from transpeer.config import Config
    from transpeer.node import Node
    print("node wiring (reader)")
    cfg = Config(in_memory=True, no_verify=True, anchor_read=True, anchor_sim_pow=True,
                 anchor_checkpoint="0:" + "00" * 32, port=17354, scan_rate=4.0,
                 networks=[])
    node = Node(cfg)
    task = asyncio.create_task(node.run())
    try:
        await asyncio.sleep(1.0)
        check(node.reader is not None, "reader built")
        check(node.scanner.current_rate() == 4.0, "cold rate while not bootstrapped")
        async with aiohttp.ClientSession() as s:
            async with s.get("http://127.0.0.1:17354/anchor/monero/headers") as r:
                j = await r.json()
                check(r.status == 200 and j.get("headers") == [] and j.get("tip") is None,
                      "anchor headers endpoint served by the node")
    finally:
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):  # noqa: BLE001
            pass


if __name__ == "__main__":
    test_index_cursor()
    test_monero_hashing()
    test_pow_backends()
    test_headers()
    test_share_codec()
    test_stores()
    asyncio.run(test_endpoints_and_client())
    asyncio.run(test_reader())
    asyncio.run(test_reader_hostile_headers())
    asyncio.run(test_reader_hostile_fork())
    asyncio.run(test_store_tags_ranking())
    asyncio.run(test_query_batch_bucketed_anchor_read())
    asyncio.run(test_node_wiring_read())
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
