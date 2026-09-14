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
    check(v.work == 50 * 29 and v.height_of(cp.hash) == 10,
          "work counts only blocks after the checkpoint")
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


def test_seed_and_work():
    print("randomx seed rule and post-checkpoint work")
    import random
    from transpeer.anchor.headers import (verify_headers, Checkpoint, ChainView, HeaderError,
                                          HeaderRow, best_view, HEADER_LOOKBACK)
    from transpeer.anchor.monero import block_id, seed_height, SEEDHASH_EPOCH_BLOCKS, SEEDHASH_EPOCH_LAG
    from transpeer.anchor.powhash import Sha256Pow

    check((SEEDHASH_EPOCH_BLOCKS, SEEDHASH_EPOCH_LAG) == (2048, 64), "seed epoch constants")
    check([seed_height(h) for h in (0, 2112, 2113, 4160, 4161)] == [0, 0, 2048, 2048, 4096],
          "seed_height vectors from rx_seedheight")
    check(HEADER_LOOKBACK == 2848, "header lookback covers the difficulty window and the seed epoch")

    pow = Sha256Pow()
    rows = make_chain(40, pow)
    cp = Checkpoint(10, block_id(rows[10].blob))
    now = 1_700_000_000 + 120 * 39 + 60

    # A pre-checkpoint row claiming an impossible difficulty fails PoW.
    # Its post-checkpoint difficulties are recomputed so that the chain is
    # internally consistent and only the proof-of-work rule can catch it.
    from transpeer.anchor.monero import next_difficulty, parse_hashing_blob
    diffs = [2 ** 256 - 1 if r.height == 7 else r.difficulty for r in rows]
    ts = [parse_hashing_blob(r.blob).timestamp for r in rows]
    cum, run = [], 0
    for i, r in enumerate(rows):
        if r.height > cp.height:
            diffs[i] = next_difficulty(ts[max(0, i - 735):i], cum[max(0, i - 735):i])
        run += diffs[i]
        cum.append(run)
    bad = [HeaderRow(r.height, r.blob, diffs[i]) for i, r in enumerate(rows)]
    try:
        verify_headers(bad, cp, pow, now, rng=random.Random(1))
        check(False, "inflated pre-checkpoint difficulty rejected")
    except HeaderError as e:
        check("proof-of-work" in str(e) and "7" in str(e),
              "inflated pre-checkpoint difficulty is caught by proof-of-work")

    # The verifier passes the seed hash of the seed height, not zeros.
    seen = []

    class RecordingPow:
        name = "recording"

        def hash(self, blob, height, seed_hash):
            seen.append((height, seed_hash))
            return pow.hash(blob, height, seed_hash)

    verify_headers(rows, cp, RecordingPow(), now, rng=random.Random(1))
    seed0 = block_id(rows[0].blob)
    check(seen and all(sh == seed0 for _h, sh in seen),
          "headers are hashed against the block id at their seed height")

    # Work: inflated pre-checkpoint difficulty buys nothing.
    honest = ChainView(first=0, ids=[bytes([i]) * 32 for i in range(20)],
                       timestamps=[0] * 20, difficulties=[50] * 20,
                       cumulative=[50 * (i + 1) for i in range(20)],
                       blobs=[b""] * 20, checkpoint_height=10)
    liar_diffs = [10 ** 9] * 11 + [50] * 4
    liar_cum, run = [], 0
    for d in liar_diffs:
        run += d
        liar_cum.append(run)
    liar = ChainView(first=0, ids=[bytes([200 + i]) * 32 for i in range(15)],
                     timestamps=[0] * 15, difficulties=liar_diffs,
                     cumulative=liar_cum, blobs=[b""] * 15, checkpoint_height=10)
    check(honest.work == 50 * 9 and liar.work == 50 * 4, "work ignores the pre-checkpoint window")
    check(best_view([liar, honest]) is honest,
          "more post-checkpoint blocks beats inflated pre-checkpoint difficulty")


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
                      anchor_window_days=window_days, port=17362, bind="127.0.0.1")
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


def mine_block(pow, height, ts, prev, difficulty=50, tx_extra=None):
    """One anchor block at `height` on top of `prev`; returns (HeaderRow, blob)."""
    from transpeer.anchor.headers import HeaderRow
    from transpeer.anchor.monero import build_block_blob, hashing_blob, check_hash
    if tx_extra is None:
        tx_extra = b"\x01" + bytes(32)
    nonce = 0
    while True:
        block = build_block_blob(16, 16, ts, prev, nonce, height, tx_extra)
        hb = hashing_blob(block)
        if check_hash(pow.hash(hb, height, bytes(32)), difficulty):
            return HeaderRow(height, hb, difficulty), block
        nonce += 1


async def test_reader_resync():
    print("reader: repeated syncs follow the tip, and a reorg")
    from aiohttp import web
    from transpeer.config import Config
    from transpeer.peerstore import PeerStore
    from transpeer.server import TranspeerServer
    from transpeer.anchor.blobdb import BlobDB, Commitment
    from transpeer.anchor.fetch import AnchorClient
    from transpeer.anchor.monero import block_id
    from transpeer.anchor.powhash import Sha256Pow
    from transpeer.anchor.reader import Reader
    from transpeer.anchor.stores import AnchorStore, ShareStore

    pow = Sha256Pow()
    world = build_world(pow)
    rows, blocks, shares = world["rows"], world["blocks"], world["shares"]
    venue, checkpoint = world["venue"], world["checkpoint"]
    start_ts = 1_700_000_000
    now = start_ts + 120 * 50

    srv_anchor = AnchorStore(None)
    srv_anchor.put_headers(rows)
    for h, blob in blocks.items():
        srv_anchor.put_block(h, blob)
    srv_shares = ShareStore(venue, None)
    for sh in shares:
        srv_shares.add(sh)
    srv_db = BlobDB()
    srv_db.add(world["blobs"]["A"], Commitment(world["hash_a"], "template", "v", "", "p", 0, 0), now)
    srv_db.add(world["blobs"]["B"], Commitment(world["hash_b"], "template", "v", "", "p", 0, 0), now)

    def grow(n, from_height):
        prev = block_id(srv_anchor.headers[from_height - 1].blob)
        for h in range(from_height, from_height + n):
            row, block = mine_block(pow, h, start_ts + 120 * h, prev)
            srv_anchor.put_headers([row])
            srv_anchor.put_block(h, block)
            prev = block_id(row.blob)

    cfg = Config(in_memory=True, no_verify=True, anchor_chain="monero",
                 port=17359, bind="127.0.0.1")
    srv_store = PeerStore(cfg)
    await srv_store.init()
    srv = TranspeerServer(cfg, srv_store, "resync_srv", time.time(), network_names=["monero"],
                          blobdb=srv_db, anchor_store=srv_anchor, share_stores={venue: srv_shares})
    runner = web.AppRunner(srv.create_app())
    await runner.setup()
    await web.TCPSite(runner, "127.0.0.1", 17359).start()

    r_store = None
    try:
        rcfg = Config(in_memory=True, no_verify=True, anchor_chain="monero",
                      anchor_checkpoint=f"5:{checkpoint.hash.hex()}", anchor_venues="mini",
                      anchor_window_days=10 * 120 / 86400, port=17362, bind="127.0.0.1")
        r_store = PeerStore(rcfg)
        await r_store.init()
        r_anchor = AnchorStore(None)
        reader = Reader(rcfg, r_store, BlobDB(), r_anchor, {}, AnchorClient(rcfg), pow,
                        clock=lambda: now)
        tips = []
        boot = []
        for i in range(3):
            if i:
                grow(3, 40 + 3 * (i - 1))
            st = await asyncio.wait_for(reader.sync([("127.0.0.1", 17359)]), timeout=30)
            tips.append(st.tip_height)
            boot.append(st.bootstrapped)
        check(tips == [39, 42, 45], f"tip advances on every sync: {tips}")
        check(all(boot), "bootstrapped stays true across syncs")

        # Reorg: the last two blocks are replaced by three different ones.
        for h in (44, 45):
            del srv_anchor.headers[h]
            del srv_anchor.blocks[h]
        grow(3, 44)
        st = await asyncio.wait_for(reader.sync([("127.0.0.1", 17359)]), timeout=30)
        check(st.tip_height == 46, f"reader follows the longer reorganised chain: {st.tip_height}")
        check(reader.anchor.view.tip_id == block_id(srv_anchor.headers[46].blob),
              "the reader's tip is the serving node's new tip")
        check(st.bootstrapped, "still bootstrapped after the reorg")
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
                anchor_checkpoint=f"5:{'00' * 32}", port=17362, bind="127.0.0.1")
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


async def test_reader_hostile_tip_and_types():
    print("reader: absurd tips and malformed JSON do not stop a good source")
    from aiohttp import web
    from transpeer.config import Config
    from transpeer.peerstore import PeerStore
    from transpeer.server import TranspeerServer
    from transpeer.anchor.blobdb import BlobDB, Commitment
    from transpeer.anchor.fetch import AnchorClient
    from transpeer.anchor.powhash import Sha256Pow
    from transpeer.anchor.reader import Reader
    from transpeer.anchor.stores import AnchorStore, ShareStore

    pow = Sha256Pow()
    world = build_world(pow)
    rows, blocks, shares = world["rows"], world["blocks"], world["shares"]
    venue, checkpoint = world["venue"], world["checkpoint"]
    now = 1_700_000_000 + 120 * 39 + 60

    async def huge_tip(request):
        # Contiguous pages for ever, and a tip no honest chain has.
        frm = int(request.query.get("from", 0))
        count = min(int(request.query.get("count", 720)), 720)
        page = [{"height": frm + i, "blob": rows[0].blob.hex(), "difficulty": 50}
                for i in range(count)]
        return web.json_response({"chain": "monero", "tip": 10 ** 18, "headers": page})

    async def bad_tip(request):
        return web.json_response({"chain": "monero", "tip": "x", "headers": []})

    async def rows_without_difficulty(request):
        frm = int(request.query.get("from", 0))
        count = min(int(request.query.get("count", 720)), 720)
        page = [{"height": r.height, "blob": r.blob.hex()}
                for r in rows if r.height >= frm][:count]
        return web.json_response({"chain": "monero", "tip": 39, "headers": page})

    hostiles = []
    for port, handler in ((17363, huge_tip), (17364, bad_tip), (17365, rows_without_difficulty)):
        app = web.Application()
        app.router.add_get("/anchor/{chain}/headers", handler)
        runner = web.AppRunner(app)
        await runner.setup()
        await web.TCPSite(runner, "127.0.0.1", port).start()
        hostiles.append(runner)

    srv_anchor = AnchorStore(None)
    srv_anchor.put_headers(rows)
    for h, blob in blocks.items():
        srv_anchor.put_block(h, blob)
    srv_shares = ShareStore(venue, None)
    for sh in shares:
        srv_shares.add(sh)
    srv_db = BlobDB()
    srv_db.add(world["blobs"]["A"], Commitment(world["hash_a"], "template", "v", "", "p", 0, 0), now)
    srv_db.add(world["blobs"]["B"], Commitment(world["hash_b"], "template", "v", "", "p", 0, 0), now)
    cfg = Config(in_memory=True, no_verify=True, anchor_chain="monero",
                 port=17366, bind="127.0.0.1")
    srv_store = PeerStore(cfg)
    await srv_store.init()
    srv = TranspeerServer(cfg, srv_store, "types_srv", time.time(), network_names=["monero"],
                          blobdb=srv_db, anchor_store=srv_anchor, share_stores={venue: srv_shares})
    runner = web.AppRunner(srv.create_app())
    await runner.setup()
    await web.TCPSite(runner, "127.0.0.1", 17366).start()

    r_store = None
    try:
        rcfg = Config(in_memory=True, no_verify=True, anchor_chain="monero",
                      anchor_checkpoint=f"5:{checkpoint.hash.hex()}", anchor_venues="mini",
                      anchor_window_days=10 * 120 / 86400, port=17367, bind="127.0.0.1")
        r_store = PeerStore(rcfg)
        await r_store.init()
        reader = Reader(rcfg, r_store, BlobDB(), AnchorStore(None), {}, AnchorClient(rcfg),
                        pow, clock=lambda: now)
        sources = [("127.0.0.1", 17363), ("127.0.0.1", 17364),
                   ("127.0.0.1", 17365), ("127.0.0.1", 17366)]
        state = await asyncio.wait_for(reader.sync(sources), timeout=30)
        check(state.tip_height == 39, f"the good source's view wins: {state.tip_height}")
        check(state.bootstrapped, "sync completes and bootstraps despite three bad sources")
    finally:
        for runner_ in hostiles:
            await runner_.cleanup()
        await runner.cleanup()
        await srv_store.close()
        if r_store is not None:
            await r_store.close()


async def test_reader_withheld_coinbases():
    print("reader: withheld coinbases lower coverage, they do not raise it")
    from aiohttp import web
    from transpeer.config import Config
    from transpeer.peerstore import PeerStore
    from transpeer.server import TranspeerServer
    from transpeer.anchor.blobdb import BlobDB, Commitment
    from transpeer.anchor.fetch import AnchorClient
    from transpeer.anchor.powhash import Sha256Pow
    from transpeer.anchor.reader import Reader
    from transpeer.anchor.stores import AnchorStore, ShareStore

    pow = Sha256Pow()
    world = build_world(pow)
    rows, blocks, shares = world["rows"], world["blocks"], world["shares"]
    venue, checkpoint = world["venue"], world["checkpoint"]
    now = 1_700_000_000 + 120 * 39 + 60

    srv_anchor = AnchorStore(None)
    srv_anchor.put_headers(rows)
    srv_anchor.put_block(39, blocks[39])          # the only coinbase served
    srv_shares = ShareStore(venue, None)
    for sh in shares:
        srv_shares.add(sh)
    srv_db = BlobDB()
    srv_db.add(world["blobs"]["B"], Commitment(world["hash_b"], "template", "v", "", "p", 0, 0), now)

    cfg = Config(in_memory=True, no_verify=True, anchor_chain="monero",
                 port=17368, bind="127.0.0.1")
    srv_store = PeerStore(cfg)
    await srv_store.init()
    srv = TranspeerServer(cfg, srv_store, "withhold_srv", time.time(), network_names=["monero"],
                          blobdb=srv_db, anchor_store=srv_anchor, share_stores={venue: srv_shares})
    runner = web.AppRunner(srv.create_app())
    await runner.setup()
    await web.TCPSite(runner, "127.0.0.1", 17368).start()

    r_store = None
    try:
        rcfg = Config(in_memory=True, no_verify=True, anchor_chain="monero",
                      anchor_checkpoint=f"5:{checkpoint.hash.hex()}", anchor_venues="mini",
                      anchor_window_days=9 * 120 / 86400, port=17362, bind="127.0.0.1")
        r_store = PeerStore(rcfg)
        await r_store.init()
        reader = Reader(rcfg, r_store, BlobDB(), AnchorStore(None), {}, AnchorClient(rcfg),
                        pow, clock=lambda: now)
        state = await asyncio.wait_for(reader.sync([("127.0.0.1", 17368)]), timeout=30)
        check(state.window_blocks == 10 and state.fetched_blocks == 1,
              f"window of 10 blocks, 1 fetched: {state.window_blocks}/{state.fetched_blocks}")
        check(state.tagged == 10 and state.resolved == 1,
              f"unavailable blocks count as tagged and unresolved: {state.tagged}/{state.resolved}")
        check(abs(state.coverage - 0.1) < 1e-9, f"coverage 0.1, not 1.0: {state.coverage}")
        check(not state.bootstrapped, "withholding the window cannot bootstrap the reader")
    finally:
        await runner.cleanup()
        await srv_store.close()
        if r_store is not None:
            await r_store.close()


async def test_reader_discovered_venue():
    print("reader: a venue discovered from /venues is resolved and its weight adds")
    from aiohttp import web
    from transpeer.config import Config
    from transpeer.peerstore import PeerStore
    from transpeer.server import TranspeerServer
    from transpeer.anchor import CHAIN_ID
    from transpeer.anchor.blob import blob_hash as _blob_hash, encode_blob
    from transpeer.anchor.blobdb import BlobDB, Commitment
    from transpeer.anchor.fetch import AnchorClient
    from transpeer.anchor.merkle import build_mm_tag
    from transpeer.anchor.monero import block_id
    from transpeer.anchor.powhash import Sha256Pow
    from transpeer.anchor.reader import Reader
    from transpeer.anchor.share import VENUES, mine_share, parse_share
    from transpeer.anchor.stores import AnchorStore, ShareStore

    pow = Sha256Pow()
    mini, nano = VENUES["mini"], VENUES["nano"]
    blob = encode_blob("monero", 1, [("20.9.0.1", 7337)])
    h_blob = _blob_hash(blob)
    start_ts = 1_700_000_000
    now = start_ts + 120 * 7 + 60

    def one_share(venue):
        kw = dict(consensus_id=venue, txin_gen_height=1, prev_id=bytes(32), timestamp=start_ts,
                  parent=bytes(32), height=0, difficulty=300, cumulative_difficulty=300,
                  aux={CHAIN_ID: (h_blob, 100000)})
        return parse_share(mine_share(kw, pow), venue)

    mini_share, nano_share = one_share(mini), one_share(nano)

    rows, blocks = [], {}
    prev = bytes(32)
    for height in range(8):
        tagger = {6: mini_share, 7: nano_share}.get(height)
        extra = b"\x01" + bytes(32)
        if tagger is not None:
            extra += build_mm_tag(tagger.n_aux_chains, tagger.aux_nonce, tagger.merkle_root)
        row, block = mine_block(pow, height, start_ts + 120 * height, prev, tx_extra=extra)
        rows.append(row)
        blocks[height] = block
        prev = block_id(row.blob)
    checkpoint_hash = block_id(rows[5].blob)

    srv_anchor = AnchorStore(None)
    srv_anchor.put_headers(rows)
    for h, b in blocks.items():
        srv_anchor.put_block(h, b)
    srv_stores = {mini: ShareStore(mini, None), nano: ShareStore(nano, None)}
    srv_stores[mini].add(mini_share)
    srv_stores[nano].add(nano_share)
    srv_db = BlobDB()
    srv_db.add(blob, Commitment(h_blob, "template", "v", "", "p", 0, 0), now)

    cfg = Config(in_memory=True, no_verify=True, anchor_chain="monero",
                 port=17369, bind="127.0.0.1")
    srv_store = PeerStore(cfg)
    await srv_store.init()
    srv = TranspeerServer(cfg, srv_store, "venues_srv", time.time(), network_names=["monero"],
                          blobdb=srv_db, anchor_store=srv_anchor, share_stores=srv_stores)
    runner = web.AppRunner(srv.create_app())
    await runner.setup()
    await web.TCPSite(runner, "127.0.0.1", 17369).start()

    r_store = None
    try:
        import aiohttp
        async with aiohttp.ClientSession() as sess:
            async with sess.get("http://127.0.0.1:17369/venues") as resp:
                served = set((await resp.json())["venues"])
        check(served == {mini.hex(), nano.hex()}, "/venues lists the venues the node serves")

        rcfg = Config(in_memory=True, no_verify=True, anchor_chain="monero",
                      anchor_checkpoint=f"5:{checkpoint_hash.hex()}", anchor_venues="mini",
                      anchor_window_days=1.0, port=17362, bind="127.0.0.1")
        r_store = PeerStore(rcfg)
        await r_store.init()
        reader = Reader(rcfg, r_store, BlobDB(), AnchorStore(None), {}, AnchorClient(rcfg),
                        pow, clock=lambda: now)
        state = await asyncio.wait_for(reader.sync([("127.0.0.1", 17369)]), timeout=30)
        check(nano in reader.shares and reader.shares[nano].get(nano_share.id) is not None,
              "the unconfigured venue's share is resolved and stored")
        check(state.venues.get(nano) == nano_share.id, "the discovered venue has a canonical tip")
        check(state.weights == {("20.9.0.1", 7337): 600},
              f"weights are venue-additive across the discovered venue: {state.weights}")
        check(state.resolved == 2, f"both tags resolved: {state.resolved}")
    finally:
        await runner.cleanup()
        await srv_store.close()
        if r_store is not None:
            await r_store.close()


async def test_reader_fetch_budget():
    print("reader: per-sync block-fetch budget, continued next sync")
    from aiohttp import web
    from transpeer.config import Config
    from transpeer.peerstore import PeerStore
    from transpeer.server import TranspeerServer
    from transpeer.anchor import reader as reader_mod
    from transpeer.anchor.blobdb import BlobDB, Commitment
    from transpeer.anchor.fetch import AnchorClient
    from transpeer.anchor.powhash import Sha256Pow
    from transpeer.anchor.reader import Reader
    from transpeer.anchor.stores import AnchorStore, ShareStore

    pow = Sha256Pow()
    world = build_world(pow)
    rows, blocks, shares = world["rows"], world["blocks"], world["shares"]
    venue, checkpoint = world["venue"], world["checkpoint"]
    now = 1_700_000_000 + 120 * 39 + 60

    srv_anchor = AnchorStore(None)
    srv_anchor.put_headers(rows)
    for h, b in blocks.items():
        srv_anchor.put_block(h, b)
    srv_shares = ShareStore(venue, None)
    for sh in shares:
        srv_shares.add(sh)
    srv_db = BlobDB()
    srv_db.add(world["blobs"]["B"], Commitment(world["hash_b"], "template", "v", "", "p", 0, 0), now)

    cfg = Config(in_memory=True, no_verify=True, anchor_chain="monero",
                 port=17368, bind="127.0.0.1")
    srv_store = PeerStore(cfg)
    await srv_store.init()
    srv = TranspeerServer(cfg, srv_store, "budget_srv", time.time(), network_names=["monero"],
                          blobdb=srv_db, anchor_store=srv_anchor, share_stores={venue: srv_shares})
    runner = web.AppRunner(srv.create_app())
    await runner.setup()
    await web.TCPSite(runner, "127.0.0.1", 17368).start()

    r_store = None
    saved = reader_mod.MAX_BLOCK_FETCHES
    reader_mod.MAX_BLOCK_FETCHES = 4
    try:
        rcfg = Config(in_memory=True, no_verify=True, anchor_chain="monero",
                      anchor_checkpoint=f"5:{checkpoint.hash.hex()}", anchor_venues="mini",
                      anchor_window_days=9 * 120 / 86400, port=17362, bind="127.0.0.1")
        r_store = PeerStore(rcfg)
        await r_store.init()
        reader = Reader(rcfg, r_store, BlobDB(), AnchorStore(None), {}, AnchorClient(rcfg),
                        pow, clock=lambda: now)
        got = []
        for _ in range(3):
            st = await asyncio.wait_for(reader.sync([("127.0.0.1", 17368)]), timeout=30)
            got.append(st.fetched_blocks)
        check(got == [4, 8, 10], f"the budget paces the window over syncs: {got}")
        check(reader.state.bootstrapped, "the third sync has the whole window and bootstraps")
    finally:
        reader_mod.MAX_BLOCK_FETCHES = saved
        await runner.cleanup()
        await srv_store.close()
        if r_store is not None:
            await r_store.close()


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
                port=17362, bind="127.0.0.1")
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


async def test_reader_cached_block_recheck():
    print("reader: a cached block blob is re-checked against the view before use")
    from aiohttp import web
    from transpeer.config import Config
    from transpeer.peerstore import PeerStore
    from transpeer.server import TranspeerServer
    from transpeer.anchor import CHAIN_ID
    from transpeer.anchor.blob import blob_hash as _blob_hash, encode_blob
    from transpeer.anchor.blobdb import BlobDB, Commitment
    from transpeer.anchor.fetch import AnchorClient
    from transpeer.anchor.merkle import aux_slot, build_mm_tag, merkle_proof, merkle_tree
    from transpeer.anchor.monero import block_id
    from transpeer.anchor.powhash import Sha256Pow
    from transpeer.anchor.reader import Reader
    from transpeer.anchor.share import VENUES, mine_share, parse_share
    from transpeer.anchor.stores import AnchorStore

    pow = Sha256Pow()
    venue = VENUES["mini"]
    blob = encode_blob("monero", 1, [("20.8.0.1", 7337)])
    h_blob = _blob_hash(blob)
    start_ts = 1_700_000_000
    now = start_ts + 120 * 7 + 60

    kw = dict(consensus_id=venue, txin_gen_height=1, prev_id=bytes(32), timestamp=start_ts,
              parent=bytes(32), height=0, difficulty=300, cumulative_difficulty=300,
              aux={CHAIN_ID: (h_blob, 100000)})
    share = parse_share(mine_share(kw, pow), venue)

    # The block commitment's proof: the blob hash at its aux slot in the
    # share's own Merkle tree, which the tag's root commits to.
    leaves = [b""] * share.n_aux_chains
    leaves[aux_slot(venue, share.aux_nonce, share.n_aux_chains)] = share.id
    leaves[aux_slot(CHAIN_ID, share.aux_nonce, share.n_aux_chains)] = h_blob
    proof, path = merkle_proof(merkle_tree(leaves), h_blob)

    rows, blocks = [], {}
    prev = bytes(32)
    for height in range(8):
        extra = b"\x01" + bytes(32)
        if height == 7:
            extra += build_mm_tag(share.n_aux_chains, share.aux_nonce, share.merkle_root)
        row, block = mine_block(pow, height, start_ts + 120 * height, prev, tx_extra=extra)
        rows.append(row)
        blocks[height] = block
        prev = block_id(row.blob)

    srv_anchor = AnchorStore(None)
    srv_anchor.put_headers(rows)
    for h, b in blocks.items():
        srv_anchor.put_block(h, b)
    srv_db = BlobDB()
    # Only the block commitment: the share is not served, so the reader
    # can only learn this blob through gossip.
    srv_db.add(blob, Commitment(h_blob, "block", "", f"7:{block_id(rows[7].blob).hex()}",
                                "pub", 50, start_ts, tuple(proof), path), now - 10)

    cfg = Config(in_memory=True, no_verify=True, anchor_chain="monero",
                 port=17368, bind="127.0.0.1")
    srv_store = PeerStore(cfg)
    await srv_store.init()
    srv = TranspeerServer(cfg, srv_store, "recheck_srv", time.time(), network_names=["monero"],
                          blobdb=srv_db, anchor_store=srv_anchor, share_stores={})
    runner = web.AppRunner(srv.create_app())
    await runner.setup()
    await web.TCPSite(runner, "127.0.0.1", 17368).start()

    r_store = None
    try:
        rcfg = Config(in_memory=True, no_verify=True, anchor_chain="monero",
                      anchor_checkpoint=f"5:{block_id(rows[5].blob).hex()}", anchor_venues="mini",
                      anchor_window_days=1.0, port=17362, bind="127.0.0.1")
        r_store = PeerStore(rcfg)
        await r_store.init()
        r_db = BlobDB()
        reader = Reader(rcfg, r_store, r_db, AnchorStore(None), {}, AnchorClient(rcfg),
                        pow, clock=lambda: now)
        await asyncio.wait_for(reader.sync([("127.0.0.1", 17368)]), timeout=30)
        check(reader.anchor.block(7) == blocks[7], "sync cached the real block 7")

        # Poison the cache with a valid block from another height.
        reader.anchor.put_block(7, blocks[6])
        stored = await asyncio.wait_for(reader.gossip("127.0.0.1", 17368), timeout=30)
        check(stored == 1 and r_db.get(h_blob) == blob,
              "the poisoned cache is refetched, so the block commitment still verifies")
        check(reader.anchor.block(7) == blocks[7], "the cache holds the real block again")
    finally:
        await runner.cleanup()
        await srv_store.close()
        if r_store is not None:
            await r_store.close()


async def test_p2p_request_block_timeout():
    print("p2p: a timed-out block request leaves no pending future")
    from transpeer.anchor.p2p import P2PoolClient
    from transpeer.anchor.share import VENUES

    class _DeadWriter:
        def __init__(self):
            self.closed = False

        def write(self, data):
            pass

        async def drain(self):
            pass

        def close(self):
            self.closed = True

    client = P2PoolClient("127.0.0.1", 17350, VENUES["mini"], timeout=0.05)
    writer = _DeadWriter()
    client._writer = writer
    try:
        await client.request_block(bytes(32))
        check(False, "a block request with no answer times out")
    except asyncio.TimeoutError:
        check(True, "a block request with no answer times out")
    check(client._block_pending == [], "the timed-out future is dropped, so replies cannot drift")
    check(writer.closed, "the connection is closed after a timed-out request")


def test_transpeer_entry_wire():
    print("wire: local tags stay local")
    from transpeer.peerstore import TranspeerEntry
    d = TranspeerEntry("20.0.0.9", 7337, published=True, unfaithful=True).to_dict()
    check("published" not in d and "unfaithful" not in d,
          "published and unfaithful are not sent on the wire")
    check(d["addr"] == "20.0.0.9" and d["port"] == 7337, "the wire fields are unchanged")


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
                 anchor_checkpoint="0:" + "00" * 32, port=17354, scan_rate=0.0,
                 networks=[])
    node = Node(cfg)
    task = asyncio.create_task(node.run())
    try:
        await asyncio.sleep(1.0)
        check(node.reader is not None, "reader built")
        check(node.scanner._idle_fn is not None and node.scanner._idle_fn() is False,
              "scanner idle rule is the reader's bootstrapped state (False before sync)")
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


async def test_challenges():
    print("faithfulness challenges (spec §9)")
    from aiohttp import web
    from transpeer.config import Config
    from transpeer.peerstore import PeerStore, TranspeerEntry
    from transpeer.server import TranspeerServer
    from transpeer.anchor.blob import blob_hash
    from transpeer.anchor.fetch import AnchorClient
    from transpeer.anchor.challenge import Challenger

    def make_commit(h):
        return Commitment(h, "share", "v", "r", "pub", 10, 1_700_000_000)

    blob_a = encode_blob("monero", 100, [("20.0.0.1", 7337)])
    blob_b = encode_blob("monero", 101, [("20.0.0.2", 7337)])
    hash_a, hash_b = blob_hash(blob_a), blob_hash(blob_b)

    good_db = BlobDB()
    good_db.add(blob_a, make_commit(hash_a), now=1_700_000_000)
    good_db.add(blob_b, make_commit(hash_b), now=1_700_000_000)
    empty_db = BlobDB()

    cfg = Config(in_memory=True, no_verify=True)
    store = PeerStore(cfg)
    await store.init()
    await store.add_transpeer(TranspeerEntry("127.0.0.1", 17355, alive=True, uptime=1000))
    await store.add_transpeer(TranspeerEntry("127.0.0.1", 17356, alive=True, uptime=1000))

    good_srv = TranspeerServer(cfg, store, "good", time.time(),
                               network_names=["monero"], blobdb=good_db)
    good_runner = web.AppRunner(good_srv.create_app())
    await good_runner.setup()
    await web.TCPSite(good_runner, "127.0.0.1", 17355).start()

    bad_srv = TranspeerServer(cfg, store, "bad", time.time(),
                              network_names=["monero"], blobdb=empty_db)
    bad_runner = web.AppRunner(bad_srv.create_app())
    await bad_runner.setup()
    await web.TCPSite(bad_runner, "127.0.0.1", 17356).start()

    class ReaderStub:
        def __init__(self, hashes):
            self.hashes = hashes

        def verified_hashes(self, min_age):
            return list(self.hashes)

    reader = ReaderStub([hash_a, hash_b])
    client = AnchorClient(cfg)
    clock_box = [3600.0]
    challenger = Challenger(store, reader, client, clock=lambda: clock_box[0])

    try:
        for _ in range(3):
            await challenger.round()
            clock_box[0] += 3600

        good = store.get_transpeer("127.0.0.1", 17355)
        bad = store.get_transpeer("127.0.0.1", 17356)
        check(bad.unfaithful is True, "404 node marked unfaithful after repeat failures")
        check(good.unfaithful is False, "good node stays faithful")
        check(challenger.lost == set(), "no lost hashes yet")

        # A third hash nobody serves: both fail it -> lost, no new mark
        hash_c = hashlib.sha256(b"nobody-has-this").digest()
        reader.hashes = [hash_a, hash_b, hash_c]
        await challenger.round()
        clock_box[0] += 3600
        check(hash_c in challenger.lost, "hash failed by every challenged transpeer is lost")
        good = store.get_transpeer("127.0.0.1", 17355)
        check(good.unfaithful is False,
              "lost hash's failure counts against nobody: good node still faithful")

        # Advance 24h with the bad node now serving everything it used to 404 on.
        empty_db.add(blob_a, make_commit(hash_a), now=1_700_000_000)
        empty_db.add(blob_b, make_commit(hash_b), now=1_700_000_000)
        clock_box[0] += 86400
        await challenger.round()
        bad = store.get_transpeer("127.0.0.1", 17356)
        check(bad.unfaithful is False,
              "24h without a failure clears the unfaithful mark")
    finally:
        await good_runner.cleanup()
        await bad_runner.cleanup()
        await store.close()


async def test_p2p_observer():
    # The handshake proof-of-work is a random search that can take tens of
    # seconds in pure Python on a loaded box; the clients here get a long
    # timeout so the check is of the protocol, not of the search's luck.
    from transpeer.anchor.powhash import Sha256Pow
    from transpeer.anchor.share import VENUES, mine_share, parse_share
    from transpeer.anchor.p2p import P2PoolClient
    from sim.p2pool_double import P2PoolDouble

    print("p2p observer client and double")
    pow = Sha256Pow()
    venue = VENUES["mini"]
    kw = dict(consensus_id=venue, txin_gen_height=3000000, prev_id=bytes(32),
              timestamp=1_700_000_000, parent=bytes(32), height=0, difficulty=1,
              cumulative_difficulty=1, aux={})
    parent_raw = mine_share(kw, pow)
    parent = parse_share(parent_raw, venue)
    child_raw = mine_share(dict(kw, parent=parent.id, height=1, cumulative_difficulty=2), pow)
    child = parse_share(child_raw, venue)

    shares = {parent.id: parent_raw, child.id: child_raw}
    configured_peers = [("203.0.113.5", 37889), ("198.51.100.9", 37889)]
    double = P2PoolDouble(venue, shares, child.id, configured_peers)
    await double.start(17357)
    try:
        client = P2PoolClient("127.0.0.1", 17357, venue, timeout=120)
        await client.connect()
        try:
            tip_raw = await client.request_block(bytes(32))
            check(tip_raw == child_raw, "request_block(zero) returns the tip's raw bytes")

            unknown = await client.request_block(hashlib.sha256(b"nope").digest())
            check(unknown is None, "request_block(unknown) returns None")

            peers = await client.request_peers()
            check(set(peers) == set(configured_peers),
                  "request_peers returns the configured peers without the pseudo-peer")

            received = []
            client.on_share = lambda raw: received.append(raw)
            await double.broadcast(parent_raw)
            for _ in range(50):
                if received:
                    break
                await asyncio.sleep(0.05)
            check(received == [parent_raw], "a broadcast from the double reaches on_share")
        finally:
            await client.close()

        wrong_client = P2PoolClient("127.0.0.1", 17357, VENUES["main"], timeout=120)
        try:
            await wrong_client.connect()
            check(False, "wrong-consensus client should not complete the handshake")
        except ConnectionError:
            check(True, "double rejects a client with a different consensus id")
        finally:
            await wrong_client.close()
    finally:
        await double.stop()


async def test_p2p_peer_list_edge_cases():
    from transpeer.anchor.share import VENUES
    from transpeer.anchor.p2p import P2PoolClient
    from sim.p2pool_double import P2PoolDouble

    print("p2p peer list: pseudo-peer slot 0 and P2Pool's IPv4 filter")
    venue = VENUES["mini"]

    # 16 real peers: the pseudo-peer must take slot 0 (dropping one real
    # peer) on the first response, not be appended past the 16-peer cap.
    sixteen_peers = [(f"203.0.113.{i}", 37889) for i in range(1, 17)]
    double = P2PoolDouble(venue, {}, bytes(32), sixteen_peers)
    await double.start(17360)
    try:
        client = P2PoolClient("127.0.0.1", 17360, venue, timeout=120)
        await client.connect()
        try:
            first = await client.request_peers()
            check(len(first) == 15,
                  "first PEER_LIST_RESPONSE: pseudo-peer takes slot 0, 15 real peers follow")
            check(set(first) <= set(sixteen_peers), "connection survives; peers are from the configured list")

            second = await client.request_peers()
            check(len(second) == 16 and set(second) == set(sixteen_peers),
                  "second PEER_LIST_RESPONSE (no pseudo-peer): all 16 real peers")
        finally:
            await client.close()
    finally:
        await double.stop()

    # P2Pool's on_peer_list_response filter: first octet 0, 127 or >= 224
    # is dropped (224.0.0.0/3 is multicast/reserved), not only 0.0.0.0/loopback.
    filtered_peers = [("203.0.113.9", 37889), ("224.0.0.1", 37889)]
    double2 = P2PoolDouble(venue, {}, bytes(32), filtered_peers)
    await double2.start(17361)
    try:
        client2 = P2PoolClient("127.0.0.1", 17361, venue, timeout=120)
        await client2.connect()
        try:
            peers = await client2.request_peers()
            check(("224.0.0.1", 37889) not in peers and ("203.0.113.9", 37889) in peers,
                  "a 224.0.0.0/3 peer is filtered out, not just 0.0.0.0/loopback")
        finally:
            await client2.close()
    finally:
        await double2.stop()


async def test_monerod_source():
    print("monerod source")
    from aiohttp import web
    from transpeer.anchor.monero import block_id
    from transpeer.anchor.monerod import MonerodSource
    from transpeer.anchor.powhash import Sha256Pow

    pow = Sha256Pow()
    world = build_world(pow)
    rows, blocks = world["rows"], world["blocks"]
    state = {"bad_height": None}

    async def handle(request):
        req = await request.json()
        method = req.get("method")
        params = req.get("params") or {}
        rid = req.get("id", "0")
        if method == "get_block_count":
            result = {"count": len(rows)}
        elif method == "get_block":
            h = int(params["height"])
            result = {"blob": blocks[h].hex(),
                      "block_header": {"hash": block_id(rows[h].blob).hex()}}
        elif method == "get_block_headers_range":
            start = int(params["start_height"])
            end = int(params["end_height"])
            headers = []
            for h in range(start, end + 1):
                row = rows[h]
                hash_hex = block_id(row.blob).hex()
                if h == state["bad_height"]:
                    hash_hex = "00" * 32
                headers.append({
                    "height": h,
                    "difficulty": row.difficulty,
                    "wide_difficulty": hex(row.difficulty),
                    "cumulative_difficulty": row.difficulty * (h + 1),
                    "timestamp": 1_700_000_000 + 120 * h,
                    "hash": hash_hex,
                    "prev_hash": block_id(rows[h - 1].blob).hex() if h > 0 else bytes(32).hex(),
                })
            result = {"headers": headers}
        else:
            return web.json_response({"jsonrpc": "2.0", "id": rid,
                                      "error": {"code": -32601, "message": "method not found"}})
        return web.json_response({"jsonrpc": "2.0", "id": rid, "result": result})

    app = web.Application()
    app.router.add_post("/json_rpc", handle)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 17358)
    await site.start()
    try:
        source = MonerodSource("http://127.0.0.1:17358")
        h = await source.height()
        check(h == 39, "height is tip = count - 1")
        got = await source.header_rows(0, 39)
        check(got == rows, "header_rows(0,39) equals the world's rows")

        state["bad_height"] = 10
        raised = False
        try:
            await source.header_rows(0, 39)
        except ValueError:
            raised = True
        check(raised, "a wrong hash in the range reply raises ValueError")
    finally:
        await runner.cleanup()


if __name__ == "__main__":
    test_index_cursor()
    test_monero_hashing()
    test_pow_backends()
    test_headers()
    test_seed_and_work()
    test_share_codec()
    test_stores()
    asyncio.run(test_endpoints_and_client())
    asyncio.run(test_reader())
    asyncio.run(test_reader_resync())
    asyncio.run(test_reader_hostile_headers())
    asyncio.run(test_reader_hostile_tip_and_types())
    asyncio.run(test_reader_withheld_coinbases())
    asyncio.run(test_reader_discovered_venue())
    asyncio.run(test_reader_fetch_budget())
    asyncio.run(test_reader_hostile_fork())
    asyncio.run(test_reader_cached_block_recheck())
    asyncio.run(test_p2p_request_block_timeout())
    test_transpeer_entry_wire()
    asyncio.run(test_store_tags_ranking())
    asyncio.run(test_query_batch_bucketed_anchor_read())
    asyncio.run(test_node_wiring_read())
    asyncio.run(test_challenges())
    asyncio.run(test_p2p_observer())
    asyncio.run(test_p2p_peer_list_edge_cases())
    asyncio.run(test_monerod_source())
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
