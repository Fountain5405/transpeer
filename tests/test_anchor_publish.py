#!/usr/bin/env python3
"""Checks for the publisher side of chain-anchored publication:
curation, period rotation, the aux-chain JSON-RPC server driven by a
P2Pool-style poller, and the blob endpoints. Loopback only, no PoW.

Run:  PYTHONPATH=$PWD .venv/bin/python tests/test_anchor_publish.py
"""

import asyncio
import hashlib
import sys
import tempfile
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
    await store.add_transpeer(TranspeerEntry("5.5.5.5", 7337, ["monero"], last_seen=t0))
    e = store.get_transpeer("5.5.5.5", 7337)
    check(e is not None and e.first_seen == t0, "first_seen set on first add")
    await store.add_transpeer(TranspeerEntry("5.5.5.5", 7337, ["monero"], last_seen=t0 + 100))
    e = store.get_transpeer("5.5.5.5", 7337)
    check(e.first_seen == t0 and e.last_seen == t0 + 100, "first_seen kept on re-add")
    await store.close()

    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = Config(data_dir=Path(tmpdir), no_verify=True)
        store1 = PeerStore(cfg)
        await store1.init()
        await store1.add_transpeer(TranspeerEntry("6.6.6.6", 7337, ["monero"], last_seen=t0))
        await store1.close()
        store2 = PeerStore(cfg)
        await store2.init()
        e2 = store2.get_transpeer("6.6.6.6", 7337)
        check(e2 is not None and e2.first_seen == t0, "first_seen survives a store restart")
        await store2.close()


async def _add(store, addr, port=7337, first_seen=0, answered=1, alive=True, native=None):
    """Insert a transpeer and set the fields curation reads. Patching the
    stored entry after add_transpeer keeps the test independent of which
    fields add_transpeer copies from its argument."""
    await store.add_transpeer(TranspeerEntry(addr, port, ["monero"], last_seen=first_seen + 1))
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
        await _add(store, addr, **kw)
    cur = pub.curate()
    check(cur == [("20.0.0.1", 7337), ("24.0.0.1", 7337), ("25.0.0.1", 7337)],
          "history, native, diversity and reserved rules")
    # Continuity: with a committed history, at most a quarter may be new.
    import transpeer.anchor.blob as blobmod
    prior = blobmod.encode_blob("monero", 1, [("20.0.0.1", 7337), ("24.0.0.1", 7337),
                                              ("30.0.0.1", 7337), ("31.0.0.1", 7337)])
    db.add(prior, Commitment(blob_hash(prior), "share", "v", "s", "w", 1, now), now)
    await _add(store, "26.0.0.1", first_seen=old, answered=8)
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
    check(list(pub.solutions) == [sol], "solution recorded")
    check(pub.solutions.maxlen == 1024, "solutions deque bounded at 1024")
    await store.close()


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
        await _add(store, f"4{i}.0.0.1", first_seen=old, answered=i)
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
    # Template records for one blob are bounded (final review, finding 1).
    from transpeer.anchor.auxrpc import MAX_TEMPLATE_RECORDS
    for i in range(MAX_TEMPLATE_RECORDS):
        tmpl_i = build_block_blob(16, 16, now, bytes([i + 32]) * 32, 0, 3_000_000, extra)
        sub_i = dict(sub, blob=tmpl_i.hex())
        r = await call("merge_mining_submit_solution", sub_i)
        if i < MAX_TEMPLATE_RECORDS - 1:
            check(r.get("result") == {"status": "accepted"}, f"template submission {i} accepted")
        else:
            check("error" in r, "submission past the template cap rejected")
    recs = db.commitments(aux_hash)
    check(sum(1 for c in recs if c.kind == "template") == MAX_TEMPLATE_RECORDS,
          "template commitments capped at MAX_TEMPLATE_RECORDS")
    check(rpc.stats["submit_rejected"] == 1, "the over-cap submission was rejected")
    bad = dict(sub, path=path ^ 1)
    r = await call("merge_mining_submit_solution", bad)
    check("error" in r and rpc.stats["submit_rejected"] == 2, "wrong path rejected")
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
    await _add(store, "50.0.0.1", first_seen=now - 20 * 86400, answered=4)
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
        check(not (Path(d) / "anchor_blobs.json").exists() and node.blobdb.blob_count() == 0,
              "empty database is not written to disk")
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):  # noqa: BLE001
            pass
    # Without the flag nothing is started.
    node2 = Node(Config(port=17342, in_memory=True, no_verify=True, no_pow=True, scan_rate=0.0))
    check(node2.publisher is None and node2.blobdb is None, "flag off: no anchor objects")


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
    await _add(store, "60.0.0.1", first_seen=int(clock["t"]) - 20 * 86400, answered=2)
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


async def main():
    await test_config_and_first_seen()
    await test_curation_and_rotation()
    await test_aux_rpc()
    await test_blob_endpoints()
    await test_node_wiring()
    await test_poller_end_to_end()
    print(f"\nResults: {passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    asyncio.run(main())
