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
    check(pub.solutions == [sol], "solution recorded")
    await store.close()


async def main():
    await test_config_and_first_seen()
    await test_curation_and_rotation()
    print(f"\nResults: {passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    asyncio.run(main())
