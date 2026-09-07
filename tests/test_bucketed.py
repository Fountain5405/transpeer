#!/usr/bin/env python3
"""Unit checks for the bucketed transpeer policy. No network, no PoW.

Run:  python tests/test_bucketed.py
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from transpeer.config import Config, MAX_TRANSPEERS_TRACKED  # noqa: E402
from transpeer.peerstore import (  # noqa: E402
    PeerStore, TranspeerEntry, MAX_TRANSPEERS_PER_SUBNET,
)

passed = failed = 0


def check(cond, name):
    global passed, failed
    if cond:
        passed += 1
        print(f"  PASS: {name}")
    else:
        failed += 1
        print(f"  FAIL: {name}")


def store(bucketed):
    return PeerStore(Config(in_memory=True, bucketed=bucketed, subnet_prefix=24))


def entry(ip, seen=1000, queried=0):
    return TranspeerEntry(addr=ip, port=7337, networks=["x"],
                          last_seen=seen, last_queried=queried)


async def test_admission():
    print("\n=== Admission: per-bucket cap ===")
    n = MAX_TRANSPEERS_PER_SUBNET + 2

    s = store(bucketed=False)
    added = sum([await s.add_transpeer(entry(f"11.0.5.{i}")) for i in range(1, n + 1)])
    check(added == n, f"default policy admits {n} scanned/candidate entries from one bucket (the bypass)")

    s = store(bucketed=False)
    added = sum([await s.add_transpeer(entry(f"11.0.5.{i}"), gossiped=True) for i in range(1, n + 1)])
    check(added == MAX_TRANSPEERS_PER_SUBNET, "default policy caps gossiped entries per bucket")

    s = store(bucketed=True)
    added = sum([await s.add_transpeer(entry(f"11.0.5.{i}")) for i in range(1, n + 1)])
    check(added == MAX_TRANSPEERS_PER_SUBNET, "bucketed policy caps scanned/candidate entries per bucket")

    s = store(bucketed=True)
    added = sum([await s.add_transpeer(entry(f"11.0.{b}.1")) for b in range(n)])
    check(added == n, "bucketed policy admits one entry from each of several buckets")


async def fill(s, buckets, per_bucket, seen):
    """Fill buckets 0..buckets-1 with per_bucket entries each."""
    for b in range(buckets):
        for h in range(1, per_bucket + 1):
            await s.add_transpeer(entry(f"11.0.{b}.{h}", seen=seen))


async def test_eviction():
    print("\n=== Eviction when full ===")
    # Under the bucketed policy the cap is 3 per bucket, so a full store of
    # 500 needs 167 buckets. Bucket 0 gets a single very old entry; the rest
    # are full and recent.
    s = store(bucketed=True)
    await s.add_transpeer(entry("11.0.0.1", seen=1))            # old, lonely
    b = 1
    while len(s.get_transpeers()) < MAX_TRANSPEERS_TRACKED:
        for h in range(1, MAX_TRANSPEERS_PER_SUBNET + 1):
            if len(s.get_transpeers()) >= MAX_TRANSPEERS_TRACKED:
                break
            await s.add_transpeer(entry(f"11.0.{b}.{h}", seen=1000))
        b += 1
    check(len(s.get_transpeers()) == MAX_TRANSPEERS_TRACKED, "store filled to cap")

    added = await s.add_transpeer(entry("11.0.250.1", seen=2000))
    keys = {t.key for t in s.get_transpeers()}
    check(added, "newcomer from a fresh bucket is admitted when full")
    check("11.0.0.1:7337" in keys, "bucketed eviction spares the oldest entry when its bucket is not the fullest")

    # Newcomer whose own bucket is uniquely the fullest is refused.
    s2 = store(bucketed=True)
    await s2.add_transpeer(entry("11.0.9.1"))
    await s2.add_transpeer(entry("11.0.9.2"))
    await s2.add_transpeer(entry("11.0.8.1"))
    # Force the "full" branch with a tiny cap by monkeypatching the module constant.
    import transpeer.peerstore as ps
    saved = ps.MAX_TRANSPEERS_TRACKED
    ps.MAX_TRANSPEERS_TRACKED = 3
    try:
        refused = not await s2.add_transpeer(entry("11.0.9.3", seen=5000))
        check(refused, "newcomer is refused when its own bucket is the unique fullest")
        admitted = await s2.add_transpeer(entry("11.0.7.1", seen=5000))
        gone_from_9 = sum(1 for t in s2.get_transpeers() if t.addr.startswith("11.0.9.")) == 1
        check(admitted and gone_from_9, "newcomer from another bucket evicts from the fullest bucket")
    finally:
        ps.MAX_TRANSPEERS_TRACKED = saved

    # Default policy: globally oldest goes, regardless of bucket.
    s3 = store(bucketed=False)
    await s3.add_transpeer(entry("11.0.0.1", seen=1))
    await s3.add_transpeer(entry("11.0.9.1", seen=1000))
    await s3.add_transpeer(entry("11.0.9.2", seen=1000))
    ps.MAX_TRANSPEERS_TRACKED = 3
    try:
        await s3.add_transpeer(entry("11.0.9.3", seen=5000))
        keys = {t.key for t in s3.get_transpeers()}
        check("11.0.0.1:7337" not in keys, "default eviction drops the globally oldest entry (recency flooding works)")
    finally:
        ps.MAX_TRANSPEERS_TRACKED = saved


async def test_query_selection():
    print("\n=== Query selection ===")
    s = store(bucketed=True)
    for h in range(1, 4):                       # 3 in bucket A (cap)
        await s.add_transpeer(entry(f"11.0.1.{h}", queried=h))
    await s.add_transpeer(entry("11.0.2.1", queried=100))   # 1 in bucket B, queried most recently
    batch = s.get_transpeers_for_query(2)
    buckets = {t.addr.rsplit(".", 1)[0] for t in batch}
    check(len(batch) == 2 and len(buckets) == 2, "bucketed batch of 2 spans 2 buckets despite A having 3x the entries")
    batch = s.get_transpeers_for_query(10)
    check(len(batch) == 4 and len({t.key for t in batch}) == 4, "bucketed batch wraps around without duplicates")

    s = store(bucketed=False)
    for h in range(1, 4):
        await s.add_transpeer(entry(f"11.0.1.{h}", queried=h))
    await s.add_transpeer(entry("11.0.2.1", queried=100))
    batch = s.get_transpeers_for_query(2)
    check([t.addr for t in batch] == ["11.0.1.1", "11.0.1.2"], "default batch is oldest-queried first")


async def test_gossip_selection():
    print("\n=== Gossip selection ===")
    import random
    random.seed(7)
    s = store(bucketed=True)
    # Bucketed admission caps bucket A at 3, so build the imbalance via the
    # default policy, then flip the flag on the same store.
    s.config.bucketed = False
    for h in range(1, 101):
        await s.add_transpeer(entry(f"11.0.1.{h}"))
    for h in range(1, 4):
        await s.add_transpeer(entry(f"11.0.2.{h}"))
    s.config.bucketed = True
    hits_b = 0
    for _ in range(200):
        sample = s.get_transpeers_for_gossip(10)
        hits_b += sum(1 for t in sample if t.addr.startswith("11.0.2."))
    share = hits_b / (200 * 10)
    check(0.2 < share < 0.5,
          f"bucketed gossip gives the 3-entry bucket ~half the slots (got {share:.2f}, population share 0.03)")
    sample = s.get_transpeers_for_gossip(10)
    check(len({t.key for t in sample}) == len(sample), "bucketed gossip sample has no duplicates")

    s.config.bucketed = False
    hits_b = sum(1 for _ in range(200) for t in s.get_transpeers_for_gossip(10) if t.addr.startswith("11.0.2."))
    share = hits_b / 2000
    check(share < 0.1, f"default gossip tracks population share (got {share:.2f})")


async def test_snapshot():
    print("\n=== Snapshot ===")
    from transpeer.peerstore import Peer
    s = store(bucketed=True)
    await s.add_transpeer(entry("11.0.1.1"))
    await s.add_transpeer(entry("11.0.2.1"))
    await s.add_peer(Peer(network="x", addr="1.2.3.4", port=1, last_seen=1), source_addr="11.0.1.1")
    await s.add_peer(Peer(network="x", addr="1.2.3.5", port=1, last_seen=1), source_addr="11.0.1.1")
    await s.add_peer(Peer(network="x", addr="1.2.3.6", port=1, last_seen=1))
    snap = s.snapshot()
    check(snap["transpeers"] == 2 and snap["buckets"] == 2, "snapshot counts transpeers and buckets")
    check(snap["peer_sources"] == {"11.0.1.1": 2, "local": 1}, "snapshot attributes peers to their source transpeer")


async def test_vouchers():
    print("\n=== Voucher counting ===")
    from transpeer.peerstore import Peer, BASE_PEERS_PER_SOURCE

    def vstore():
        return PeerStore(Config(in_memory=True, bucketed=True, vouchers=True, subnet_prefix=24))

    def peer(addr, claimed=1):
        return Peer(network="x", addr=addr, port=1, last_seen=1, sources=claimed)

    # Claimed counts are ignored; vouchers are distinct observed buckets.
    s = vstore()
    await s.add_peer(peer("1.1.1.1", claimed=999), source_addr="11.0.5.1")
    await s.add_peer(peer("1.1.1.1", claimed=999), source_addr="11.0.5.2")
    await s.add_peer(peer("1.1.1.1", claimed=999), source_addr="11.0.5.3")
    p = s.get_peers("x", verified_only=False)[0]
    check(p.sources == 1 and p.vouchers == {"11.0.5.0/24"},
          "three reporters in one bucket are one voucher, claimed 999 ignored")
    await s.add_peer(peer("1.1.1.1"), source_addr="11.0.6.1")
    p = s.get_peers("x", verified_only=False)[0]
    check(p.sources == 2 and len(p.vouchers) == 2, "a reporter in a second bucket is a second voucher")

    # Default policy keeps the claimed-max behaviour.
    s0 = store(bucketed=False)
    await s0.add_peer(peer("1.1.1.1", claimed=1), source_addr="11.0.5.1")
    await s0.add_peer(peer("1.1.1.1", claimed=999), source_addr="11.0.5.2")
    check(s0.get_peers("x", verified_only=False)[0].sources == 999,
          "default policy still takes the remote's claimed source count")

    # Per-source cap is shared by every transpeer in a bucket.
    s = vstore()
    for i in range(BASE_PEERS_PER_SOURCE):
        await s.add_peer(peer(f"2.0.0.{i+1}"), source_addr="11.0.5.1")
    refused = not await s.add_peer(peer("2.0.1.1"), source_addr="11.0.5.2")
    accepted = await s.add_peer(peer("2.0.1.1"), source_addr="11.0.6.1")
    check(refused and accepted, "a second transpeer in a capped bucket is refused; another bucket is not")

    s = store(bucketed=True)
    for i in range(BASE_PEERS_PER_SOURCE):
        await s.add_peer(peer(f"2.0.0.{i+1}"), source_addr="11.0.5.1")
    check(await s.add_peer(peer("2.0.1.1"), source_addr="11.0.5.2"),
          "without --vouchers the cap is per address, so the same-bucket reporter gets a fresh 50")

    # Ranking: most independently corroborated first.
    s = vstore()
    await s.add_peer(peer("3.0.0.1"), source_addr="11.0.5.1")      # 1 voucher
    await s.add_peer(peer("3.0.0.2"), source_addr="11.0.5.1")
    await s.add_peer(peer("3.0.0.2"), source_addr="11.0.6.1")      # 2 vouchers
    await s.add_peer(peer("3.0.0.2"), source_addr="11.0.7.1")      # 3 vouchers
    await s.add_peer(peer("3.0.0.3"), source_addr="11.0.8.1")
    await s.add_peer(peer("3.0.0.3"), source_addr="11.0.9.1")      # 2 vouchers
    order = [p.addr for p in s.get_peers("x", verified_only=False)]
    check(order == ["3.0.0.2", "3.0.0.3", "3.0.0.1"], "get_peers ranks by voucher count")
    snap = s.snapshot(networks=["x"])
    check(snap["voucher_hist"] == {1: 1, 2: 1, 3: 1} and snap["daemon_view"]["x"][0] == "11.0.5.1:3",
          "snapshot reports the voucher histogram and the daemon's view in rank order")


async def main():
    await test_admission()
    await test_eviction()
    await test_query_selection()
    await test_gossip_selection()
    await test_snapshot()
    await test_vouchers()
    print(f"\nResults: {passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    asyncio.run(main())
