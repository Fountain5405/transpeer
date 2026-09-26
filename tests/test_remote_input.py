#!/usr/bin/env python3
"""Hostile or malformed input from remote transpeers. No scanning; the
only network use is a local aiohttp server on 127.0.0.1:17380.

Run:  PYTHONPATH=$PWD .venv/bin/python tests/test_remote_input.py
"""

import asyncio
import sys
import time
from pathlib import Path

from aiohttp import web

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from transpeer.client import (  # noqa: E402
    MAX_NETWORKS_PER_TRANSPEER, TranspeerClient, _clamp_time, _clean_networks,
    _valid_endpoint,
)
from transpeer.config import (  # noqa: E402
    Config, HANDSHAKE_MAX_EFFORT, PROTOCOL_VERSION, RATE_LIMIT_REQUESTS,
)
from transpeer.peerstore import PeerStore, TranspeerEntry  # noqa: E402
from transpeer.pow import HANDSHAKE_BUCKET_SECS, verify_handshake  # noqa: E402
from transpeer.scanner import random_ip_in_cidr  # noqa: E402
from transpeer.server import TranspeerServer  # noqa: E402

PORT = 17380
passed = failed = 0


def check(cond, name):
    global passed, failed
    if cond:
        passed += 1
        print(f"  PASS: {name}")
    else:
        failed += 1
        print(f"  FAIL: {name}")


def test_helpers():
    print("Validation helpers")
    check(_valid_endpoint("20.1.2.3", 7337), "IPv4 literal with a usable port is accepted")
    check(not _valid_endpoint("example.org", 7337), "hostname rejected")
    check(not _valid_endpoint("2001:db8::1", 7337), "IPv6 literal rejected (store keys split on ':')")
    check(not _valid_endpoint("20.1.2.3", 0) and not _valid_endpoint("20.1.2.3", 65536), "port range enforced")
    check(not _valid_endpoint("20.1.2.3", "7337") and not _valid_endpoint("20.1.2.3", True), "port must be an int")
    check(not _valid_endpoint(20, 7337), "addr must be a string")
    now = 1_000
    check(_clamp_time(2**62, now) == now, "future timestamp clamped to the local clock")
    check(_clamp_time(-1, now) == 0 and _clamp_time("x", now) == 0 and _clamp_time(True, now) == 0,
          "negative or non-int timestamp becomes 0")
    check(_clean_networks(["monero", 7, "", "x" * 65, "aeon"]) == ["monero", "aeon"],
          "network names must be non-empty strings of bounded length")
    check(_clean_networks("monero") == [] and _clean_networks(None) == [],
          "a non-list networks field is treated as empty")
    check(len(_clean_networks([f"n{i}" for i in range(500)])) == MAX_NETWORKS_PER_TRANSPEER,
          "network list is truncated to the cap")


def test_pow_guard():
    print("EquiX buffer guard")
    bucket = int(time.time()) // HANDSHAKE_BUCKET_SECS
    for bad in (b"", b"\x01", b"\x00" * 15, b"\x00" * 17):
        ok = verify_handshake("20.1.2.3", "node", b"n" * 16, 10, bad, bucket)
        check(ok is False, f"solution of {len(bad)} bytes is rejected, not memmoved")


def test_scanner_edge():
    print("Scanner CIDR edge")
    check(random_ip_in_cidr("20.1.2.3/32") == "20.1.2.3", "/32 yields the address itself, not the next one")
    check(random_ip_in_cidr("20.1.2.2/31") in ("20.1.2.2",), "/31 stays inside the block")
    ip = random_ip_in_cidr("20.1.2.0/30")
    check(ip in ("20.1.2.1", "20.1.2.2"), "/30 skips network and broadcast")


def test_rate_limit_table():
    print("Rate-limit table")
    cfg = Config(in_memory=True, scan_rate=0.0)
    store = PeerStore(cfg)
    srv = TranspeerServer(cfg, store, "node", time.time())
    n = 10 * RATE_LIMIT_REQUESTS
    for i in range(n):
        srv._check_rate_limit(f"20.0.{i // 256}.{i % 256}")
    check(len(srv._rate_limits) >= 4 * RATE_LIMIT_REQUESTS, "entries inside the window are kept")
    # Age every entry out of the window, then one more request triggers pruning.
    for ts in srv._rate_limits.values():
        ts[:] = [t - 10_000 for t in ts]
    srv._check_rate_limit("20.9.9.9")
    check(len(srv._rate_limits) == 1, "expired addresses are dropped from the table")
    addr = "20.5.5.5"
    allowed = sum(1 for _ in range(RATE_LIMIT_REQUESTS + 5) if srv._check_rate_limit(addr))
    check(allowed == RATE_LIMIT_REQUESTS, "per-address limit unchanged")


async def test_gossip_uptime():
    print("Gossip and uptime")
    store = PeerStore(Config(in_memory=True, scan_rate=0.0))
    now = int(time.time())
    await store.add_transpeer(TranspeerEntry(addr="20.1.1.1", port=7337, networks=["monero"],
                                             last_seen=now, uptime=5000))
    await store.add_transpeer(TranspeerEntry(addr="20.1.1.1", port=7337, networks=["monero"],
                                             last_seen=now), gossiped=True)
    check(store.get_transpeer("20.1.1.1", 7337).uptime == 5000, "a gossiped mention does not zero uptime")
    await store.add_transpeer(TranspeerEntry(addr="20.1.1.1", port=7337, networks=["monero"],
                                             last_seen=now, uptime=6000))
    check(store.get_transpeer("20.1.1.1", 7337).uptime == 6000, "a direct probe still updates uptime")


class Hostile:
    """A server whose answers are well-formed JSON but not the protocol."""

    def __init__(self):
        self.calls = 0

    async def transpeer(self, request):
        return web.json_response({
            "protocol": PROTOCOL_VERSION, "node_id": "h", "uptime": -5,
            "networks": ["monero", 3, "", ["x"]] + [f"n{i}" for i in range(200)],
        })

    async def peers(self, request):
        net = request.match_info["network"]
        if net == "big402":
            return web.json_response({"effort": 2**31, "node_id": "h", "client_ip": "127.0.0.1"},
                                     status=402)
        if net == "notobject":
            return web.json_response([1, 2, 3])
        if net == "mixed":
            return web.json_response({"peers": [
                {},                                        # missing addr/port
                {"addr": "evil.example", "port": 18080},   # hostname
                {"addr": "20.2.2.2", "port": "18080"},     # port as string
                {"addr": "20.2.2.2", "port": 18080, "last_seen": 2**62},
                {"addr": "20.3.3.3", "port": 18080, "proof": {"nonce": "!!!", "solution": "x"}},
                {"addr": "20.4.4.4", "port": 18080, "last_seen": 1},
            ]})
        return web.json_response({"peers": "not a list"})

    async def transpeers(self, request):
        return web.json_response({"transpeers": [
            "junk",
            {"port": 7337},
            {"addr": "127.0.0.1:7337", "port": 7337},
            {"addr": "20.6.6.6", "port": 7337, "last_seen": 2**62, "networks": "monero"},
            {"addr": "20.7.7.7", "port": 7337, "last_seen": 5, "networks": ["monero"]},
        ]})


async def test_hostile_server():
    print("Hostile server")
    h = Hostile()
    app = web.Application()
    app.router.add_get("/transpeer", h.transpeer)
    app.router.add_get("/peers/{network}", h.peers)
    app.router.add_get("/transpeers", h.transpeers)
    runner = web.AppRunner(app)
    await runner.setup()
    await web.TCPSite(runner, "127.0.0.1", PORT).start()
    try:
        cfg = Config(in_memory=True, scan_rate=0.0, no_pow=True, sim_pow=True)
        store = PeerStore(cfg)
        client = TranspeerClient(cfg, store)
        now = int(time.time())

        entry = await client.probe_transpeer("127.0.0.1", PORT)
        check(entry is not None and entry.uptime == 0, "negative uptime becomes 0")
        check(entry is not None and entry.networks[0] == "monero"
              and len(entry.networks) == MAX_NETWORKS_PER_TRANSPEER
              and all(isinstance(n, str) for n in entry.networks),
              "advertised networks are cleaned and capped")

        t0 = time.monotonic()
        peers = await client.fetch_peers("127.0.0.1", PORT, "big402")
        check(peers == [] and time.monotonic() - t0 < 2.0,
              f"a 402 demanding effort above {HANDSHAKE_MAX_EFFORT} is refused without solving")

        check(await client.fetch_peers("127.0.0.1", PORT, "notobject") == [], "non-object /peers body -> []")
        check(await client.fetch_peers("127.0.0.1", PORT, "notlist") == [], "non-list peers field -> []")
        peers = await client.fetch_peers("127.0.0.1", PORT, "mixed")
        got = sorted((p.addr, p.port, p.last_seen) for p in peers)
        check([g[:2] for g in got] == [("20.2.2.2", 18080), ("20.4.4.4", 18080)],
              "bad entries are skipped individually; valid ones survive")
        check(all(g[2] <= now + 5 for g in got), "peer last_seen is clamped to now")

        tps = await client.fetch_transpeers("127.0.0.1", PORT)
        addrs = sorted(t.addr for t in tps)
        check(addrs == ["20.6.6.6", "20.7.7.7"], "junk, addr-less and 'ip:port' items are dropped")
        by = {t.addr: t for t in tps}
        check(by["20.6.6.6"].last_seen <= now + 5 and by["20.6.6.6"].networks == [],
              "gossiped last_seen clamped; non-list networks emptied")
        check(by["20.7.7.7"].last_seen == 5, "an honest past last_seen is kept")

        # The whole query path: the hostile answers must count as a query so
        # the rotation moves on.
        await store.add_transpeer(TranspeerEntry(addr="127.0.0.1", port=PORT, networks=["monero"],
                                                 last_seen=now))
        ok = await client.query_transpeer(store.get_transpeer("127.0.0.1", PORT))
        e = store.get_transpeer("127.0.0.1", PORT)
        check(ok is True and e is not None, "query of a hostile transpeer completes")
    finally:
        await runner.cleanup()


async def main():
    test_helpers()
    test_pow_guard()
    test_scanner_edge()
    test_rate_limit_table()
    await test_gossip_uptime()
    await test_hostile_server()
    print(f"\nResults: {passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    asyncio.run(main())
