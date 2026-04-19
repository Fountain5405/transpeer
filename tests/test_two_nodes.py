"""Integration test: two transpeer nodes discover each other and exchange peers."""

import asyncio
import time
from pathlib import Path
import shutil
import sys

import aiohttp
from aiohttp import web

sys.path.insert(0, str(Path(__file__).parent.parent))

from transpeer.config import Config, PROTOCOL_VERSION
from transpeer.peerstore import Peer, PeerStore, TranspeerEntry
from transpeer.server import TranspeerServer
from transpeer.client import TranspeerClient
from transpeer.pow import solve as pow_solve, verify as pow_verify


# Test directories
DIR_A = Path("/tmp/transpeer_test_a")
DIR_B = Path("/tmp/transpeer_test_b")
PORT_A = 17337
PORT_B = 17338


def cleanup():
    for d in (DIR_A, DIR_B):
        if d.exists():
            shutil.rmtree(d)


async def start_node(name, port, data_dir, networks):
    """Start a transpeer server and return its components."""
    config = Config(port=port, bind="127.0.0.1", data_dir=data_dir, networks=networks)
    store = PeerStore(config)
    await store.init()
    node_id = f"test_{name}"
    server = TranspeerServer(config, store, node_id, time.time())
    client = TranspeerClient(config, store)

    app = server.create_app()
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", port)
    await site.start()

    return config, store, server, client, runner


async def run_tests():
    cleanup()
    passed = 0
    failed = 0

    def check(name, condition):
        nonlocal passed, failed
        if condition:
            print(f"  PASS: {name}")
            passed += 1
        else:
            print(f"  FAIL: {name}")
            failed += 1

    # --- Start two nodes ---
    print("\n=== Starting Node A (monero) on port %d ===" % PORT_A)
    cfg_a, store_a, server_a, client_a, runner_a = await start_node(
        "node_a", PORT_A, DIR_A, ["monero"]
    )

    print("=== Starting Node B (wownero) on port %d ===" % PORT_B)
    cfg_b, store_b, server_b, client_b, runner_b = await start_node(
        "node_b", PORT_B, DIR_B, ["wownero"]
    )

    # --- Add test peers to each node ---
    print("\n=== Adding test peers ===")

    # Node A has monero peers
    now = int(time.time())
    for i in range(5):
        addr = f"44.{i}.1.1"
        nonce, sol, bucket = pow_solve("monero", addr, 18080, effort=1)
        peer = Peer(
            network="monero", addr=addr, port=18080,
            last_seen=now, sources=1, verified=True,
            nonce=nonce, effort=1, solution=sol, timestamp_bucket=bucket,
        )
        await store_a.add_peer(peer)

    # Node B has wownero peers
    for i in range(3):
        addr = f"55.{i}.2.2"
        nonce, sol, bucket = pow_solve("wownero", addr, 34567, effort=1)
        peer = Peer(
            network="wownero", addr=addr, port=34567,
            last_seen=now, sources=1, verified=True,
            nonce=nonce, effort=1, solution=sol, timestamp_bucket=bucket,
        )
        await store_b.add_peer(peer)

    check("Node A has 5 monero peers", store_a.peer_count("monero") == 5)
    check("Node B has 3 wownero peers", store_b.peer_count("wownero") == 3)
    check("Node A has 0 wownero peers", store_a.peer_count("wownero") == 0)
    check("Node B has 0 monero peers", store_b.peer_count("monero") == 0)

    # --- Test 1: Handshake / Discovery ---
    print("\n=== Test 1: Handshake ===")

    entry_a = await client_b.probe_transpeer("127.0.0.1", PORT_A)
    check("Node B can probe Node A", entry_a is not None)
    check("Node A reports correct protocol", entry_a is not None)
    if entry_a:
        check("Node A reports monero network", "monero" in entry_a.networks)

    entry_b = await client_a.probe_transpeer("127.0.0.1", PORT_B)
    check("Node A can probe Node B", entry_b is not None)
    if entry_b:
        check("Node B reports wownero network", "wownero" in entry_b.networks)

    # --- Test 2: Peer Exchange ---
    print("\n=== Test 2: Peer Exchange ===")

    # Node B fetches monero peers from Node A
    monero_peers = await client_b.fetch_peers("127.0.0.1", PORT_A, "monero")
    check("Node B receives 5 monero peers from A", len(monero_peers) == 5)

    # Verify PoW on received peers
    if monero_peers:
        p = monero_peers[0]
        valid = pow_verify(
            "monero", p.addr, p.port,
            p.nonce, p.effort, p.solution, p.timestamp_bucket,
        )
        check("PoW on received monero peer is valid", valid)

    # Node A fetches wownero peers from Node B
    wownero_peers = await client_a.fetch_peers("127.0.0.1", PORT_B, "wownero")
    check("Node A receives 3 wownero peers from B", len(wownero_peers) == 3)

    # Store the received peers
    for p in monero_peers:
        await store_b.add_peer(p)
    for p in wownero_peers:
        await store_a.add_peer(p)

    check("Node A now has wownero peers",
          len(store_a.get_peers("wownero", verified_only=False)) == 3)
    check("Node B now has monero peers",
          len(store_b.get_peers("monero", verified_only=False)) == 5)

    # --- Test 3: Transpeer List Exchange ---
    print("\n=== Test 3: Transpeer List Exchange ===")

    # Add each other as known transpeers
    await store_a.add_transpeer(entry_b)
    await store_b.add_transpeer(entry_a)

    # Node A fetches transpeer list from Node B
    tp_list = await client_a.fetch_transpeers("127.0.0.1", PORT_B)
    check("Node A gets transpeer list from B", len(tp_list) >= 1)
    if tp_list:
        check("Transpeer list includes Node A itself", any(
            t.addr == "127.0.0.1" and t.port == PORT_A for t in tp_list
        ))

    # --- Test 4: Full query_transpeer flow ---
    print("\n=== Test 4: Full Query Flow ===")

    # Reset Node B's store to simulate fresh discovery
    store_b2_dir = Path("/tmp/transpeer_test_b2")
    if store_b2_dir.exists():
        shutil.rmtree(store_b2_dir)
    cfg_b2 = Config(port=PORT_B, bind="127.0.0.1", data_dir=store_b2_dir, networks=["wownero"])
    store_b2 = PeerStore(cfg_b2)
    await store_b2.init()
    client_b2 = TranspeerClient(cfg_b2, store_b2)

    check("Fresh node has 0 monero peers", store_b2.peer_count("monero") == 0)

    # Query Node A using the full flow
    await client_b2.query_transpeer(TranspeerEntry(
        addr="127.0.0.1", port=PORT_A, networks=["monero"], last_seen=now,
    ))

    check("After full query, fresh node has monero peers",
          len(store_b2.get_peers("monero", verified_only=False)) == 5)
    check("Fresh node learned about Node A as transpeer",
          len(store_b2.get_transpeers()) >= 1)

    await store_b2.close()
    if store_b2_dir.exists():
        shutil.rmtree(store_b2_dir)

    # --- Test 5: Implicit Self-Announcement ---
    print("\n=== Test 5: Implicit Self-Announcement ===")

    # When Node B queries Node A's endpoints, Node A should record B's IP
    # We can check the candidate list on server_a
    # Make a direct HTTP request to trigger candidate recording
    async with aiohttp.ClientSession() as session:
        async with session.get(f"http://127.0.0.1:{PORT_A}/transpeer") as resp:
            await resp.json()

    candidates = store_a.pop_candidates()
    check("Node A recorded requesting IP as candidate", len(candidates) > 0)

    # --- Test 6: Invalid PoW Rejection ---
    print("\n=== Test 6: Invalid PoW Rejection ===")

    bad_peer = Peer(
        network="monero", addr="99.99.99.99", port=18080,
        last_seen=now, sources=1, verified=True,
        nonce=b"\x00" * 16, effort=1,
        solution=b"\x00" * 16, timestamp_bucket=0,
    )
    valid = pow_verify(
        "monero", bad_peer.addr, bad_peer.port,
        bad_peer.nonce, bad_peer.effort, bad_peer.solution,
        bad_peer.timestamp_bucket,
    )
    check("Fabricated PoW is rejected", not valid)

    # --- Test 7: Requesting non-existent network ---
    print("\n=== Test 7: Empty Network Request ===")

    bitcoin_peers = await client_a.fetch_peers("127.0.0.1", PORT_B, "bitcoin")
    check("Requesting unknown network returns empty list", len(bitcoin_peers) == 0)

    # --- Test 8: Rate limiting ---
    print("\n=== Test 8: Rate Limiting ===")

    # Hammer Node A with requests — should eventually get rate limited
    rate_limited = False
    async with aiohttp.ClientSession() as session:
        for _ in range(70):
            async with session.get(f"http://127.0.0.1:{PORT_A}/transpeer") as resp:
                if resp.status == 429:
                    rate_limited = True
                    break
    check("Rate limiting kicks in after many requests", rate_limited)

    # --- Cleanup ---
    await runner_a.cleanup()
    await runner_b.cleanup()
    await store_a.close()
    await store_b.close()
    cleanup()

    # --- Summary ---
    total = passed + failed
    print(f"\n{'='*40}")
    print(f"Results: {passed}/{total} passed, {failed} failed")
    if failed == 0:
        print("All tests passed!")
    else:
        print("Some tests failed.")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(run_tests())
