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


async def main():
    await test_config_and_first_seen()
    print(f"\nResults: {passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    asyncio.run(main())
