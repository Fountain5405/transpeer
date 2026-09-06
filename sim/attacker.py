#!/usr/bin/env python3
"""Attacker node that tries to flood the transpeer network with fake peers.

Strategy: Generate fake peer entries for a network and serve them via
the transpeer protocol. With PoW enabled, the attacker must solve EquiX
for each fake entry, which costs CPU time. Without PoW, entries are free.

Usage:
    python attacker.py --target-network p2pa --num-fake-peers 1000 \
        --port 7337 --difficulty 100
"""

import argparse
import asyncio
import json
import logging
import os
import random
import struct
import sys
import time

import os
sys.path.insert(0, os.environ.get(
    "TRANSPEER_DIR",
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from aiohttp import web
from transpeer.config import PROTOCOL_VERSION

log = logging.getLogger(__name__)


def random_fake_ip():
    """Generate a random plausible-looking IP."""
    return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def parse_args():
    parser = argparse.ArgumentParser(description="Transpeer attacker node")
    parser.add_argument("--target-network", default="p2pa", help="Network to flood")
    parser.add_argument("--target-port", type=int, default=10000, help="Fake P2P port")
    parser.add_argument("--num-fake-peers", type=int, default=100, help="Number of fake peers")
    parser.add_argument("--port", type=int, default=7337, help="Transpeer port")
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--difficulty", type=int, default=100, help="PoW difficulty")
    parser.add_argument("--no-pow", action="store_true", help="Skip PoW on entries")
    parser.add_argument("--sim-pow", action="store_true", help="Use simulated PoW (sleep-based)")
    parser.add_argument("--announce-targets", default="",
                        help="Comma-separated transpeer IPs to self-announce to")
    parser.add_argument("--announce-interval", type=int, default=0,
                        help="Seconds between self-announce rounds (0 = off)")
    parser.add_argument("--serve-while-generating", action="store_true",
                        help="Start serving before fake-peer PoW finishes, so the "
                             "attacker is discoverable from t=0")
    return parser.parse_args()


class Attacker:
    def __init__(self, args):
        self.args = args
        self.node_id = "attacker_" + os.urandom(2).hex()
        self.start_time = time.time()
        self.fake_peers = []
        self.peers_generated = 0
        self.pow_time_total = 0.0

    async def generate_fake_peers(self):
        """Generate fake peer entries, optionally with PoW."""
        log.info("Generating %d fake peers for %s (difficulty=%d, pow=%s)",
                 self.args.num_fake_peers, self.args.target_network,
                 self.args.difficulty, not self.args.no_pow)

        for i in range(self.args.num_fake_peers):
            addr = random_fake_ip()
            port = self.args.target_port
            entry = {
                "addr": addr,
                "port": port,
                "last_seen": int(time.time()),
                "sources": 1,
            }

            if not self.args.no_pow:
                import base64
                if self.args.sim_pow:
                    from transpeer.pow import solve_simulated as pow_fn
                else:
                    from transpeer.pow import solve as pow_fn
                t0 = time.time()
                nonce, solution, bucket = pow_fn(
                    self.args.target_network, addr, port, self.args.difficulty,
                )
                elapsed = time.time() - t0
                self.pow_time_total += elapsed
                entry["proof"] = {
                    "nonce": base64.b64encode(nonce).decode(),
                    "effort": self.args.difficulty,
                    "solution": base64.b64encode(solution).decode(),
                    "timestamp_bucket": bucket,
                }

            self.fake_peers.append(entry)
            self.peers_generated += 1

            if (i + 1) % 10 == 0:
                log.info("Generated %d/%d fake peers (%.1fs PoW total)",
                         i + 1, self.args.num_fake_peers, self.pow_time_total)

        log.info("ATTACKER STATS: Generated %d fake peers in %.1fs PoW time (avg %.3fs/peer)",
                 self.peers_generated, self.pow_time_total,
                 self.pow_time_total / max(1, self.peers_generated))

    async def announce_loop(self):
        """Self-announce: hit /transpeer on every target.

        The target records the requester as a candidate, probes it back and
        admits it to its store. One request per target is the cheapest way
        into an honest node's transpeer list, and under the default policy
        it bypasses the gossip subnet limit. Repeating keeps last_seen
        fresh so recency-based eviction drops honest entries first.
        """
        targets = [t for t in self.args.announce_targets.split(",") if t]
        if not targets or self.args.announce_interval <= 0:
            return
        import aiohttp
        # Spread the first round so a thousand attackers do not fire at once.
        await asyncio.sleep(random.uniform(0, min(60, self.args.announce_interval)))
        sem = asyncio.Semaphore(10)
        rounds = ok = fail = 0

        async def hit(session, target):
            nonlocal ok, fail
            async with sem:
                try:
                    url = f"http://{target}:{self.args.port}/transpeer"
                    async with session.get(url) as r:
                        if r.status == 200:
                            ok += 1
                        else:
                            fail += 1
                except Exception:
                    fail += 1

        while True:
            rounds += 1
            timeout = aiohttp.ClientTimeout(total=5)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                await asyncio.gather(*(hit(session, t) for t in targets))
            log.info("ANNOUNCE round=%d ok=%d fail=%d targets=%d",
                     rounds, ok, fail, len(targets))
            await asyncio.sleep(self.args.announce_interval)

    async def handle_transpeer(self, request):
        return web.json_response({
            "protocol": PROTOCOL_VERSION,
            "node_id": self.node_id,
            "networks": [self.args.target_network],
            "peer_counts": {self.args.target_network: len(self.fake_peers)},
            "uptime": int(time.time() - self.start_time),
            "difficulty": self.args.difficulty,
        })

    async def handle_peers(self, request):
        network = request.match_info["network"]
        if network == self.args.target_network:
            return web.json_response({
                "network": network,
                "peers": self.fake_peers,
            })
        return web.json_response({"network": network, "peers": []})

    async def handle_transpeers(self, request):
        return web.json_response({"transpeers": []})


async def main():
    args = parse_args()
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [ATTACKER] %(message)s")

    attacker = Attacker(args)

    # Default: generate first, then serve. The PoW delay before an attacker
    # becomes reachable is part of what attacker_ratio measured, so it stays
    # the default. --serve-while-generating makes the attacker discoverable
    # from t=0 and fills in fake peers as their PoW completes.
    if not args.serve_while_generating:
        await attacker.generate_fake_peers()

    # Serve via transpeer protocol
    app = web.Application()
    app.router.add_get("/transpeer", attacker.handle_transpeer)
    app.router.add_get("/peers/{network}", attacker.handle_peers)
    app.router.add_get("/transpeers", attacker.handle_transpeers)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, args.bind, args.port)
    await site.start()
    log.info("Attacker serving %d fake %s peers on port %d",
             len(attacker.fake_peers), args.target_network, args.port)

    background = [attacker.announce_loop(), asyncio.Event().wait()]
    if args.serve_while_generating:
        background.append(attacker.generate_fake_peers())
    await asyncio.gather(*background)


if __name__ == "__main__":
    asyncio.run(main())
