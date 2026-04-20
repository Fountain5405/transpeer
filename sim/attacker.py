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

sys.path.insert(0, "/home/lever65/transpeer")

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

    # Generate fake peers (this is where PoW cost hits)
    await attacker.generate_fake_peers()

    # Serve them via transpeer protocol
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

    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
