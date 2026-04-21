#!/usr/bin/env python3
"""Flooder attacker: hammers target transpeers with /peers and /transpeers
requests to test handshake PoW defenses.

Unlike attacker.py (which publishes fake peer entries), the flooder just
sends a high volume of requests to exhaust server resources or enumerate
data. The goal is to trigger the adaptive handshake PoW.

Usage:
    python flooder.py --targets 11.0.0.1,11.0.0.2 --rate 10 --network p2pa
"""

import argparse
import asyncio
import base64
import logging
import random
import sys
import time

sys.path.insert(0, "/home/lever65/transpeer")

import aiohttp

from transpeer.pow import solve_handshake

log = logging.getLogger(__name__)


def parse_args():
    parser = argparse.ArgumentParser(description="Flooder DoS attacker")
    parser.add_argument("--targets", required=True,
                        help="Comma-separated list of target IPs")
    parser.add_argument("--target-port", type=int, default=7337)
    parser.add_argument("--rate", type=float, default=10,
                        help="Requests per second (total, across all targets)")
    parser.add_argument("--network", default="p2pa",
                        help="Network name to query /peers for")
    parser.add_argument("--duration", type=int, default=0,
                        help="Seconds to run (0 = forever)")
    parser.add_argument("--solve-pow", action="store_true",
                        help="Actually solve handshake PoW when challenged (costs CPU)")
    parser.add_argument("--sim-pow", action="store_true",
                        help="Use simulated PoW for Shadow compatibility")
    return parser.parse_args()


class Flooder:
    def __init__(self, args):
        self.args = args
        self.targets = args.targets.split(",")
        self.requests_sent = 0
        self.requests_200 = 0
        self.requests_402 = 0
        self.requests_429 = 0
        self.requests_other = 0
        self.pow_solves = 0
        self.pow_time_total = 0.0
        # Cache solved handshake proofs per target
        # key: (server_ip, node_id, bucket) -> header
        self._pow_cache: dict[tuple[str, str, int], str] = {}

    async def _get_cached_pow(self, server_ip: str) -> str | None:
        for (ip, _, _), hdr in self._pow_cache.items():
            if ip == server_ip:
                return hdr
        return None

    async def _solve_and_cache(self, server_ip: str, effort: int,
                               node_id: str, client_ip: str) -> str:
        t0 = time.time()
        nonce, solution, bucket = solve_handshake(
            client_ip, node_id, effort, simulated=self.args.sim_pow,
        )
        elapsed = time.time() - t0
        self.pow_solves += 1
        self.pow_time_total += elapsed
        header = f"{bucket}:{base64.b64encode(nonce).decode()}:{base64.b64encode(solution).decode()}"
        self._pow_cache[(server_ip, node_id, bucket)] = header
        return header

    async def _make_request(self, session: aiohttp.ClientSession, target: str,
                            endpoint: str):
        url = f"http://{target}:{self.args.target_port}{endpoint}"
        headers = {}
        cached = await self._get_cached_pow(target)
        if cached:
            headers["X-Transpeer-PoW"] = cached

        try:
            async with session.get(url, headers=headers,
                                   timeout=aiohttp.ClientTimeout(total=10)) as resp:
                self.requests_sent += 1
                if resp.status == 200:
                    self.requests_200 += 1
                elif resp.status == 402:
                    self.requests_402 += 1
                    if self.args.solve_pow:
                        info = await resp.json()
                        effort = info.get("effort", 0)
                        node_id = info.get("node_id", "")
                        client_ip = info.get("client_ip", "")
                        if effort > 0 and node_id and client_ip:
                            log.info("Solving handshake PoW: effort=%d (target=%s)",
                                     effort, target)
                            header = await self._solve_and_cache(
                                target, effort, node_id, client_ip,
                            )
                            # Retry once
                            async with session.get(
                                url, headers={"X-Transpeer-PoW": header},
                                timeout=aiohttp.ClientTimeout(total=10),
                            ) as retry_resp:
                                self.requests_sent += 1
                                if retry_resp.status == 200:
                                    self.requests_200 += 1
                                else:
                                    self.requests_other += 1
                elif resp.status == 429:
                    self.requests_429 += 1
                else:
                    self.requests_other += 1
        except (aiohttp.ClientError, asyncio.TimeoutError):
            self.requests_other += 1

    async def flood_loop(self):
        logging.basicConfig(level=logging.INFO,
                            format="%(asctime)s [FLOODER] %(message)s")
        interval = 1.0 / self.args.rate if self.args.rate > 0 else 0.1
        start = time.time()
        last_report = start

        async with aiohttp.ClientSession() as session:
            while True:
                target = random.choice(self.targets)
                endpoint = random.choice([f"/peers/{self.args.network}", "/transpeers"])
                await self._make_request(session, target, endpoint)

                now = time.time()
                if now - last_report >= 60:
                    log.info("FLOODER STATS: sent=%d 200=%d 402=%d 429=%d other=%d "
                             "pow_solves=%d pow_time=%.1fs",
                             self.requests_sent, self.requests_200,
                             self.requests_402, self.requests_429, self.requests_other,
                             self.pow_solves, self.pow_time_total)
                    last_report = now

                if self.args.duration > 0 and (now - start) >= self.args.duration:
                    break

                await asyncio.sleep(interval)


async def main():
    args = parse_args()
    flooder = Flooder(args)
    await flooder.flood_loop()


if __name__ == "__main__":
    asyncio.run(main())
