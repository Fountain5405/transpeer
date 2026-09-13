#!/usr/bin/env python3
"""A P2Pool-style merge-mining client: polls a sidecar's aux-chain
JSON-RPC the way p2pool v4.18 does (every 500 ms, sends the current
aux_hash, treats an empty result or the same hash as no change, keeps
the last 8 jobs, expires a chain whose hash is unchanged for 1800 s).

Used by tests, by the Shadow venue oracle, and by hand:
    .venv/bin/python sim/mm_poller.py http://127.0.0.1:7338/ WALLET
"""

import asyncio
import collections
import sys
import time

import aiohttp

NUM_PREVIOUS_HASHES = 8
EXPIRE_TIME = 1800.0
POLL_INTERVAL = 0.5


class MergeMiningPoller:
    def __init__(self, url: str, address: str, interval: float = POLL_INTERVAL,
                 expire: float = EXPIRE_TIME, clock=time.time, sleep=asyncio.sleep):
        self.url = url
        self.address = address
        self.interval = interval
        self.expire = expire
        self.clock = clock
        self.sleep = sleep
        self.chain_id: str | None = None
        self.aux_hash = "00" * 32
        self.aux_blob = ""
        self.aux_diff = 0
        self.previous = collections.deque(maxlen=NUM_PREVIOUS_HASHES)
        self.last_updated = 0.0
        self.expired = False
        self.polls = 0
        self.changes = 0
        self.height = 0
        self.prev_id = "00" * 32

    async def _call(self, session, method, params=None):
        req = {"jsonrpc": "2.0", "id": "0", "method": method}
        if params is not None:
            req["params"] = params
        async with session.post(self.url, json=req) as r:
            return await r.json()

    async def run_once(self, session) -> bool:
        if self.chain_id is None:
            r = await self._call(session, "merge_mining_get_chain_id")
            self.chain_id = r["result"]["chain_id"]
        self.polls += 1
        r = await self._call(session, "merge_mining_get_aux_block", {
            "address": self.address, "aux_hash": self.aux_hash,
            "height": self.height, "prev_id": self.prev_id,
        })
        res = r.get("result") or {}
        changed = bool(res) and res.get("aux_hash") != self.aux_hash
        if changed:
            self.aux_hash = res["aux_hash"]
            self.aux_blob = res["aux_blob"]
            self.aux_diff = int(res["aux_diff"])
            self.previous.append((self.aux_hash, self.aux_blob))
            self.last_updated = self.clock()
            self.changes += 1
        self.expired = self.last_updated > 0 and self.clock() - self.last_updated >= self.expire
        return changed

    async def submit(self, session, blob: bytes, merkle_proof, path: int, seed_hash: bytes,
                     aux_hash: str | None = None) -> dict:
        aux_hash = aux_hash or self.aux_hash
        aux_blob = next((b for h, b in self.previous if h == aux_hash), self.aux_blob)
        return await self._call(session, "merge_mining_submit_solution", {
            "aux_blob": aux_blob, "aux_hash": aux_hash, "blob": blob.hex(),
            "merkle_proof": [p.hex() for p in merkle_proof], "path": path,
            "seed_hash": seed_hash.hex(),
        })

    async def run(self, session):
        while True:
            if await self.run_once(session):
                print(f"{time.strftime('%H:%M:%S')} job {self.aux_hash[:16]} diff {self.aux_diff} "
                      f"blob {len(self.aux_blob) // 2} B", flush=True)
            if self.expired:
                print("chain expired: no hash change for 1800 s", flush=True)
            await self.sleep(self.interval)


async def _main(argv):
    url, address = argv[1], argv[2]
    async with aiohttp.ClientSession() as s:
        await MergeMiningPoller(url, address).run(s)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(2)
    asyncio.run(_main(sys.argv))
