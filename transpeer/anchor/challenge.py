"""Faithfulness challenges (spec §9): any node may challenge any
transpeer by sampling blob hashes it has verified and fetching them
back. Repeat failures mark the transpeer unfaithful; a hash every
challenged transpeer fails is "lost" and is never sampled against
anyone again."""

import asyncio
import random
import time
from collections import deque

from ..peerstore import PeerStore
from .fetch import AnchorClient

PER_HOUR = 8            # spec §9: up to 8 hashes per transpeer per hour
MIN_AGE = 600            # only commitments verified >= 10 minutes ago
FAIL_LIMIT = 3           # 3 failures in the window marks unfaithful
FAIL_WINDOW = 86400      # 24h failure window; 24h clean clears the mark
MIN_UPTIME = 600         # a transpeer syncing under 10 minutes isn't challenged


class Challenger:
    def __init__(self, store: PeerStore, reader, client: AnchorClient,
                clock=time.time, rng=None):
        self.store = store
        self.reader = reader
        self.client = client
        self.clock = clock
        self.rng = rng or random.Random()
        # (addr, port) -> deque of failure timestamps, pruned to FAIL_WINDOW.
        self._failures: dict[tuple, deque] = {}
        # (addr, port) -> {hour_bucket: {hashes already asked this hour}}.
        self._asked: dict[tuple, dict] = {}
        # Hashes every challenged transpeer has failed; not evidence
        # against any of them (spec §9), and never sampled again.
        self.lost: set = set()
        self.stats = {"challenged": 0, "failed": 0, "marked": 0, "lost": 0}

    async def round(self) -> None:
        now = self.clock()
        hour = int(now) // 3600
        hashes = [h for h in self.reader.verified_hashes(MIN_AGE) if h not in self.lost]
        entries = [
            e for e in self.store.get_transpeers()
            if e.alive and e.uptime >= MIN_UPTIME
        ]

        async def challenge_one(entry):
            key = (entry.addr, entry.port)
            by_hour = self._asked.setdefault(key, {})
            for k in list(by_hour):
                if k != hour:
                    del by_hour[k]
            asked_this_hour = by_hour.setdefault(hour, set())
            available = [h for h in hashes if h not in asked_this_hour]
            n = min(PER_HOUR, len(available))
            sample = self.rng.sample(available, n) if n else []
            results = {}
            for h in sample:
                asked_this_hour.add(h)
                blob = await self.client.fetch_blob(entry.addr, entry.port, h)
                results[h] = blob is not None
            return key, entry, results

        outcomes = await asyncio.gather(*(challenge_one(e) for e in entries))

        # Tally per hash first: a hash every challenger in this round
        # failed is lost, and its failures count against nobody.
        hash_results: dict[bytes, list] = {}
        for _key, _entry, results in outcomes:
            for h, ok in results.items():
                hash_results.setdefault(h, []).append(ok)
        newly_lost = {h for h, oks in hash_results.items() if oks and not any(oks)}
        self.lost.update(newly_lost)

        challenged = failed = marked = 0
        cutoff = now - FAIL_WINDOW
        for key, entry, results in outcomes:
            if not results:
                continue
            challenged += 1
            fails = self._failures.setdefault(key, deque())
            for h, ok in results.items():
                if h in newly_lost:
                    continue
                if not ok:
                    fails.append(now)
                    failed += 1
            while fails and fails[0] < cutoff:
                fails.popleft()
            if len(fails) >= FAIL_LIMIT:
                if not entry.unfaithful:
                    marked += 1
                await self.store.set_unfaithful(entry.addr, entry.port, True)
            elif len(fails) == 0 and entry.unfaithful:
                await self.store.set_unfaithful(entry.addr, entry.port, False)

        self.stats = {
            "challenged": challenged,
            "failed": failed,
            "marked": marked,
            "lost": len(newly_lost),
        }
