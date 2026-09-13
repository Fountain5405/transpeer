"""The publisher: curates a list from the peer store (spec §4.1),
issues it as a blob that rotates every period (§3.1, §4.2), serves
every blob it has issued (§4.3) and records the solutions P2Pool
reports."""

import ipaddress
import time
from collections import OrderedDict
from dataclasses import dataclass

from ..config import Config
from ..peerstore import PeerStore
from .blob import (MAX_ENTRIES, blob_hash, decode_blob, encode_blob, is_reserved,
                    list_body, period_of, with_period)
from .blobdb import BlobDB

BODY_MAX_AGE = 86400       # spec §4.1: at most one new list body per day
QUALITY_MIN_SAMPLES = 5
QUALITY_MIN_RATE = 0.8


@dataclass(frozen=True)
class Solution:
    aux_hash: bytes
    height: int
    prev_id: bytes
    timestamp: int
    root: bytes
    proof: tuple
    path: int
    seed_hash: bytes
    address: str
    received: int


class Publisher:
    ISSUED_KEEP = 8 * 24 * 60 * 60 // 1500 + 8   # a week of periods plus P2Pool's ring

    def __init__(self, config: Config, store: PeerStore, db: BlobDB, clock=time.time):
        self.config = config
        self.store = store
        self.db = db
        self.clock = clock
        self.body: bytes | None = None
        self.body_since: float = 0.0
        self.address: str = ""
        self.solutions: list[Solution] = []
        self._issued: OrderedDict[bytes, bytes] = OrderedDict()

    # -- curation, spec §4.1 ------------------------------------------------

    def curate(self, now: float | None = None) -> list[tuple[str, int]]:
        now = self.clock() if now is None else now
        min_age = self.config.anchor_min_age * 86400
        cands = []
        for e in self.store.get_transpeers():
            if is_reserved(e.addr):
                continue
            # 1. History: old enough, has answered, and reachable now (a
            # body may change early only because an entry died).
            if e.first_seen <= 0 or now - e.first_seen < min_age or e.answered < 1 or not e.alive:
                continue
            # 2. Quality: only judged once there are enough verifications.
            t = self.store.get_source_trust(e.addr)
            total = t.verified_alive + t.verified_dead
            if total >= QUALITY_MIN_SAMPLES and t.verified_alive / total < QUALITY_MIN_RATE:
                continue
            # 3. Native: only judged when the probe has run.
            if e.native and not any(e.native.values()):
                continue
            cands.append(e)
        # 4. Diversity: one per /16, highest answered wins.
        by16: dict[str, object] = {}
        for e in sorted(cands, key=lambda e: -e.answered):
            key = str(ipaddress.ip_network(f"{e.addr}/16", strict=False))
            by16.setdefault(key, e)
        chosen = sorted(by16.values(), key=lambda e: -e.answered)
        # 5. Continuity: bounded share of entries with no committed history.
        if self.db.blob_count() > 0:
            cont = [e for e in chosen if self.db.has_body_entry(e.addr, e.port)]
            new = [e for e in chosen if not self.db.has_body_entry(e.addr, e.port)]
            allow = int(self.config.anchor_max_new * len(chosen))
            chosen = sorted(cont + new[:allow], key=lambda e: -e.answered)
        # 6. Faithfulness (spec §9): not available until slice 3 (challenges).
        chosen = sorted(chosen, key=lambda e: -e.answered)[:MAX_ENTRIES]
        return sorted(((e.addr, e.port) for e in chosen),
                      key=lambda a: (int(ipaddress.IPv4Address(a[0])), a[1]))

    # -- body and rotation ---------------------------------------------------

    def _entries_alive(self) -> bool:
        if self.body is None:
            return True
        for addr, port in decode_blob(self.body).entries:
            e = self.store.get_transpeer(addr, port)
            if e is None or not e.alive:
                return False
        return True

    def refresh(self, now: float | None = None) -> bool:
        now = self.clock() if now is None else now
        due = (self.body is None or now - self.body_since >= BODY_MAX_AGE
               or not self._entries_alive())
        if not due:
            return False
        entries = self.curate(now)
        if not entries:
            return False
        body = list_body(encode_blob(self.config.anchor_chain, 0, entries))
        if body == self.body:
            return False
        self.body = body
        self.body_since = now
        return True

    def current(self, now: float | None = None):
        now = self.clock() if now is None else now
        if self.body is None:
            return None
        blob = with_period(self.body, period_of(now))
        h = blob_hash(blob)
        if h not in self._issued:
            self._issued[h] = blob
            while len(self._issued) > self.ISSUED_KEEP:
                self._issued.popitem(last=False)
        return h, blob

    def lookup(self, aux_hash: bytes) -> bytes | None:
        return self._issued.get(aux_hash)

    def record_solution(self, sol: Solution) -> None:
        self.solutions.append(sol)
