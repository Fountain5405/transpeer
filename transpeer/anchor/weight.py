"""Difficulty-weighted, venue-additive weighting (spec §7) and the
coverage rule (§8). Pure functions over verified shares."""

from collections import defaultdict
from dataclasses import dataclass
from typing import Iterable

from . import CHAIN_ID
from .blobdb import BlobDB

BOOTSTRAP_COVERAGE = 0.5


@dataclass(frozen=True)
class Share:
    id: bytes
    venue: str
    height: int
    parent: bytes
    difficulty: int
    timestamp: int
    wallet: str
    aux: dict  # chain id (bytes) -> aux hash (bytes)


def canonical_window(shares: dict, tip: bytes, window: int) -> list:
    """Shares on the fork ending at `tip`, newest first, at most
    `window` of them; stops at a parent that is not known."""
    out = []
    cur = shares.get(tip)
    while cur is not None and len(out) < window:
        out.append(cur)
        cur = shares.get(cur.parent)
    return out


def blob_weights(canonical: Iterable[Share], chain_id: bytes = CHAIN_ID) -> dict:
    w: dict = defaultdict(int)
    for s in canonical:
        h = s.aux.get(chain_id)
        if h is not None:
            w[h] += s.difficulty
    return dict(w)


def publisher_weights(canonical: Iterable[Share], chain_id: bytes = CHAIN_ID) -> dict:
    w: dict = defaultdict(int)
    for s in canonical:
        if chain_id in s.aux:
            w[s.wallet] += s.difficulty
    return dict(w)


def transpeer_weights(bw: dict, db: BlobDB) -> dict:
    w: dict = defaultdict(int)
    for h, weight in bw.items():
        for entry in db.entries_of(h):
            w[entry] += weight
    return dict(w)


def coverage(tagged: int, resolved: int) -> float:
    return resolved / tagged if tagged else 0.0


def bootstrapped(tagged: int, resolved: int) -> bool:
    return coverage(tagged, resolved) >= BOOTSTRAP_COVERAGE
