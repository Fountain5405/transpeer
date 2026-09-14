"""Peer and transpeer storage with SQLite persistence."""

import asyncio
import base64
import ipaddress
import random
import time
from dataclasses import dataclass, field

import aiosqlite

from .config import (
    Config, PEER_PRUNE_AGE, TRANSPEER_PRUNE_AGE,
    MAX_TRANSPEERS_TRACKED, MAX_PEERS_PER_NETWORK,
)


@dataclass
class Peer:
    network: str
    addr: str
    port: int
    last_seen: int = 0
    sources: int = 1
    verified: bool = False
    source_addr: str = ""  # transpeer that gave us this peer
    # Buckets of the transpeers that reported this peer, as observed by us.
    # Only maintained under --vouchers; never sent on the wire.
    vouchers: set = field(default_factory=set)
    # Subset of `vouchers` whose transpeer verifiably runs this peer's
    # network (its host answered on the network's P2P port). Only
    # maintained under --native-vouchers.
    native_vouchers: set = field(default_factory=set)
    # PoW proof
    nonce: bytes = b""
    effort: int = 0
    solution: bytes = b""
    timestamp_bucket: int = 0

    @property
    def key(self) -> str:
        return f"{self.network}:{self.addr}:{self.port}"

    def to_dict(self) -> dict:
        d = {
            "addr": self.addr,
            "port": self.port,
            "last_seen": self.last_seen,
            "sources": self.sources,
        }
        if self.nonce:
            d["proof"] = {
                "nonce": base64.b64encode(self.nonce).decode(),
                "effort": self.effort,
                "solution": base64.b64encode(self.solution).decode(),
                "timestamp_bucket": self.timestamp_bucket,
            }
        return d

    @classmethod
    def from_dict(cls, network: str, data: dict) -> "Peer":
        proof = data.get("proof", {})
        return cls(
            network=network,
            addr=data["addr"],
            port=data["port"],
            last_seen=data.get("last_seen", 0),
            sources=data.get("sources", 1),
            nonce=base64.b64decode(proof["nonce"]) if proof.get("nonce") else b"",
            effort=proof.get("effort", 0),
            solution=base64.b64decode(proof["solution"]) if proof.get("solution") else b"",
            timestamp_bucket=proof.get("timestamp_bucket", 0),
        )


@dataclass
class TranspeerEntry:
    addr: str
    port: int
    networks: list[str] = field(default_factory=list)
    last_seen: int = 0
    node_id: str = ""
    last_queried: int = 0  # Timestamp of last successful query (for rotation)
    answered: int = 0  # Queries this transpeer has answered; feeds the tried table
    alive: bool = False  # Did the most recent query get an answer?
    # network -> True/False: did this transpeer's host answer on that
    # network's P2P port? Filled by the native probe under --native-vouchers.
    native: dict = field(default_factory=dict)
    first_seen: int = 0
    # Chain-anchored publication (spec §7, §9): seeded/re-seeded from
    # weights (published) or marked after repeated faithfulness-challenge
    # failures (unfaithful). Both default off; set by the reader.
    published: bool = False
    unfaithful: bool = False

    @property
    def key(self) -> str:
        return f"{self.addr}:{self.port}"

    def to_dict(self) -> dict:
        return {
            "addr": self.addr,
            "port": self.port,
            "networks": self.networks,
            "last_seen": self.last_seen,
            "first_seen": self.first_seen,
            "published": self.published,
            "unfaithful": self.unfaithful,
        }


# Per-source transpeer limits
BASE_PEERS_PER_SOURCE = 50  # Initial cap for a new source transpeer
VERIFY_THRESHOLD = 0.8  # 80% alive to earn a cap increase
DEAD_PEER_MAX_AGE = 3600  # Prune unverified/dead peers after 1 hour
DEAD_PEER_COOLDOWN = 1800  # Don't re-accept a dead peer for 30 minutes
MAX_TRANSPEERS_PER_SUBNET = 3  # Max transpeers accepted from same /16 subnet
TRIED_THRESHOLD = 2  # Answered queries before an entry counts as tried
# A hand-off reserve pick must carry at least this many vouchers. Without a
# floor, an attacker with K prefixes could split them into K one-bucket
# clusters and buy K reserve slots it would never earn by rank; with it,
# each reserve slot costs the attacker this many prefixes.
RESERVE_MIN_VOUCHERS = 2


@dataclass
class SourceTrust:
    """Tracks per-source acceptance cap based on verification results."""
    cap: int = BASE_PEERS_PER_SOURCE
    accepted: int = 0
    verified_alive: int = 0
    verified_dead: int = 0

    @property
    def total_verified(self) -> int:
        return self.verified_alive + self.verified_dead

    @property
    def alive_rate(self) -> float:
        if self.total_verified == 0:
            return 0.0
        return self.verified_alive / self.total_verified

    def record_verification(self, alive: bool):
        if alive:
            self.verified_alive += 1
        else:
            self.verified_dead += 1

    def maybe_expand(self):
        """Expand cap if verification rate exceeds threshold."""
        if self.total_verified >= 10 and self.alive_rate >= VERIFY_THRESHOLD:
            self.cap += BASE_PEERS_PER_SOURCE
            # Reset counters for next evaluation period
            self.verified_alive = 0
            self.verified_dead = 0

    def maybe_contract(self):
        """Contract cap if verification rate drops below threshold."""
        if self.total_verified >= 10 and self.alive_rate < VERIFY_THRESHOLD:
            self.cap = BASE_PEERS_PER_SOURCE
            self.verified_alive = 0
            self.verified_dead = 0


class PeerStore:
    def __init__(self, config: Config):
        self.config = config
        self._peers: dict[str, Peer] = {}  # key -> Peer
        self._transpeers: dict[str, TranspeerEntry] = {}  # key -> TranspeerEntry
        self._candidates: dict[str, int] = {}  # addr -> timestamp (IPs that queried us)
        self._dead_peers: dict[str, int] = {}  # key -> timestamp of death (cooldown)
        self._source_trust: dict[str, SourceTrust] = {}  # source_addr -> trust info
        self._db: aiosqlite.Connection | None = None
        self._lock = asyncio.Lock()

    async def init(self):
        if self.config.in_memory:
            return
        self._db = await aiosqlite.connect(str(self.config.db_path))
        await self._db.executescript("""
            CREATE TABLE IF NOT EXISTS peers (
                network TEXT NOT NULL,
                addr TEXT NOT NULL,
                port INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                sources INTEGER NOT NULL DEFAULT 1,
                verified INTEGER NOT NULL DEFAULT 0,
                nonce BLOB,
                effort INTEGER NOT NULL DEFAULT 0,
                solution BLOB,
                timestamp_bucket INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (network, addr, port)
            );
            CREATE TABLE IF NOT EXISTS transpeers (
                addr TEXT NOT NULL,
                port INTEGER NOT NULL,
                networks TEXT NOT NULL DEFAULT '',
                last_seen INTEGER NOT NULL,
                PRIMARY KEY (addr, port)
            );
        """)
        await self._db.commit()
        async with self._db.execute("PRAGMA table_info(transpeers)") as cur:
            columns = {row[1] async for row in cur}
        if "first_seen" not in columns:
            await self._db.execute(
                "ALTER TABLE transpeers ADD COLUMN first_seen INTEGER NOT NULL DEFAULT 0"
            )
            await self._db.commit()
        if "published" not in columns:
            await self._db.execute(
                "ALTER TABLE transpeers ADD COLUMN published INTEGER NOT NULL DEFAULT 0"
            )
            await self._db.commit()
        if "unfaithful" not in columns:
            await self._db.execute(
                "ALTER TABLE transpeers ADD COLUMN unfaithful INTEGER NOT NULL DEFAULT 0"
            )
            await self._db.commit()
        await self._load()

    async def _load(self):
        async with self._db.execute("SELECT * FROM peers") as cur:
            async for row in cur:
                peer = Peer(
                    network=row[0], addr=row[1], port=row[2],
                    last_seen=row[3], sources=row[4], verified=bool(row[5]),
                    nonce=row[6] or b"", effort=row[7],
                    solution=row[8] or b"", timestamp_bucket=row[9],
                )
                self._peers[peer.key] = peer

        async with self._db.execute("SELECT * FROM transpeers") as cur:
            async for row in cur:
                entry = TranspeerEntry(
                    addr=row[0], port=row[1],
                    networks=row[2].split(",") if row[2] else [],
                    last_seen=row[3],
                    first_seen=row[4] or row[3],
                    published=bool(row[5]) if len(row) > 5 else False,
                    unfaithful=bool(row[6]) if len(row) > 6 else False,
                )
                self._transpeers[entry.key] = entry

    async def close(self):
        if self._db and not self.config.in_memory:
            await self._db.close()

    # -- Peers --

    def _trust_key(self, source_addr: str) -> str:
        """Per-source trust is keyed by bucket under --vouchers, so every
        transpeer in one subnet shares a single acceptance cap."""
        if self.config.vouchers:
            return self._bucket_of(source_addr)
        return source_addr

    def get_source_trust(self, source_addr: str) -> SourceTrust:
        key = self._trust_key(source_addr)
        if key not in self._source_trust:
            self._source_trust[key] = SourceTrust()
        return self._source_trust[key]

    async def add_peer(self, peer: Peer, source_addr: str = "") -> bool:
        """Add or update a peer. Returns True if new."""
        async with self._lock:
            # Reject peers on the dead cooldown list
            now = int(time.time())
            death_time = self._dead_peers.get(peer.key)
            if death_time and now - death_time < DEAD_PEER_COOLDOWN:
                return False

            # Enforce per-source ramp-up cap
            if source_addr:
                trust = self.get_source_trust(source_addr)
                if peer.key not in self._peers and trust.accepted >= trust.cap:
                    return False

            # Enforce per-network cap (avoid unbounded growth at scale)
            if peer.key not in self._peers:
                net_count = sum(1 for p in self._peers.values()
                                if p.network == peer.network)
                if net_count >= MAX_PEERS_PER_NETWORK:
                    return False

            existing = self._peers.get(peer.key)
            if existing:
                if self.config.vouchers:
                    if source_addr:
                        existing.vouchers.add(self._bucket_of(source_addr))
                        if self._source_is_native(source_addr, peer.network):
                            existing.native_vouchers.add(self._bucket_of(source_addr))
                    existing.sources = max(1, len(existing.vouchers))
                else:
                    existing.sources = max(existing.sources, peer.sources)
                if peer.last_seen > existing.last_seen:
                    existing.last_seen = peer.last_seen
                    existing.nonce = peer.nonce
                    existing.effort = peer.effort
                    existing.solution = peer.solution
                    existing.timestamp_bucket = peer.timestamp_bucket
                await self._save_peer(existing)
                return False
            else:
                if source_addr:
                    peer.source_addr = source_addr
                if self.config.vouchers:
                    # Trust what we saw, not the remote's claimed count.
                    peer.vouchers = (
                        {self._bucket_of(source_addr)} if source_addr else {"local"}
                    )
                    if not source_addr:
                        peer.native_vouchers = {"local"}
                    elif self._source_is_native(source_addr, peer.network):
                        peer.native_vouchers = {self._bucket_of(source_addr)}
                    peer.sources = 1
                self._peers[peer.key] = peer
                await self._save_peer(peer)
                if source_addr:
                    self.get_source_trust(source_addr).accepted += 1
                return True

    async def mark_verified(self, network: str, addr: str, port: int):
        key = f"{network}:{addr}:{port}"
        async with self._lock:
            peer = self._peers.get(key)
            if peer:
                peer.verified = True
                peer.last_seen = int(time.time())
                await self._save_peer(peer)
                if peer.source_addr:
                    trust = self.get_source_trust(peer.source_addr)
                    trust.record_verification(alive=True)
                    trust.maybe_expand()

    async def mark_dead(self, network: str, addr: str, port: int):
        key = f"{network}:{addr}:{port}"
        async with self._lock:
            peer = self._peers.get(key)
            if peer:
                # Record dead verification in source trust
                if peer.source_addr:
                    trust = self.get_source_trust(peer.source_addr)
                    trust.record_verification(alive=False)
                    trust.maybe_contract()

                if peer.verified:
                    # Previously verified peer went offline — give it a chance
                    peer.sources = max(0, peer.sources - 1)
                    peer.verified = False
                    await self._save_peer(peer)
                else:
                    # Never verified — remove immediately, add to cooldown
                    del self._peers[key]
                    self._dead_peers[key] = int(time.time())
                    if self._db:
                        await self._db.execute(
                            "DELETE FROM peers WHERE network=? AND addr=? AND port=?",
                            (network, addr, port),
                        )
                        await self._db.commit()

    def _source_is_native(self, source_addr: str, network: str) -> bool:
        """Under --native-vouchers, a reporting transpeer counts as native
        for a network when its host answered a probe on that network's P2P
        port. Claims are not consulted; only probe results are."""
        if not self.config.native_vouchers:
            return False
        return any(
            t.native.get(network, False)
            for t in self._transpeers.values() if t.addr == source_addr
        )

    def set_native(self, addr: str, port: int, network: str, ok: bool):
        entry = self._transpeers.get(f"{addr}:{port}")
        if entry is not None:
            entry.native[network] = ok

    def native_transpeer_count(self) -> int:
        return sum(1 for t in self._transpeers.values() if any(t.native.values()))

    def _rank_key(self, p: Peer):
        if self.config.native_vouchers:
            return (len(p.native_vouchers), len(p.vouchers), p.verified, p.last_seen)
        return (len(p.vouchers), p.verified, p.last_seen)

    def get_peers(self, network: str, verified_only: bool = True,
                  top: int | None = None) -> list[Peer]:
        """Peers for a network, best first.

        Under --vouchers the order is by independent corroboration: the peer
        the most distinct subnets agree on is the one the daemon should try
        first; under --native-vouchers, corroboration by transpeers that
        verifiably run the network outranks the rest. With `top` set and
        --handoff-reserve K, the last K of the first `top` entries are
        chosen for reporter diversity instead (see `_represent`), so the
        list a daemon receives is never sourced from one reporter cluster
        alone.
        """
        peers = [
            p for p in self._peers.values()
            if p.network == network and (not verified_only or p.verified)
        ]
        if self.config.vouchers:
            peers.sort(key=self._rank_key, reverse=True)
            if top and self.config.handoff_reserve > 0:
                peers, _ = self._represent(peers, top, self.config.handoff_reserve)
        return peers

    def _represent(self, ranked: list[Peer], top: int, reserve: int
                   ) -> tuple[list[Peer], int]:
        """Reserve `reserve` of the first `top` slots for reporter diversity.

        The first `top - reserve` slots keep the ranking. The reporter
        buckets that vouched for none of those peers are then visited in
        random order, and each contributes its best-ranked peer, skipping
        buckets an earlier pick already covered. Displaced peers follow.

        A coordinated attacker whose fakes fill the ranked slots has, by
        construction, not vouched for the honest peers, so every honest
        reporter bucket is unrepresented and the reserve goes to honest
        peers. The attacker can dilute the reserve only by adding
        reporter buckets that vouch for nothing in the ranked head, which
        costs prefixes; splitting into more buckets than the honest side
        buys them a proportional share, never the whole list. A pick must
        carry RESERVE_MIN_VOUCHERS vouchers, so below the crossover a
        small attacker cannot turn each stray prefix into a slot.

        Returns the reordered list and the number of unrepresented buckets
        before the pass, which is the split signal an operator would alarm
        on.
        """
        head = ranked[:max(0, top - reserve)]
        represented: set = set()
        for p in head:
            represented |= p.vouchers
        all_buckets = {b for p in ranked for b in p.vouchers if b != "local"}
        unrep = sorted(b for b in all_buckets if b not in represented)
        n_unrep = len(unrep)
        random.shuffle(unrep)
        chosen = {p.key for p in head}
        picks: list[Peer] = []
        for b in unrep:
            if len(picks) >= reserve:
                break
            if b in represented:
                continue
            cand = next((p for p in ranked
                         if b in p.vouchers and p.key not in chosen
                         and len(p.vouchers) >= RESERVE_MIN_VOUCHERS), None)
            if cand is None:
                continue
            picks.append(cand)
            chosen.add(cand.key)
            represented |= cand.vouchers
        rest = [p for p in ranked if p.key not in chosen]
        return head + picks + rest, n_unrep

    def handoff_unrepresented(self, network: str, top: int) -> int:
        """Number of reporter buckets with no peer in the ranked head of the
        hand-off list (before the reserve pass). Zero when one cluster of
        reporters accounts for the whole head, or when there is no reserve."""
        if not (self.config.vouchers and self.config.handoff_reserve > 0):
            return 0
        peers = sorted(
            (p for p in self._peers.values() if p.network == network),
            key=self._rank_key, reverse=True,
        )
        _, n = self._represent(peers, top, self.config.handoff_reserve)
        return n

    def get_all_networks(self) -> list[str]:
        return list({p.network for p in self._peers.values()})

    def peer_count(self, network: str) -> int:
        return len([p for p in self._peers.values() if p.network == network and p.verified])

    async def prune_stale(self):
        now = int(time.time())
        async with self._lock:
            stale = [
                key for key, p in self._peers.items()
                if (now - p.last_seen > PEER_PRUNE_AGE and p.sources <= 0)
                or (not p.verified and now - p.last_seen > DEAD_PEER_MAX_AGE)
            ]
            for key in stale:
                del self._peers[key]

            stale_tp = [
                key for key, t in self._transpeers.items()
                if now - t.last_seen > TRANSPEER_PRUNE_AGE
            ]
            for key in stale_tp:
                del self._transpeers[key]

            # Clean up expired dead peer cooldowns
            expired_dead = [
                key for key, ts in self._dead_peers.items()
                if now - ts > DEAD_PEER_COOLDOWN
            ]
            for key in expired_dead:
                del self._dead_peers[key]

            if self._db and (stale or stale_tp):
                for key in stale:
                    parts = key.split(":")
                    await self._db.execute(
                        "DELETE FROM peers WHERE network=? AND addr=? AND port=?",
                        (parts[0], parts[1], int(parts[2])),
                    )
                for key in stale_tp:
                    parts = key.split(":")
                    await self._db.execute(
                        "DELETE FROM transpeers WHERE addr=? AND port=?",
                        (parts[0], int(parts[1])),
                    )
                await self._db.commit()

    async def _save_peer(self, peer: Peer):
        if not self._db:
            return
        await self._db.execute("""
            INSERT OR REPLACE INTO peers
            (network, addr, port, last_seen, sources, verified, nonce, effort, solution, timestamp_bucket)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            peer.network, peer.addr, peer.port, peer.last_seen,
            peer.sources, int(peer.verified), peer.nonce, peer.effort,
            peer.solution, peer.timestamp_bucket,
        ))
        await self._db.commit()

    # -- Transpeers --

    def _bucket_of(self, addr: str) -> str:
        """Diversity bucket an address belongs to: its /N prefix, N from config.

        /16 in production. Simulations use a longer prefix so a small scan
        range can still hold many distinct buckets.
        """
        prefix = self.config.subnet_prefix
        try:
            n = int(ipaddress.IPv4Address(addr))
        except (ipaddress.AddressValueError, ValueError):
            return addr
        if prefix <= 0:
            return "0"
        mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
        return f"{ipaddress.IPv4Address(n & mask)}/{prefix}"

    def _transpeers_by_bucket(self) -> dict[str, list[TranspeerEntry]]:
        buckets: dict[str, list[TranspeerEntry]] = {}
        for t in self._transpeers.values():
            buckets.setdefault(self._bucket_of(t.addr), []).append(t)
        return buckets

    def _count_transpeers_in_bucket(self, bucket: str) -> int:
        return sum(
            1 for t in self._transpeers.values()
            if self._bucket_of(t.addr) == bucket
        )

    def transpeer_bucket_count(self) -> int:
        return len({self._bucket_of(t.addr) for t in self._transpeers.values()})

    async def add_transpeer(self, entry: TranspeerEntry, gossiped: bool = False) -> bool:
        """Add or update a transpeer. Returns True if new.

        Args:
            gossiped: True if this transpeer was learned from another transpeer's
                /transpeers endpoint. False if discovered directly by scanning
                or by probing a candidate that contacted us.

        Default policy: the per-bucket limit applies to gossiped entries only,
        on the theory that direct discoveries are diverse by construction.
        That does not hold for the candidate path, where any IP that sends
        one request gets probed and admitted, so a flood from a single
        subnet can fill the store. Under --bucketed the limit applies to
        every path, and eviction targets the most crowded bucket instead of
        the globally oldest entry, so re-announcing cannot push honest
        transpeers out.
        """
        async with self._lock:
            existing = self._transpeers.get(entry.key)
            if existing:
                existing.last_seen = max(existing.last_seen, entry.last_seen)
                if entry.networks:
                    existing.networks = entry.networks
                await self._save_transpeer(existing)
                return False

            entry.first_seen = entry.last_seen or int(time.time())

            bucket = self._bucket_of(entry.addr)
            if gossiped or self.config.bucketed:
                if self._count_transpeers_in_bucket(bucket) >= MAX_TRANSPEERS_PER_SUBNET:
                    return False

            # Enforce total transpeer cap. When full, make room.
            if len(self._transpeers) >= MAX_TRANSPEERS_TRACKED:
                evict_key = self._pick_eviction(bucket)
                if evict_key is None:
                    return False
                del self._transpeers[evict_key]
                if self._db:
                    parts = evict_key.split(":")
                    await self._db.execute(
                        "DELETE FROM transpeers WHERE addr=? AND port=?",
                        (parts[0], int(parts[1])),
                    )

            self._transpeers[entry.key] = entry
            await self._save_transpeer(entry)
            return True

    def _pick_eviction(self, incoming_bucket: str) -> str | None:
        """Choose which transpeer to drop when the store is full.

        Default: the least recently seen entry. Bucketed: the least recently
        seen member of the most populated bucket, never the newcomer's own
        bucket while another is tied for fullest. If the newcomer's bucket is
        the unique fullest, the newcomer is refused instead, so a flood from
        one subnet only ever displaces itself.
        """
        # Tried entries are off the table unless nothing else is left.
        pool = {k: t for k, t in self._transpeers.items() if not self.is_tried(t)}
        if not pool:
            pool = dict(self._transpeers)
        if not self.config.bucketed:
            return min(pool.keys(), key=lambda k: pool[k].last_seen)
        buckets: dict[str, list[TranspeerEntry]] = {}
        for t in pool.values():
            buckets.setdefault(self._bucket_of(t.addr), []).append(t)
        max_size = max(len(m) for m in buckets.values())
        fullest = [b for b, m in buckets.items()
                   if len(m) == max_size and b != incoming_bucket]
        if not fullest:
            return None
        victim = min(buckets[random.choice(fullest)], key=lambda t: t.last_seen)
        return victim.key

    def get_transpeers(self) -> list[TranspeerEntry]:
        return list(self._transpeers.values())

    def get_transpeer(self, addr: str, port: int) -> TranspeerEntry | None:
        return self._transpeers.get(f"{addr}:{port}")

    def get_transpeers_for_query(self, limit: int) -> list[TranspeerEntry]:
        """Return up to `limit` transpeers to query this cycle.

        Default: oldest-queried first, so rotation eventually reaches every
        entry. Bucketed: visit buckets in random order taking the oldest-
        queried member of each, wrapping around until the batch is full. An
        attacker's share of the batch is then their share of buckets, not of
        entries.
        """
        if not self.config.bucketed:
            return sorted(
                self._transpeers.values(),
                key=lambda t: t.last_queried,
            )[:limit]
        queues = [
            sorted(members, key=lambda t: t.last_queried)
            for members in self._transpeers_by_bucket().values()
        ]
        random.shuffle(queues)
        picked: list[TranspeerEntry] = []
        while queues and len(picked) < limit:
            remaining = []
            for q in queues:
                if len(picked) >= limit:
                    break
                picked.append(q.pop(0))
                if q:
                    remaining.append(q)
            queues = remaining
        return picked

    def mark_queried(self, addr: str, port: int, answered: bool = False):
        """Record that we just queried a transpeer, and whether it answered."""
        key = f"{addr}:{port}"
        entry = self._transpeers.get(key)
        if entry:
            entry.last_queried = int(time.time())
            entry.alive = bool(answered)
            if answered:
                entry.answered += 1

    def live_transpeer_count(self) -> int:
        """Transpeers whose most recent query was answered. The scanner
        stops once this reaches the configured target: a node that has
        found a few live transpeers can learn the rest from them."""
        return sum(1 for t in self._transpeers.values() if t.alive)

    def is_tried(self, entry: TranspeerEntry) -> bool:
        """Under --tried-table an entry that has answered at least
        TRIED_THRESHOLD queries is protected from eviction by newcomers.
        An attacker can only displace what has never proven itself."""
        return self.config.tried_table and entry.answered >= TRIED_THRESHOLD

    def get_transpeers_for_gossip(self, limit: int,
                                  exclude_addr: str = "") -> list[TranspeerEntry]:
        """Return up to `limit` transpeers to share via /transpeers.

        Default: sample weighted toward recently-seen transpeers so we gossip
        about live ones. Bucketed: pick a bucket uniformly, then a recent
        member of it, so gossip carries bucket diversity rather than raw
        population. Excludes the requester's own IP.
        """
        candidates = [
            t for t in self._transpeers.values()
            if t.addr != exclude_addr
        ]
        if len(candidates) <= limit:
            return candidates
        now = int(time.time())

        def recency(t):
            return max(1, 86400 - (now - t.last_seen))

        if not self.config.bucketed:
            weights = [recency(t) for t in candidates]
            return random.choices(candidates, weights=weights, k=limit)

        buckets: dict[str, list[TranspeerEntry]] = {}
        for t in candidates:
            buckets.setdefault(self._bucket_of(t.addr), []).append(t)
        keys = list(buckets)
        picked: list[TranspeerEntry] = []
        seen: set[str] = set()
        # Bounded attempts: with few buckets and many slots, draws repeat.
        for _ in range(limit * 4):
            if len(picked) >= limit:
                break
            members = buckets[random.choice(keys)]
            t = random.choices(members, weights=[recency(m) for m in members], k=1)[0]
            if t.key not in seen:
                seen.add(t.key)
                picked.append(t)
        return picked

    def snapshot(self, networks: list[str] | None = None, top: int = 20) -> dict:
        """Compact store composition for STORE_SNAPSHOT logging.

        daemon_view lists, per network, the source of each of the first `top`
        peers get_peers would hand out. Unverified peers are included because
        simulations run with --no-verify.
        """
        by_source: dict[str, int] = {}
        hist: dict[int, int] = {}
        for p in self._peers.values():
            src = p.source_addr or "local"
            by_source[src] = by_source.get(src, 0) + 1
            n = len(p.vouchers) if self.config.vouchers else p.sources
            hist[n] = hist.get(n, 0) + 1
        def depth(p):
            return len(p.vouchers) if self.config.vouchers else p.sources

        daemon_view = {
            net: [f"{p.source_addr or 'local'}:{depth(p)}"
                  for p in self.get_peers(net, verified_only=False, top=top)[:top]]
            for net in (networks or [])
        }
        unrepresented = {
            net: self.handoff_unrepresented(net, top) for net in (networks or [])
        }
        return {
            "transpeers": len(self._transpeers),
            "buckets": self.transpeer_bucket_count(),
            "transpeer_addrs": sorted(t.addr for t in self._transpeers.values()),
            "peers": len(self._peers),
            "peer_sources": by_source,
            "voucher_hist": hist,
            "daemon_view": daemon_view,
            "tried_addrs": sorted(t.addr for t in self._transpeers.values()
                                  if self.is_tried(t)),
            "unrepresented": unrepresented,
            "native_transpeers": self.native_transpeer_count(),
        }

    async def _save_transpeer(self, entry: TranspeerEntry):
        if not self._db:
            return
        await self._db.execute("""
            INSERT OR REPLACE INTO transpeers
                (addr, port, networks, last_seen, first_seen, published, unfaithful)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (entry.addr, entry.port, ",".join(entry.networks), entry.last_seen,
              entry.first_seen, int(entry.published), int(entry.unfaithful)))
        await self._db.commit()

    async def set_published(self, addr: str, port: int, flag: bool) -> None:
        """Mark a transpeer published/unpublished (spec §7): set by the
        reader when it seeds or re-seeds the store from weights."""
        async with self._lock:
            entry = self._transpeers.get(f"{addr}:{port}")
            if entry is None:
                return
            entry.published = flag
            await self._save_transpeer(entry)

    async def set_unfaithful(self, addr: str, port: int, flag: bool) -> None:
        """Mark a transpeer unfaithful/faithful (spec §9)."""
        async with self._lock:
            entry = self._transpeers.get(f"{addr}:{port}")
            if entry is None:
                return
            entry.unfaithful = flag
            await self._save_transpeer(entry)

    # -- Candidates (IPs that queried us, potential transpeers) --

    def add_candidate(self, addr: str):
        self._candidates[addr] = int(time.time())

    def pop_candidates(self, max_count: int = 50) -> list[str]:
        addrs = list(self._candidates.keys())[:max_count]
        for addr in addrs:
            del self._candidates[addr]
        return addrs
