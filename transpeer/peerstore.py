"""Peer and transpeer storage with SQLite persistence."""

import asyncio
import base64
import time
from dataclasses import dataclass, field

import aiosqlite

from .config import Config, PEER_PRUNE_AGE, TRANSPEER_PRUNE_AGE


@dataclass
class Peer:
    network: str
    addr: str
    port: int
    last_seen: int = 0
    sources: int = 1
    verified: bool = False
    source_addr: str = ""  # transpeer that gave us this peer
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

    @property
    def key(self) -> str:
        return f"{self.addr}:{self.port}"

    def to_dict(self) -> dict:
        return {
            "addr": self.addr,
            "port": self.port,
            "networks": self.networks,
            "last_seen": self.last_seen,
        }


# Per-source transpeer limits
BASE_PEERS_PER_SOURCE = 50  # Initial cap for a new source transpeer
VERIFY_THRESHOLD = 0.8  # 80% alive to earn a cap increase
DEAD_PEER_MAX_AGE = 3600  # Prune unverified/dead peers after 1 hour
DEAD_PEER_COOLDOWN = 1800  # Don't re-accept a dead peer for 30 minutes
MAX_TRANSPEERS_PER_SUBNET = 3  # Max transpeers accepted from same /16 subnet


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
                )
                self._transpeers[entry.key] = entry

    async def close(self):
        if self._db and not self.config.in_memory:
            await self._db.close()

    # -- Peers --

    def get_source_trust(self, source_addr: str) -> SourceTrust:
        if source_addr not in self._source_trust:
            self._source_trust[source_addr] = SourceTrust()
        return self._source_trust[source_addr]

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

            existing = self._peers.get(peer.key)
            if existing:
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

    def get_peers(self, network: str, verified_only: bool = True) -> list[Peer]:
        return [
            p for p in self._peers.values()
            if p.network == network and (not verified_only or p.verified)
        ]

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

    @staticmethod
    def _subnet_16(addr: str) -> str:
        """Extract /16 subnet prefix from an IPv4 address."""
        parts = addr.split(".")
        if len(parts) >= 2:
            return f"{parts[0]}.{parts[1]}"
        return addr

    def _count_transpeers_in_subnet(self, subnet: str) -> int:
        return sum(
            1 for t in self._transpeers.values()
            if self._subnet_16(t.addr) == subnet
        )

    async def add_transpeer(self, entry: TranspeerEntry, gossiped: bool = False) -> bool:
        """Add or update a transpeer. Returns True if new.

        Args:
            gossiped: True if this transpeer was learned from another transpeer's
                /transpeers endpoint. False if discovered directly by scanning.
                Subnet diversity limits only apply to gossiped transpeers.
        """
        async with self._lock:
            existing = self._transpeers.get(entry.key)
            if existing:
                existing.last_seen = max(existing.last_seen, entry.last_seen)
                if entry.networks:
                    existing.networks = entry.networks
                await self._save_transpeer(existing)
                return False

            # Enforce /16 subnet diversity limit for gossiped transpeers only.
            # Directly scanned transpeers are inherently diverse (random sampling).
            if gossiped:
                subnet = self._subnet_16(entry.addr)
                if self._count_transpeers_in_subnet(subnet) >= MAX_TRANSPEERS_PER_SUBNET:
                    return False

            self._transpeers[entry.key] = entry
            await self._save_transpeer(entry)
            return True

    def get_transpeers(self) -> list[TranspeerEntry]:
        return list(self._transpeers.values())

    async def _save_transpeer(self, entry: TranspeerEntry):
        if not self._db:
            return
        await self._db.execute("""
            INSERT OR REPLACE INTO transpeers (addr, port, networks, last_seen)
            VALUES (?, ?, ?, ?)
        """, (entry.addr, entry.port, ",".join(entry.networks), entry.last_seen))
        await self._db.commit()

    # -- Candidates (IPs that queried us, potential transpeers) --

    def add_candidate(self, addr: str):
        self._candidates[addr] = int(time.time())

    def pop_candidates(self, max_count: int = 50) -> list[str]:
        addrs = list(self._candidates.keys())[:max_count]
        for addr in addrs:
            del self._candidates[addr]
        return addrs
