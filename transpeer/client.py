"""HTTP client for fetching data from other transpeers."""

import asyncio
import logging
import time

import aiohttp

from .config import Config, PROTOCOL_VERSION, TRANSPEER_PORT
from .peerstore import Peer, PeerStore, TranspeerEntry
from .pow import verify as pow_verify

log = logging.getLogger(__name__)


class TranspeerClient:
    def __init__(self, config: Config, store: PeerStore):
        self.config = config
        self.store = store

    async def probe_transpeer(self, addr: str, port: int = TRANSPEER_PORT) -> TranspeerEntry | None:
        """Probe an IP to check if it's a transpeer. Returns entry if valid."""
        url = f"http://{addr}:{port}/transpeer"
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5)) as session:
                async with session.get(url) as resp:
                    if resp.status != 200:
                        return None
                    data = await resp.json()
                    if data.get("protocol") != PROTOCOL_VERSION:
                        return None
                    return TranspeerEntry(
                        addr=addr,
                        port=port,
                        networks=data.get("networks", []),
                        last_seen=int(time.time()),
                        node_id=data.get("node_id", ""),
                    )
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError):
            return None

    async def fetch_peers(self, addr: str, port: int, network: str) -> list[Peer]:
        """Fetch peer list for a network from a transpeer."""
        url = f"http://{addr}:{port}/peers/{network}"
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                async with session.get(url) as resp:
                    if resp.status != 200:
                        return []
                    data = await resp.json()
                    peers = []
                    for entry in data.get("peers", []):
                        peer = Peer.from_dict(network, entry)
                        # Verify PoW if proof is present (skip if --no-pow)
                        if not self.config.no_pow and peer.nonce and peer.solution:
                            if not pow_verify(
                                network, peer.addr, peer.port,
                                peer.nonce, peer.effort, peer.solution,
                                peer.timestamp_bucket,
                            ):
                                log.debug("Invalid PoW for %s:%d on %s", peer.addr, peer.port, network)
                                continue
                        peers.append(peer)
                    return peers
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as e:
            log.debug("Failed to fetch peers from %s:%d: %s", addr, port, e)
            return []

    async def fetch_transpeers(self, addr: str, port: int) -> list[TranspeerEntry]:
        """Fetch known transpeers from a transpeer."""
        url = f"http://{addr}:{port}/transpeers"
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                async with session.get(url) as resp:
                    if resp.status != 200:
                        return []
                    data = await resp.json()
                    entries = []
                    for item in data.get("transpeers", []):
                        entries.append(TranspeerEntry(
                            addr=item["addr"],
                            port=item.get("port", TRANSPEER_PORT),
                            networks=item.get("networks", []),
                            last_seen=item.get("last_seen", 0),
                        ))
                    return entries
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as e:
            log.debug("Failed to fetch transpeers from %s:%d: %s", addr, port, e)
            return []

    async def query_transpeer(self, entry: TranspeerEntry):
        """Query a known transpeer for all its data and merge into our store."""
        log.info("Querying transpeer %s:%d", entry.addr, entry.port)

        # Probe to confirm it's still alive and update info
        updated = await self.probe_transpeer(entry.addr, entry.port)
        if not updated:
            log.info("Transpeer %s:%d unreachable", entry.addr, entry.port)
            return
        await self.store.add_transpeer(updated)

        # Fetch peers for each network it serves
        for network in updated.networks:
            peers = await self.fetch_peers(entry.addr, entry.port, network)
            for peer in peers:
                await self.store.add_peer(peer)
            if peers:
                log.info("Got %d peers for %s from %s", len(peers), network, entry.addr)

        # Fetch its transpeer list
        new_transpeers = await self.fetch_transpeers(entry.addr, entry.port)
        for tp in new_transpeers:
            await self.store.add_transpeer(tp)
        if new_transpeers:
            log.info("Got %d transpeers from %s", len(new_transpeers), entry.addr)
