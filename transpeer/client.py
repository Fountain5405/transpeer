"""HTTP client for fetching data from other transpeers."""

import asyncio
import base64
import logging
import time

import aiohttp

from .config import Config, PROTOCOL_VERSION, TRANSPEER_PORT
from .peerstore import Peer, PeerStore, TranspeerEntry
from .pow import (
    verify as pow_verify, verify_simulated as pow_verify_sim,
    solve_handshake, HANDSHAKE_BUCKET_SECS,
)

log = logging.getLogger(__name__)


class HandshakeProofCache:
    """Cache solved handshake proofs per (server_ip, server_node_id).

    A proof is valid for the full bucket (~1 hour), so we reuse across
    many requests to the same server.
    """
    def __init__(self):
        self._cache: dict[tuple[str, str, int], str] = {}

    def get(self, server_ip: str, node_id: str) -> str | None:
        if not node_id:
            return None
        bucket = int(time.time()) // HANDSHAKE_BUCKET_SECS
        return self._cache.get((server_ip, node_id, bucket))

    def put(self, server_ip: str, node_id: str, bucket: int, header: str):
        self._cache[(server_ip, node_id, bucket)] = header
        # Garbage collect expired entries
        cutoff = bucket - 1
        for k in list(self._cache.keys()):
            if k[2] < cutoff:
                del self._cache[k]


class TranspeerClient:
    def __init__(self, config: Config, store: PeerStore):
        self.config = config
        self.store = store
        self._handshake_cache = HandshakeProofCache()
        # Client's own IP for handshake PoW binding. In sim mode we can't
        # easily know it; the server is authoritative (it uses request.remote).
        # We construct proofs for whatever the server sees; we don't need to
        # know our own IP here.

    async def _solve_handshake_for(self, server_ip: str, effort: int,
                                   node_id: str, client_ip_hint: str = "") -> str:
        """Solve a handshake PoW and return the header value.

        The server uses request.remote as the client_ip. We don't know that
        from the client side in general, so we solve for the IP the server
        will see by having a round-trip first (in practice we'll learn it
        from the 402 response — but for now we solve for the server's view).

        Note: This requires the server to tell us the IP it sees. We encode
        that assumption by having the caller pass a hint or by solving
        speculatively and letting the server reject if wrong.
        """
        simulated = self.config.sim_pow
        # If we have no hint, we can't solve a binding PoW. The caller must
        # get the hint from a 402 response first (server includes it).
        nonce, solution, bucket = solve_handshake(
            client_ip_hint, node_id, effort, simulated=simulated,
        )
        return f"{bucket}:{base64.b64encode(nonce).decode()}:{base64.b64encode(solution).decode()}"

    async def _get_with_pow(self, session: aiohttp.ClientSession, url: str,
                            server_ip: str) -> dict | None:
        """GET with transparent handshake PoW handling.

        Returns parsed JSON on success, None on failure.
        """
        headers = {}
        # Try any cached proof for this server (we may not know node_id yet;
        # if not cached, we'll get a 402 and cache then)
        for (srv, _, _), hdr in self._handshake_cache._cache.items():
            if srv == server_ip:
                headers["X-Transpeer-PoW"] = hdr
                break

        try:
            async with session.get(url, headers=headers) as resp:
                if resp.status == 402:
                    # Handshake PoW required — solve and retry
                    challenge_info = await resp.json()
                    effort = challenge_info.get("effort", 0)
                    node_id = challenge_info.get("node_id", "")
                    # Server echoes the IP it saw us at, so we can solve the
                    # correct challenge
                    client_ip_hint = (
                        challenge_info.get("client_ip")
                        or resp.headers.get("X-Transpeer-Client-Ip", "")
                    )
                    if effort <= 0 or not node_id or not client_ip_hint:
                        return None

                    log.info("Handshake PoW required by %s: effort=%d", server_ip, effort)
                    pow_header = await self._solve_handshake_for(
                        server_ip, effort, node_id, client_ip_hint,
                    )
                    bucket = int(pow_header.split(":", 1)[0])
                    self._handshake_cache.put(server_ip, node_id, bucket, pow_header)

                    # Retry with PoW
                    async with session.get(
                        url, headers={"X-Transpeer-PoW": pow_header}
                    ) as retry_resp:
                        if retry_resp.status != 200:
                            return None
                        return await retry_resp.json()
                elif resp.status != 200:
                    return None
                return await resp.json()
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as e:
            log.debug("Request to %s failed: %s", url, e)
            return None

    async def probe_transpeer(self, addr: str, port: int = TRANSPEER_PORT) -> TranspeerEntry | None:
        """Probe an IP to check if it's a transpeer. Returns entry if valid.

        /transpeer is always free (no handshake PoW required).
        """
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
                data = await self._get_with_pow(session, url, addr)
                if not data:
                    return []
                peers = []
                for entry in data.get("peers", []):
                    peer = Peer.from_dict(network, entry)
                    if not self.config.no_pow and peer.nonce and peer.solution:
                        vfn = pow_verify_sim if self.config.sim_pow else pow_verify
                        if not vfn(
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
                data = await self._get_with_pow(session, url, addr)
                if not data:
                    return []
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

        updated = await self.probe_transpeer(entry.addr, entry.port)
        if not updated:
            log.info("Transpeer %s:%d unreachable", entry.addr, entry.port)
            return
        await self.store.add_transpeer(updated)

        for network in updated.networks:
            peers = await self.fetch_peers(entry.addr, entry.port, network)
            accepted = 0
            for peer in peers:
                if await self.store.add_peer(peer, source_addr=entry.addr):
                    accepted += 1
            if peers:
                log.info("Got %d peers for %s from %s (%d new)",
                         len(peers), network, entry.addr, accepted)

        new_transpeers = await self.fetch_transpeers(entry.addr, entry.port)
        for tp in new_transpeers:
            await self.store.add_transpeer(tp, gossiped=True)
        if new_transpeers:
            log.info("Got %d transpeers from %s", len(new_transpeers), entry.addr)
