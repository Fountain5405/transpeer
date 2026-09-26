"""HTTP client for fetching data from other transpeers."""

import asyncio
import base64
import ipaddress
import logging
import time

import aiohttp

from .config import Config, HANDSHAKE_MAX_EFFORT, PROTOCOL_VERSION, TRANSPEER_PORT, user_agent
from .peerstore import Peer, PeerStore, TranspeerEntry
from .pow import (
    verify as pow_verify, verify_simulated as pow_verify_sim,
    solve_handshake, HANDSHAKE_BUCKET_SECS,
)

log = logging.getLogger(__name__)

# Errors a malformed but syntactically valid JSON body can raise while it is
# picked apart. They are treated like a bad response, never like a bug.
_MALFORMED = (ValueError, TypeError, KeyError, AttributeError)
# A transpeer advertising more networks than this is truncated; every name
# costs one /peers request per query cycle.
MAX_NETWORKS_PER_TRANSPEER = 64


def _valid_endpoint(addr, port) -> bool:
    """A remote-supplied address is accepted only as a literal IPv4 address
    with a usable port. Store keys are `net:addr:port` strings split on
    ':', so a hostname or an IPv6 literal would corrupt them, and a name
    would make the verifier resolve DNS on an attacker's behalf."""
    if not isinstance(addr, str) or isinstance(port, bool) or not isinstance(port, int):
        return False
    if not 1 <= port <= 65535:
        return False
    try:
        ipaddress.IPv4Address(addr)
    except ValueError:
        return False
    return True


def _clean_networks(value) -> list[str]:
    if not isinstance(value, list):
        return []
    names = [n for n in value if isinstance(n, str) and 0 < len(n) <= 64]
    return names[:MAX_NETWORKS_PER_TRANSPEER]


def _clamp_time(value, now: int) -> int:
    """Gossiped timestamps are capped at the local clock: a value in the
    future would never age out and would dominate recency weighting."""
    if isinstance(value, bool) or not isinstance(value, int):
        return 0
    return max(0, min(value, now))


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
    def __init__(self, config: Config, store: PeerStore, after_query=None):
        self.config = config
        self.store = store
        self.after_query = after_query
        self._handshake_cache = HandshakeProofCache()
        # Every request identifies the probe: protocol, project URL, and
        # the operator's opt-out contact if set.
        self._headers = {"User-Agent": user_agent(config.contact)}
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
                    if not isinstance(challenge_info, dict):
                        return None
                    effort = challenge_info.get("effort", 0)
                    node_id = challenge_info.get("node_id", "")
                    # Server echoes the IP it saw us at, so we can solve the
                    # correct challenge
                    client_ip_hint = (
                        challenge_info.get("client_ip")
                        or resp.headers.get("X-Transpeer-Client-Ip", "")
                    )
                    if (isinstance(effort, bool) or not isinstance(effort, int)
                            or effort <= 0 or not isinstance(node_id, str) or not node_id
                            or not isinstance(client_ip_hint, str) or not client_ip_hint):
                        return None
                    if effort > HANDSHAKE_MAX_EFFORT:
                        # The solve is synchronous; an unbounded effort would
                        # park the whole node on one remote's say-so.
                        log.warning("Handshake PoW effort %d demanded by %s exceeds the "
                                    "ceiling %d; refusing", effort, server_ip, HANDSHAKE_MAX_EFFORT)
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
        except (aiohttp.ClientError, asyncio.TimeoutError, *_MALFORMED) as e:
            log.debug("Request to %s failed: %s", url, e)
            return None

    async def probe_transpeer(self, addr: str, port: int = TRANSPEER_PORT) -> TranspeerEntry | None:
        """Probe an IP to check if it's a transpeer. Returns entry if valid.

        /transpeer is always free (no handshake PoW required).
        """
        url = f"http://{addr}:{port}/transpeer"
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5), headers=self._headers) as session:
                async with session.get(url) as resp:
                    if resp.status != 200:
                        return None
                    data = await resp.json()
                    if not isinstance(data, dict) or data.get("protocol") != PROTOCOL_VERSION:
                        return None
                    node_id = data.get("node_id", "")
                    uptime = data.get("uptime", 0)
                    return TranspeerEntry(
                        addr=addr,
                        port=port,
                        networks=_clean_networks(data.get("networks", [])),
                        last_seen=int(time.time()),
                        node_id=node_id if isinstance(node_id, str) else "",
                        uptime=max(0, uptime) if isinstance(uptime, int) and not isinstance(uptime, bool) else 0,
                    )
        except (aiohttp.ClientError, asyncio.TimeoutError, *_MALFORMED):
            return None

    async def fetch_peers(self, addr: str, port: int, network: str) -> list[Peer]:
        """Fetch peer list for a network from a transpeer."""
        url = f"http://{addr}:{port}/peers/{network}"
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10), headers=self._headers) as session:
                data = await self._get_with_pow(session, url, addr)
                if not data:
                    return []
                peers = []
                now = int(time.time())
                raw = data.get("peers", []) if isinstance(data, dict) else []
                for entry in raw if isinstance(raw, list) else []:
                    try:
                        peer = Peer.from_dict(network, entry)
                    except _MALFORMED:
                        # One bad entry must not discard the whole list.
                        continue
                    if not _valid_endpoint(peer.addr, peer.port):
                        continue
                    peer.last_seen = _clamp_time(peer.last_seen, now)
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
        except (aiohttp.ClientError, asyncio.TimeoutError, *_MALFORMED) as e:
            log.debug("Failed to fetch peers from %s:%d: %s", addr, port, e)
            return []

    async def fetch_transpeers(self, addr: str, port: int) -> list[TranspeerEntry]:
        """Fetch known transpeers from a transpeer."""
        url = f"http://{addr}:{port}/transpeers"
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10), headers=self._headers) as session:
                data = await self._get_with_pow(session, url, addr)
                if not data:
                    return []
                entries = []
                now = int(time.time())
                raw = data.get("transpeers", []) if isinstance(data, dict) else []
                for item in raw if isinstance(raw, list) else []:
                    if not isinstance(item, dict):
                        continue
                    tp_addr = item.get("addr")
                    tp_port = item.get("port", TRANSPEER_PORT)
                    if not _valid_endpoint(tp_addr, tp_port):
                        continue
                    entries.append(TranspeerEntry(
                        addr=tp_addr,
                        port=tp_port,
                        networks=_clean_networks(item.get("networks", [])),
                        last_seen=_clamp_time(item.get("last_seen", 0), now),
                    ))
                return entries
        except (aiohttp.ClientError, asyncio.TimeoutError, *_MALFORMED) as e:
            log.debug("Failed to fetch transpeers from %s:%d: %s", addr, port, e)
            return []

    async def _probe_native(self, entry: TranspeerEntry, networks: list[str]):
        """Under --native-vouchers, check once per (transpeer, network)
        whether the transpeer's host answers on the network's P2P port.

        Only networks this node runs can be checked, since only for those
        does it know the port. A transpeer's claim to run a network is
        never used; the probe result is what makes its vouchers native.
        The probe is a TCP connect, the same check the verifier makes on
        peers; a production build would use the network plugin's handshake.
        Results are kept for the life of the entry (no re-probe yet).
        """
        stored = self.store.get_transpeer(entry.addr, entry.port)
        if stored is None:
            return
        for network in networks:
            port = self.config.native_ports.get(network)
            if port is None or network in stored.native:
                continue
            ok = False
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(entry.addr, port), timeout=5)
                writer.close()
                await writer.wait_closed()
                ok = True
            except (OSError, asyncio.TimeoutError):
                ok = False
            self.store.set_native(entry.addr, entry.port, network, ok)
            log.info("Native probe %s:%d for %s: %s", entry.addr, port, network,
                     "open" if ok else "closed")

    async def query_transpeer(self, entry: TranspeerEntry):
        """Query a known transpeer for all its data and merge into our store."""
        log.info("Querying transpeer %s:%d", entry.addr, entry.port)

        updated = await self.probe_transpeer(entry.addr, entry.port)
        if not updated:
            log.info("Transpeer %s:%d unreachable", entry.addr, entry.port)
            return False
        await self.store.add_transpeer(updated)

        if self.config.native_vouchers:
            await self._probe_native(entry, updated.networks)

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
        if self.after_query:
            try:
                await self.after_query(updated)
            except Exception:  # noqa: BLE001 — guards a loop callback
                log.exception("after_query")
        return True
