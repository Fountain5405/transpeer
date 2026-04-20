"""Async peer verification — probe daemon ports to confirm peers are real."""

import asyncio
import logging

from .config import VERIFY_CONCURRENCY, VERIFY_TIMEOUT
from .networks.base import Network
from .peerstore import Peer, PeerStore

log = logging.getLogger(__name__)


async def probe_peer_tcp(peer: Peer) -> bool:
    """Basic TCP connect check — is anything listening on the port?"""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(peer.addr, peer.port),
            timeout=VERIFY_TIMEOUT,
        )
        writer.close()
        await writer.wait_closed()
        return True
    except (OSError, asyncio.TimeoutError):
        return False


async def verify_peers(store: PeerStore, network: str,
                       network_plugin: Network | None = None):
    """Verify peers for a network.

    If a network_plugin is provided, uses its verify_peer() method for
    protocol-level handshake verification (e.g., checking levin signature
    for Monero). Falls back to TCP-only if no plugin is available.
    """
    peers = store.get_peers(network, verified_only=False)
    if not peers:
        return

    log.info("Verifying %d peers for %s (mode: %s)", len(peers), network,
             "handshake" if network_plugin else "tcp-only")

    semaphore = asyncio.Semaphore(VERIFY_CONCURRENCY)

    async def _verify_one(peer: Peer):
        async with semaphore:
            if network_plugin:
                alive = await network_plugin.verify_peer(peer.addr, peer.port)
            else:
                alive = await probe_peer_tcp(peer)
            if alive:
                await store.mark_verified(peer.network, peer.addr, peer.port)
            else:
                await store.mark_dead(peer.network, peer.addr, peer.port)
            return alive

    tasks = [_verify_one(p) for p in peers]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    alive_count = sum(1 for r in results if r is True)
    log.info("Verification for %s: %d/%d alive", network, alive_count, len(peers))
