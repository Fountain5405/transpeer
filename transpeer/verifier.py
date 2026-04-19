"""Async peer verification — probe daemon ports to confirm peers are real."""

import asyncio
import logging

from .config import VERIFY_CONCURRENCY, VERIFY_TIMEOUT
from .peerstore import Peer, PeerStore

log = logging.getLogger(__name__)


async def probe_peer(peer: Peer) -> bool:
    """Check if a peer is reachable on its daemon port.

    Does a TCP connect — if the port is open, the peer is likely running
    the claimed daemon. Network-specific handshake verification can be
    added per-network for stronger validation.
    """
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


async def verify_peers(store: PeerStore, network: str):
    """Verify all unverified peers for a network, and re-verify existing ones."""
    peers = store.get_peers(network, verified_only=False)
    if not peers:
        return

    log.info("Verifying %d peers for %s", len(peers), network)

    semaphore = asyncio.Semaphore(VERIFY_CONCURRENCY)

    async def _verify_one(peer: Peer):
        async with semaphore:
            alive = await probe_peer(peer)
            if alive:
                await store.mark_verified(peer.network, peer.addr, peer.port)
            else:
                await store.mark_dead(peer.network, peer.addr, peer.port)
            return alive

    tasks = [_verify_one(p) for p in peers]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    alive_count = sum(1 for r in results if r is True)
    log.info("Verification for %s: %d/%d alive", network, alive_count, len(peers))
