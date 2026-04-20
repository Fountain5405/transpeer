"""Wownero network plugin."""

import asyncio
import logging

import aiohttp

from .base import Network, PeerInfo

log = logging.getLogger(__name__)


class WowneroNetwork(Network):
    name = "wownero"
    default_port = 34567
    default_rpc_port = 34568

    async def extract_peers(self, rpc_host: str = "127.0.0.1") -> list[PeerInfo]:
        """Get currently connected peers from local wownerod."""
        url = f"http://{rpc_host}:{self.default_rpc_port}/json_rpc"
        payload = {
            "jsonrpc": "2.0",
            "id": "0",
            "method": "get_connections",
        }
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                async with session.post(url, json=payload) as resp:
                    if resp.status != 200:
                        log.warning("wownerod RPC returned %d", resp.status)
                        return []
                    data = await resp.json()

            result = data.get("result", {})
            peers = []
            for conn in result.get("connections", []):
                host = conn.get("host", "") or conn.get("ip", "")
                port = conn.get("port", "")
                if host and port:
                    peers.append(PeerInfo(addr=host, port=int(port)))
            log.info("Extracted %d connected Wownero peers", len(peers))
            return peers
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            log.debug("Failed to query wownerod: %s", e)
            return []

    async def verify_peer(self, addr: str, port: int) -> bool:
        """Check if a peer responds on the Wownero P2P port."""
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(addr, port),
                timeout=5,
            )
            writer.close()
            await writer.wait_closed()
            return True
        except (OSError, asyncio.TimeoutError):
            return False
