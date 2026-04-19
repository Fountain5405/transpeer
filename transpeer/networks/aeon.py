"""Aeon network plugin."""

import asyncio
import logging

import aiohttp

from .base import Network, PeerInfo

log = logging.getLogger(__name__)


class AeonNetwork(Network):
    name = "aeon"
    default_port = 11180
    default_rpc_port = 11181

    async def extract_peers(self, rpc_host: str = "127.0.0.1") -> list[PeerInfo]:
        """Get peer list from local aeond via JSON-RPC."""
        url = f"http://{rpc_host}:{self.default_rpc_port}/json_rpc"
        payload = {
            "jsonrpc": "2.0",
            "id": "0",
            "method": "get_peer_list",
        }
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                async with session.post(url, json=payload) as resp:
                    if resp.status != 200:
                        log.warning("aeond RPC returned %d", resp.status)
                        return []
                    data = await resp.json()

            result = data.get("result", {})
            peers = []
            for entry in result.get("white_list", []):
                host = entry.get("host", "")
                port = entry.get("port", self.default_port)
                if host and port:
                    peers.append(PeerInfo(addr=host, port=port))
            log.info("Extracted %d Aeon peers from local daemon", len(peers))
            return peers
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            log.debug("Failed to query aeond: %s", e)
            return []

    async def verify_peer(self, addr: str, port: int) -> bool:
        """Check if a peer responds on the Aeon P2P port."""
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
