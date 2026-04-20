"""Generic network plugin for arbitrary P2P networks."""

import asyncio
import logging

import aiohttp

from .base import Network, PeerInfo

log = logging.getLogger(__name__)


class GenericNetwork(Network):
    """A network plugin that works with any daemon exposing a Monero-style
    get_peer_list JSON-RPC endpoint."""

    def __init__(self, name: str, p2p_port: int, rpc_port: int):
        self.name = name
        self.default_port = p2p_port
        self.default_rpc_port = rpc_port

    async def extract_peers(self, rpc_host: str = "127.0.0.1") -> list[PeerInfo]:
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
                        log.warning("%s RPC returned %d", self.name, resp.status)
                        return []
                    data = await resp.json()

            result = data.get("result", {})
            peers = []
            for entry in result.get("white_list", []):
                host = entry.get("host", "")
                port = entry.get("port", self.default_port)
                if host and port:
                    peers.append(PeerInfo(addr=host, port=port))
            log.info("Extracted %d %s peers from local daemon", len(peers), self.name)
            return peers
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            log.debug("Failed to query %s daemon: %s", self.name, e)
            return []

    async def verify_peer(self, addr: str, port: int) -> bool:
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
