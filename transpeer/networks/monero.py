"""Monero network plugin."""

import asyncio
import logging

import aiohttp

from .base import Network, PeerInfo

log = logging.getLogger(__name__)

# Monero P2P protocol: the first bytes of a handshake contain a network ID.
# Mainnet levin protocol signature.
LEVIN_SIGNATURE = b"\x01\x21\x01\x01\x01\x01\x01\x01"


class MoneroNetwork(Network):
    name = "monero"
    default_port = 18080
    default_rpc_port = 18081

    async def extract_peers(self, rpc_host: str = "127.0.0.1") -> list[PeerInfo]:
        """Get peers from local monerod.

        Default: returns only currently connected peers (get_connections).
        With share_white_list=True: returns the full white list (get_peer_list).
        """
        if self.share_white_list:
            return await self._extract_white_list(rpc_host)
        return await self._extract_connections(rpc_host)

    async def _extract_connections(self, rpc_host: str) -> list[PeerInfo]:
        url = f"http://{rpc_host}:{self.default_rpc_port}/json_rpc"
        payload = {"jsonrpc": "2.0", "id": "0", "method": "get_connections"}
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                async with session.post(url, json=payload) as resp:
                    if resp.status != 200:
                        return []
                    data = await resp.json()
            peers = []
            for conn in data.get("result", {}).get("connections", []):
                host = conn.get("host", "") or conn.get("ip", "")
                port = conn.get("port", "")
                if host and port:
                    peers.append(PeerInfo(addr=host, port=int(port)))
            log.info("Extracted %d connected Monero peers", len(peers))
            return peers
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            log.debug("Failed to query monerod: %s", e)
            return []

    async def _extract_white_list(self, rpc_host: str) -> list[PeerInfo]:
        url = f"http://{rpc_host}:{self.default_rpc_port}/json_rpc"
        payload = {"jsonrpc": "2.0", "id": "0", "method": "get_peer_list"}
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                async with session.post(url, json=payload) as resp:
                    if resp.status != 200:
                        return []
                    data = await resp.json()
            peers = []
            for entry in data.get("result", {}).get("white_list", []):
                host = entry.get("host", "")
                port = entry.get("port", self.default_port)
                if host and port:
                    peers.append(PeerInfo(addr=host, port=port))
            log.info("Extracted %d Monero white list peers", len(peers))
            return peers
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            log.debug("Failed to query monerod: %s", e)
            return []

    async def verify_peer(self, addr: str, port: int) -> bool:
        """Check if a peer responds with Monero's levin protocol signature."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(addr, port),
                timeout=5,
            )
            # Read first bytes — Monero sends a handshake with levin signature
            data = await asyncio.wait_for(reader.read(8), timeout=5)
            writer.close()
            await writer.wait_closed()
            return data == LEVIN_SIGNATURE
        except (OSError, asyncio.TimeoutError):
            return False
