"""Fetch client for the chain-anchored reader (spec §5): pulls anchor
headers, block blobs, venue shares, and generic content-addressed blobs
from another transpeer's port. Content-addressed data: no handshake PoW.
"""

import asyncio

import aiohttp

from ..config import Config, user_agent
from .blob import blob_hash
from .headers import HeaderRow

_TIMEOUT = aiohttp.ClientTimeout(total=10)


class AnchorClient:
    def __init__(self, config: Config):
        self.config = config
        self._headers = {"User-Agent": user_agent(config.contact)}

    async def fetch_headers(self, addr: str, port: int, chain: str,
                            from_height: int, count: int) -> list[HeaderRow]:
        url = f"http://{addr}:{port}/anchor/{chain}/headers?from={from_height}&count={count}"
        try:
            async with aiohttp.ClientSession(timeout=_TIMEOUT, headers=self._headers) as session:
                async with session.get(url) as resp:
                    if resp.status != 200:
                        return []
                    data = await resp.json()
                    if data.get("chain") != chain:
                        return []
                    return [HeaderRow(h["height"], bytes.fromhex(h["blob"]), h["difficulty"])
                            for h in data.get("headers", [])]
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError):
            return []

    async def fetch_tip(self, addr: str, port: int, chain: str) -> int | None:
        url = f"http://{addr}:{port}/anchor/{chain}/headers?count=1"
        try:
            async with aiohttp.ClientSession(timeout=_TIMEOUT, headers=self._headers) as session:
                async with session.get(url) as resp:
                    if resp.status != 200:
                        return None
                    data = await resp.json()
                    if data.get("chain") != chain:
                        return None
                    return data.get("tip")
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError):
            return None

    async def fetch_block(self, addr: str, port: int, chain: str, height: int) -> bytes | None:
        url = f"http://{addr}:{port}/anchor/{chain}/coinbase/{height}"
        try:
            async with aiohttp.ClientSession(timeout=_TIMEOUT, headers=self._headers) as session:
                async with session.get(url) as resp:
                    if resp.status != 200:
                        return None
                    return await resp.read()
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError):
            return None

    async def fetch_share(self, addr: str, port: int, venue: bytes, share_id: bytes) -> bytes | None:
        url = f"http://{addr}:{port}/venue/{venue.hex()}/share/{share_id.hex()}"
        try:
            async with aiohttp.ClientSession(timeout=_TIMEOUT, headers=self._headers) as session:
                async with session.get(url) as resp:
                    if resp.status != 200:
                        return None
                    return await resp.read()
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError):
            return None

    async def fetch_shares(self, addr: str, port: int, venue: bytes,
                           from_id: bytes, count: int) -> list[bytes]:
        url = f"http://{addr}:{port}/venue/{venue.hex()}/shares?from={from_id.hex()}&count={count}"
        try:
            async with aiohttp.ClientSession(timeout=_TIMEOUT, headers=self._headers) as session:
                async with session.get(url) as resp:
                    if resp.status != 200:
                        return []
                    data = await resp.json()
                    return [bytes.fromhex(s) for s in data.get("shares", [])]
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError):
            return []

    async def fetch_share_by_root(self, addr: str, port: int, venue: bytes, root: bytes) -> bytes | None:
        url = f"http://{addr}:{port}/venue/{venue.hex()}/share_by_root/{root.hex()}"
        try:
            async with aiohttp.ClientSession(timeout=_TIMEOUT, headers=self._headers) as session:
                async with session.get(url) as resp:
                    if resp.status != 200:
                        return None
                    return await resp.read()
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError):
            return None

    async def fetch_blob(self, addr: str, port: int, h: bytes) -> bytes | None:
        url = f"http://{addr}:{port}/blob/{h.hex()}"
        try:
            async with aiohttp.ClientSession(timeout=_TIMEOUT, headers=self._headers) as session:
                async with session.get(url) as resp:
                    if resp.status != 200:
                        return None
                    body = await resp.read()
                    if blob_hash(body) != h:
                        return None
                    return body
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError):
            return None

    async def fetch_index(self, addr: str, port: int, since: int,
                          after: bytes = b"") -> tuple[list[dict], int | None, bytes | None]:
        url = f"http://{addr}:{port}/blobs/index?since={since}"
        if after:
            url += f"&after={after.hex()}"
        try:
            async with aiohttp.ClientSession(timeout=_TIMEOUT, headers=self._headers) as session:
                async with session.get(url) as resp:
                    if resp.status != 200:
                        return [], None, None
                    data = await resp.json()
                    rows = data.get("blobs", [])
                    next_since = data.get("next_since")
                    next_after_hex = data.get("next_after")
                    next_after = bytes.fromhex(next_after_hex) if next_after_hex else None
                    return rows, next_since, next_after
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError):
            return [], None, None
