"""Fetch client for the chain-anchored reader (spec §5): pulls anchor
headers, block blobs, venue shares, and generic content-addressed blobs
from another transpeer's port. Content-addressed data: no handshake PoW.
"""

import asyncio

import aiohttp

from ..config import Config, user_agent
from .blob import blob_hash
from .headers import HeaderRow

def _hex32(value) -> bytes:
    """A JSON value as exactly 32 bytes, or ValueError/TypeError."""
    b = bytes.fromhex(value)
    if len(b) != 32:
        raise ValueError("not 32 bytes")
    return b


def _obj(data) -> dict:
    """A JSON body that must be an object, or ValueError. A body that is
    an array or a scalar is malformed, like any other wrong type."""
    if not isinstance(data, dict):
        raise ValueError("body is not a JSON object")
    return data


def _items(value, kind) -> list:
    """A JSON array whose elements are all `kind`, or ValueError."""
    if not isinstance(value, list) or not all(isinstance(v, kind) for v in value):
        raise ValueError("not an array of the expected type")
    return value


class AnchorClient:
    """Every method returns well-typed values or the empty result: JSON
    from the network is untrusted, so a wrong type, a short hash or a
    missing field is treated exactly like a network error."""

    def __init__(self, config: Config, timeout: float = 10.0):
        self.config = config
        self._timeout = aiohttp.ClientTimeout(total=timeout)
        self._headers = {"User-Agent": user_agent(config.contact)}

    async def fetch_headers(self, addr: str, port: int, chain: str,
                            from_height: int, count: int) -> list[HeaderRow]:
        url = f"http://{addr}:{port}/anchor/{chain}/headers?from={from_height}&count={count}"
        try:
            async with aiohttp.ClientSession(timeout=self._timeout, headers=self._headers) as session:
                async with session.get(url) as resp:
                    if resp.status != 200:
                        return []
                    data = _obj(await resp.json())
                    if data.get("chain") != chain:
                        return []
                    return [HeaderRow(int(h["height"]), bytes.fromhex(h["blob"]),
                                      int(h["difficulty"]))
                            for h in _items(data.get("headers", []), dict)]
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError, TypeError, KeyError):
            return []

    async def fetch_tip(self, addr: str, port: int, chain: str) -> int | None:
        url = f"http://{addr}:{port}/anchor/{chain}/headers?count=1"
        try:
            async with aiohttp.ClientSession(timeout=self._timeout, headers=self._headers) as session:
                async with session.get(url) as resp:
                    if resp.status != 200:
                        return None
                    data = _obj(await resp.json())
                    if data.get("chain") != chain:
                        return None
                    tip = data.get("tip")
                    return None if tip is None else int(tip)
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError, TypeError):
            return None

    async def fetch_venues(self, addr: str, port: int) -> list[bytes]:
        """Consensus ids of the venues this transpeer serves (spec §6.4:
        venues are discovered, not only configured)."""
        url = f"http://{addr}:{port}/venues"
        try:
            async with aiohttp.ClientSession(timeout=self._timeout, headers=self._headers) as session:
                async with session.get(url) as resp:
                    if resp.status != 200:
                        return []
                    data = _obj(await resp.json())
                    return [_hex32(v) for v in _items(data.get("venues", []), str)]
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError, TypeError):
            return []

    async def fetch_block(self, addr: str, port: int, chain: str, height: int) -> bytes | None:
        url = f"http://{addr}:{port}/anchor/{chain}/coinbase/{height}"
        try:
            async with aiohttp.ClientSession(timeout=self._timeout, headers=self._headers) as session:
                async with session.get(url) as resp:
                    if resp.status != 200:
                        return None
                    return await resp.read()
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError):
            return None

    async def fetch_share(self, addr: str, port: int, venue: bytes, share_id: bytes) -> bytes | None:
        url = f"http://{addr}:{port}/venue/{venue.hex()}/share/{share_id.hex()}"
        try:
            async with aiohttp.ClientSession(timeout=self._timeout, headers=self._headers) as session:
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
            async with aiohttp.ClientSession(timeout=self._timeout, headers=self._headers) as session:
                async with session.get(url) as resp:
                    if resp.status != 200:
                        return []
                    data = _obj(await resp.json())
                    return [bytes.fromhex(s) for s in _items(data.get("shares", []), str)]
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError, TypeError):
            return []

    async def fetch_share_by_root(self, addr: str, port: int, venue: bytes, root: bytes) -> bytes | None:
        url = f"http://{addr}:{port}/venue/{venue.hex()}/share_by_root/{root.hex()}"
        try:
            async with aiohttp.ClientSession(timeout=self._timeout, headers=self._headers) as session:
                async with session.get(url) as resp:
                    if resp.status != 200:
                        return None
                    return await resp.read()
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError):
            return None

    async def fetch_blob(self, addr: str, port: int, h: bytes) -> bytes | None:
        url = f"http://{addr}:{port}/blob/{h.hex()}"
        try:
            async with aiohttp.ClientSession(timeout=self._timeout, headers=self._headers) as session:
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
            async with aiohttp.ClientSession(timeout=self._timeout, headers=self._headers) as session:
                async with session.get(url) as resp:
                    if resp.status != 200:
                        return [], None, None
                    data = _obj(await resp.json())
                    rows = _items(data.get("blobs", []), dict)
                    next_since = data.get("next_since")
                    next_since = None if next_since is None else int(next_since)
                    next_after_hex = data.get("next_after")
                    next_after = _hex32(next_after_hex) if next_after_hex else None
                    return rows, next_since, next_after
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError, TypeError):
            return [], None, None
