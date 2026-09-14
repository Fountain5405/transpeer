"""monerod JSON-RPC source for the anchor store (spec §17, slice 3, task
13): fills a local AnchorStore from a monerod the node operator runs,
so that store can be served to the network under --anchor-read.

The RPC shapes here (get_block_count, get_block, get_block_headers_range)
are taken from monerod's published documentation for v0.18 and have not
been verified against a live daemon on this machine.
"""

import aiohttp

from ..config import user_agent
from .headers import HeaderRow
from .monero import block_id, hashing_blob


class MonerodSource:
    """One JSON-RPC call per method, one aiohttp session per call, like
    the other clients in this package. RPC-level errors (an `error` in
    the reply, a non-200 status, malformed JSON, a missing field) raise
    ValueError; connection failures propagate as aiohttp.ClientError or
    asyncio.TimeoutError for the caller to catch."""

    def __init__(self, url: str, session_factory=aiohttp.ClientSession, timeout: float = 30):
        self._url = url.rstrip("/") + "/json_rpc"
        self._session_factory = session_factory
        self._timeout = aiohttp.ClientTimeout(total=timeout)
        self._headers = {"User-Agent": user_agent()}

    async def _rpc(self, method: str, params: dict | None = None) -> dict:
        payload = {"jsonrpc": "2.0", "id": "0", "method": method}
        if params is not None:
            payload["params"] = params
        async with self._session_factory(timeout=self._timeout, headers=self._headers) as session:
            async with session.post(self._url, json=payload) as resp:
                if resp.status != 200:
                    raise ValueError(f"monerod {method} returned HTTP {resp.status}")
                try:
                    data = await resp.json()
                except (aiohttp.ContentTypeError, ValueError) as e:
                    raise ValueError(f"monerod {method} returned malformed JSON") from e
        if not isinstance(data, dict):
            raise ValueError(f"monerod {method} returned a non-object reply")
        if "error" in data:
            raise ValueError(f"monerod {method} error: {data['error']}")
        result = data.get("result")
        if not isinstance(result, dict):
            raise ValueError(f"monerod {method} reply missing result")
        return result

    async def height(self) -> int:
        result = await self._rpc("get_block_count")
        try:
            return int(result["count"]) - 1
        except (KeyError, TypeError, ValueError) as e:
            raise ValueError("monerod get_block_count reply missing count") from e

    async def block_blob(self, height: int) -> bytes:
        result = await self._rpc("get_block", {"height": height})
        try:
            return bytes.fromhex(result["blob"])
        except (KeyError, TypeError, ValueError) as e:
            raise ValueError(f"monerod get_block reply missing blob at height {height}") from e

    async def headers_range(self, start: int, end: int) -> list:
        result = await self._rpc("get_block_headers_range",
                                 {"start_height": start, "end_height": end})
        headers = result.get("headers")
        if not isinstance(headers, list):
            raise ValueError("monerod get_block_headers_range reply missing headers")
        return headers

    async def header_rows(self, start: int, end: int) -> list:
        headers = await self.headers_range(start, end)
        by_height = {}
        for h in headers:
            try:
                by_height[int(h["height"])] = h
            except (KeyError, TypeError, ValueError) as e:
                raise ValueError("monerod get_block_headers_range served a malformed header") from e
        rows = []
        for height in range(start, end + 1):
            header = by_height.get(height)
            if header is None:
                raise ValueError(f"monerod did not serve a header for height {height}")
            blob = await self.block_blob(height)
            hb = hashing_blob(blob)
            try:
                expected = bytes.fromhex(header["hash"])
            except (KeyError, TypeError, ValueError) as e:
                raise ValueError(f"monerod served a malformed hash at height {height}") from e
            if block_id(hb) != expected:
                raise ValueError(f"monerod block hash mismatch at height {height}")
            wide = header.get("wide_difficulty")
            try:
                difficulty = int(wide, 16) if wide else int(header["difficulty"])
            except (KeyError, TypeError, ValueError) as e:
                raise ValueError(f"monerod served a malformed difficulty at height {height}") from e
            rows.append(HeaderRow(height, hb, difficulty))
        return rows
