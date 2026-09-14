"""Anchor and per-venue share stores for the chain-anchored reader (spec
slice 3). AnchorStore holds verified header rows, block blobs for the
coverage window and the current ChainView. ShareStore holds raw P2Pool
shares for one venue, indexed in memory and persisted as one file per
share on disk.
"""

import json
from pathlib import Path

from .headers import HeaderRow, ChainView
from .share import ParsedShare, parse_share


class AnchorStore:
    def __init__(self, path: Path | None):
        self.path = path
        self.headers: dict[int, HeaderRow] = {}
        self.blocks: dict[int, bytes] = {}
        self.view: ChainView | None = None

    def put_headers(self, rows) -> None:
        for row in rows:
            self.headers[row.height] = row

    def header_rows(self, from_height: int, count: int) -> list:
        out = []
        h = from_height
        while len(out) < count and h in self.headers:
            out.append(self.headers[h])
            h += 1
        return out

    def put_block(self, height: int, blob: bytes) -> None:
        self.blocks[height] = blob

    def block(self, height: int) -> bytes | None:
        return self.blocks.get(height)

    def tip_height(self) -> int | None:
        if not self.headers:
            return None
        return max(self.headers)

    def prune(self, keep_from_height: int) -> None:
        for h in [h for h in self.headers if h < keep_from_height]:
            del self.headers[h]
        for h in [h for h in self.blocks if h < keep_from_height]:
            del self.blocks[h]

    def save(self) -> None:
        if self.path is None:
            return
        doc = {
            "headers": [[row.height, row.blob.hex(), row.difficulty]
                        for row in self.headers.values()],
            "blocks": {str(h): blob.hex() for h, blob in self.blocks.items()},
            "view": self._view_to_dict(),
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(doc))

    def load(self) -> None:
        if self.path is None:
            return
        try:
            doc = json.loads(self.path.read_text())
        except (OSError, ValueError):
            return
        try:
            self.headers = {
                int(height): HeaderRow(int(height), bytes.fromhex(blob_hex), int(difficulty))
                for height, blob_hex, difficulty in doc.get("headers", [])
            }
            self.blocks = {
                int(h): bytes.fromhex(blob_hex) for h, blob_hex in doc.get("blocks", {}).items()
            }
            self.view = self._view_from_dict(doc.get("view"))
        except (ValueError, TypeError, KeyError):
            self.headers = {}
            self.blocks = {}
            self.view = None

    def _view_to_dict(self) -> dict | None:
        v = self.view
        if v is None:
            return None
        return {
            "first": v.first,
            "ids": [i.hex() for i in v.ids],
            "timestamps": list(v.timestamps),
            "difficulties": list(v.difficulties),
            "cumulative": list(v.cumulative),
            "blobs": [b.hex() for b in v.blobs],
        }

    def _view_from_dict(self, d) -> ChainView | None:
        if d is None:
            return None
        return ChainView(
            first=int(d["first"]),
            ids=[bytes.fromhex(i) for i in d["ids"]],
            timestamps=list(d["timestamps"]),
            difficulties=list(d["difficulties"]),
            cumulative=list(d["cumulative"]),
            blobs=[bytes.fromhex(b) for b in d["blobs"]],
        )


class ShareStore:
    def __init__(self, venue: bytes, path: Path | None):
        self.venue = venue
        self.path = path
        self._shares: dict[bytes, ParsedShare] = {}
        self._by_root: dict[bytes, bytes] = {}

    def add(self, share: ParsedShare) -> bool:
        if share.id in self._shares:
            return False
        self._shares[share.id] = share
        self._by_root[share.merkle_root] = share.id
        if self.path is not None:
            self.path.mkdir(parents=True, exist_ok=True)
            (self.path / share.id.hex()).write_bytes(share.raw)
        return True

    def get(self, id: bytes) -> ParsedShare | None:
        return self._shares.get(id)

    def raw(self, id: bytes) -> bytes | None:
        share = self._shares.get(id)
        return share.raw if share is not None else None

    def by_root(self, root: bytes) -> ParsedShare | None:
        id_ = self._by_root.get(root)
        return self._shares.get(id_) if id_ is not None else None

    def walk(self, from_id: bytes, count: int) -> list:
        out = []
        id_ = from_id
        while len(out) < count:
            share = self._shares.get(id_)
            if share is None:
                break
            out.append(share)
            id_ = share.parent
        return out

    def tip(self) -> ParsedShare | None:
        if not self._shares:
            return None
        return min(self._shares.values(), key=lambda s: (-s.cumulative_difficulty, s.id))

    def prune(self, tip_height: int, window: int = 2160) -> None:
        cutoff = tip_height - 4 * window
        stale = [id_ for id_, share in self._shares.items() if share.height < cutoff]
        for id_ in stale:
            share = self._shares.pop(id_)
            self._by_root.pop(share.merkle_root, None)
            if self.path is not None:
                (self.path / id_.hex()).unlink(missing_ok=True)

    def count(self) -> int:
        return len(self._shares)

    def load(self) -> None:
        if self.path is None or not self.path.is_dir():
            return
        self._shares = {}
        self._by_root = {}
        for entry in self.path.iterdir():
            if entry.is_symlink() or not entry.is_file():
                continue
            try:
                data = entry.read_bytes()
                share = parse_share(data, self.venue)
            except (OSError, ValueError):
                entry.unlink(missing_ok=True)
                continue
            self._shares[share.id] = share
            self._by_root[share.merkle_root] = share.id


def venue_dir(data_dir: Path, venue: bytes) -> Path:
    return data_dir / "venues" / venue.hex()
