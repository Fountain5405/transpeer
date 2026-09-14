"""Content-addressed store of list blobs and their commitment records,
spec §3.2 and §3.3. A body (blob with period zeroed) is stored once;
each blob hash maps to (body hash, period)."""

import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from .blob import BlobError, blob_hash, decode_blob, list_body, with_period

KINDS = ("share", "block", "template")


@dataclass(frozen=True)
class Commitment:
    hash: bytes
    kind: str
    venue: str
    ref: str
    publisher: str
    difficulty: int
    timestamp: int
    proof: tuple[bytes, ...] = ()
    path: int = 0

    def to_dict(self) -> dict:
        return {
            "hash": self.hash.hex(), "kind": self.kind, "venue": self.venue,
            "ref": self.ref, "publisher": self.publisher,
            "difficulty": self.difficulty, "timestamp": self.timestamp,
            "proof": [p.hex() for p in self.proof], "path": self.path,
        }

    @staticmethod
    def from_dict(d: dict) -> "Commitment":
        return Commitment(
            bytes.fromhex(d["hash"]), d["kind"], d["venue"], d["ref"], d["publisher"],
            int(d["difficulty"]), int(d["timestamp"]),
            tuple(bytes.fromhex(p) for p in d.get("proof", [])), int(d.get("path", 0)),
        )


@dataclass
class _BlobRow:
    body_hash: bytes
    period: int
    first_seen: int
    commitments: list[Commitment] = field(default_factory=list)


class BlobDB:
    def __init__(self):
        self._bodies: dict[bytes, bytes] = {}       # body hash -> body bytes
        self._blobs: dict[bytes, _BlobRow] = {}     # blob hash -> row
        self._entries: set[tuple[str, int]] = set()

    def add(self, blob: bytes, commitment: Commitment, now: int) -> bool:
        h = blob_hash(blob)
        if commitment.hash != h or commitment.kind not in KINDS:
            return False
        try:
            decoded = decode_blob(blob)
        except BlobError:
            return False
        row = self._blobs.get(h)
        if row is None:
            body = list_body(blob)
            bh = hashlib.sha256(body).digest()
            self._bodies.setdefault(bh, body)
            row = _BlobRow(bh, decoded.period, now)
            self._blobs[h] = row
            self._entries.update(decoded.entries)
        if commitment not in row.commitments:
            row.commitments.append(commitment)
        return True

    def get(self, h: bytes) -> bytes | None:
        row = self._blobs.get(h)
        if row is None:
            return None
        return with_period(self._bodies[row.body_hash], row.period)

    def commitments(self, h: bytes) -> list[Commitment]:
        row = self._blobs.get(h)
        return list(row.commitments) if row else []

    def entries_of(self, h: bytes) -> tuple[tuple[str, int], ...]:
        b = self.get(h)
        return decode_blob(b).entries if b else ()

    def has_body_entry(self, addr: str, port: int) -> bool:
        return (addr, port) in self._entries

    def index_since(self, since: int, limit: int = 500, after: bytes = b""
                    ) -> list[tuple[bytes, int, list[Commitment]]]:
        """Rows after the cursor (since, after) in (first_seen, hash) order.
        With an empty `after` this is the old strictly-greater rule; with a
        hash it resumes exactly where the previous page ended, so rows
        that share a timestamp across a page boundary are not skipped."""
        rows = [(h, r.first_seen, list(r.commitments))
                for h, r in self._blobs.items()
                if r.first_seen > since or (after and r.first_seen == since and h > after)]
        rows.sort(key=lambda t: (t[1], t[0]))
        return rows[:limit]

    def body_count(self) -> int:
        return len(self._bodies)

    def blob_count(self) -> int:
        return len(self._blobs)

    def commitment_count(self) -> int:
        return sum(len(r.commitments) for r in self._blobs.values())

    def to_json(self) -> dict:
        return {
            "version": 1,
            "bodies": {k.hex(): v.hex() for k, v in self._bodies.items()},
            "blobs": {
                h.hex(): {
                    "body": r.body_hash.hex(), "period": r.period,
                    "first_seen": r.first_seen,
                    "commitments": [c.to_dict() for c in r.commitments],
                } for h, r in self._blobs.items()
            },
        }

    @staticmethod
    def from_json(d: dict) -> "BlobDB":
        db = BlobDB()
        if d.get("version") != 1:
            return db
        db._bodies = {bytes.fromhex(k): bytes.fromhex(v) for k, v in d["bodies"].items()}
        for h, r in d["blobs"].items():
            row = _BlobRow(bytes.fromhex(r["body"]), int(r["period"]), int(r["first_seen"]),
                           [Commitment.from_dict(c) for c in r["commitments"]])
            db._blobs[bytes.fromhex(h)] = row
            db._entries.update(decode_blob(with_period(db._bodies[row.body_hash], row.period)).entries)
        return db

    def save(self, path: Path) -> None:
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(self.to_json()))
        os.replace(tmp, path)

    @staticmethod
    def load(path: Path) -> "BlobDB":
        if not path.exists():
            return BlobDB()
        return BlobDB.from_json(json.loads(path.read_text()))
