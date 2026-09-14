"""Header-chain verification for the anchor reader (spec §6.2, §17.1).

Verifies a run of Monero hashing blobs against a shipped checkpoint:
linkage, timestamps, the difficulty rule, sampled proof-of-work, and
the stale-tip rule.
"""

import random
from dataclasses import dataclass, field

from .monero import (
    parse_hashing_blob, block_id, check_hash, next_difficulty,
    DIFFICULTY_BLOCKS_COUNT, BLOCK_FUTURE_TIME_LIMIT,
)
from .powhash import PowBackend

STALE_TIP = 1800


@dataclass(frozen=True)
class HeaderRow:
    height: int
    blob: bytes
    difficulty: int


@dataclass
class Checkpoint:
    height: int
    hash: bytes


def parse_checkpoint(s: str) -> Checkpoint:
    try:
        height_s, hex_hash = s.split(":", 1)
        height = int(height_s)
        h = bytes.fromhex(hex_hash)
    except (ValueError, AttributeError) as e:
        raise ValueError(f"malformed checkpoint {s!r}") from e
    if height < 0 or len(h) != 32:
        raise ValueError(f"malformed checkpoint {s!r}")
    return Checkpoint(height, h)


class HeaderError(ValueError):
    pass


@dataclass
class ChainView:
    first: int
    ids: list
    timestamps: list
    difficulties: list
    cumulative: list
    blobs: list

    @property
    def tip_height(self) -> int:
        return self.first + len(self.ids) - 1

    @property
    def tip_id(self) -> bytes:
        return self.ids[-1]

    @property
    def work(self) -> int:
        return self.cumulative[-1]

    def height_of(self, id_: bytes):
        for i, cid in enumerate(self.ids):
            if cid == id_:
                return self.first + i
        return None

    def id_at(self, height: int) -> bytes:
        return self.ids[height - self.first]

    def timestamp_at(self, height: int) -> int:
        return self.timestamps[height - self.first]


def _median(values: list) -> int:
    """Monero epee::misc_utils::median: sort; for even counts, the
    truncated mean of the two middle values."""
    s = sorted(values)
    n = len(s)
    mid = n // 2
    if n % 2:
        return s[mid]
    return (s[mid - 1] + s[mid]) // 2


def _check_shape(rows: list, checkpoint: Checkpoint) -> None:
    if not rows:
        raise HeaderError("no header rows supplied")
    for i in range(1, len(rows)):
        if rows[i].height != rows[i - 1].height + 1:
            raise HeaderError(f"non-contiguous heights at {rows[i].height}")
    first, last = rows[0].height, rows[-1].height
    if not (first <= checkpoint.height <= last):
        raise HeaderError(f"checkpoint height {checkpoint.height} outside rows [{first},{last}]")
    if checkpoint.height < DIFFICULTY_BLOCKS_COUNT:
        if first != 0:
            raise HeaderError(f"rows must start at 0 for checkpoint {checkpoint.height}")
    else:
        if first > checkpoint.height - DIFFICULTY_BLOCKS_COUNT:
            raise HeaderError(f"rows do not cover the difficulty window before checkpoint {checkpoint.height}")


def _check_linkage(rows: list, checkpoint: Checkpoint):
    heads = []
    ids = []
    prev = None
    for i, row in enumerate(rows):
        try:
            head = parse_hashing_blob(row.blob)
        except ValueError as e:
            raise HeaderError(f"unparseable blob at height {row.height}: {e}") from e
        rid = block_id(row.blob)
        if i > 0 and head.prev_id != ids[-1]:
            raise HeaderError(f"broken linkage at height {row.height}")
        heads.append(head)
        ids.append(rid)
        prev = rid
    idx = checkpoint.height - rows[0].height
    if ids[idx] != checkpoint.hash:
        raise HeaderError(f"checkpoint mismatch at height {checkpoint.height}")
    return heads, ids


def _check_timestamps(rows: list, heads: list, now: int) -> None:
    limit = now + BLOCK_FUTURE_TIME_LIMIT
    for i, (row, head) in enumerate(zip(rows, heads)):
        if head.timestamp > limit:
            raise HeaderError(f"timestamp too far in the future at height {row.height}")
        if i >= 60:
            prev_60 = [heads[j].timestamp for j in range(i - 60, i)]
            if head.timestamp < _median(prev_60):
                raise HeaderError(f"timestamp below median of previous 60 at height {row.height}")


def _check_difficulty(rows: list, heads: list, checkpoint: Checkpoint) -> list:
    cumulative = []
    running = 0
    timestamps = [h.timestamp for h in heads]
    for i, row in enumerate(rows):
        running += row.difficulty
        cumulative.append(running)
        if row.height <= checkpoint.height:
            if row.difficulty < 1:
                raise HeaderError(f"non-positive difficulty at height {row.height}")
            continue
        window_ts = timestamps[max(0, i - DIFFICULTY_BLOCKS_COUNT):i]
        window_cum = cumulative[max(0, i - DIFFICULTY_BLOCKS_COUNT):i]
        expected = next_difficulty(window_ts, window_cum)
        if expected != row.difficulty:
            raise HeaderError(f"difficulty mismatch at height {row.height}")
    return cumulative


def _check_pow(rows: list, pow: PowBackend, rng, sample: float, recent: int, seed_hash_for) -> None:
    n = len(rows)
    for i, row in enumerate(rows):
        recently = i >= n - recent
        if recently or rng.random() < sample:
            h = pow.hash(row.blob, row.height, seed_hash_for(row.height))
            if not check_hash(h, row.difficulty):
                raise HeaderError(f"proof-of-work invalid at height {row.height}")


def verify_headers(rows: list, checkpoint: Checkpoint, pow: PowBackend, now: int,
                    rng=random.Random(), sample: float = 0.05, recent: int = 720,
                    seed_hash_for=lambda height: bytes(32)) -> ChainView:
    _check_shape(rows, checkpoint)
    heads, ids = _check_linkage(rows, checkpoint)
    _check_timestamps(rows, heads, now)
    cumulative = _check_difficulty(rows, heads, checkpoint)
    _check_pow(rows, pow, rng, sample, recent, seed_hash_for)
    timestamps = [h.timestamp for h in heads]
    if now - timestamps[-1] > STALE_TIP:
        raise HeaderError("stale tip")
    difficulties = [row.difficulty for row in rows]
    blobs = [row.blob for row in rows]
    return ChainView(rows[0].height, ids, timestamps, difficulties, cumulative, blobs)


def best_view(views: list):
    if not views:
        return None
    return min(views, key=lambda v: (-v.work, v.tip_id))
