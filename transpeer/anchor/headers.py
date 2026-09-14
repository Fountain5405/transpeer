"""Header-chain verification for the anchor reader (spec §6.2, §17.1).

Verifies a run of Monero hashing blobs against a shipped checkpoint:
linkage, timestamps, the difficulty rule, sampled proof-of-work, and
the stale-tip rule.
"""

import random
from dataclasses import dataclass, field

from .monero import (
    parse_hashing_blob, block_id, check_hash, next_difficulty, seed_height,
    DIFFICULTY_BLOCKS_COUNT, BLOCK_FUTURE_TIME_LIMIT,
    SEEDHASH_EPOCH_BLOCKS, SEEDHASH_EPOCH_LAG,
)
from .powhash import PowBackend

STALE_TIP = 1800
# How far before the checkpoint headers are fetched: the difficulty
# window (735) plus one RandomX seed epoch and its lag (2048 + 64 + 1),
# so every proof-of-work-checked header has both its difficulty history
# and its seed block inside the view.
HEADER_LOOKBACK = DIFFICULTY_BLOCKS_COUNT + SEEDHASH_EPOCH_BLOCKS + SEEDHASH_EPOCH_LAG + 1


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
    checkpoint_height: int = 0

    @property
    def tip_height(self) -> int:
        return self.first + len(self.ids) - 1

    @property
    def tip_id(self) -> bytes:
        return self.ids[-1]

    @property
    def work(self) -> int:
        """Cumulative difficulty after the checkpoint only. Difficulties at
        or before the checkpoint are served, not derived, so counting them
        would let a source buy the comparison with a lie (spec §17.1)."""
        idx = self.checkpoint_height - self.first
        base = self.cumulative[idx] if 0 <= idx < len(self.cumulative) else 0
        return self.cumulative[-1] - base

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
    start = max(0, checkpoint.height - HEADER_LOOKBACK)
    if first > start:
        raise HeaderError(
            f"rows start at {first}, past the lookback start {start} for checkpoint {checkpoint.height}")


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


def _seed_lookup(ids: list, first: int):
    """Seed hash for a height: the block id at its RandomX seed height."""
    def lookup(height: int) -> bytes:
        sh = seed_height(height)
        i = sh - first
        if not (0 <= i < len(ids)):
            raise HeaderError(f"seed block {sh} for height {height} is not in the view")
        return ids[i]
    return lookup


def _pow_required(row, i: int, n: int, checkpoint: Checkpoint, rng, sample: float,
                  recent: int) -> bool:
    """Which rows are proof-of-work checked. Rows in the difficulty window
    up to and including the checkpoint: all of them, so a served
    pre-checkpoint difficulty cannot be over-claimed. Rows after the
    checkpoint: the recent ones plus the sample (spec §6.2). Rows older
    than the window: linkage only."""
    if row.height <= checkpoint.height:
        return row.height > checkpoint.height - DIFFICULTY_BLOCKS_COUNT
    return i >= n - recent or rng.random() < sample


def _check_pow(rows: list, checkpoint: Checkpoint, pow: PowBackend, rng, sample: float,
               recent: int, seed_hash_for) -> None:
    n = len(rows)
    for i, row in enumerate(rows):
        if _pow_required(row, i, n, checkpoint, rng, sample, recent):
            h = pow.hash(row.blob, row.height, seed_hash_for(row.height))
            if not check_hash(h, row.difficulty):
                raise HeaderError(f"proof-of-work invalid at height {row.height}")


def verify_headers(rows: list, checkpoint: Checkpoint, pow: PowBackend, now: int,
                    rng=random.Random(), sample: float = 0.05, recent: int = 720,
                    seed_hash_for=None, trusted: ChainView | None = None) -> ChainView:
    """Verify `rows` against `checkpoint`. With `trusted`, `rows` must be
    the rows that extend that already-verified view (its tip id is
    `rows[0]`'s parent); the trusted view supplies the difficulty and
    timestamp history and every new row is fully checked. The trusted
    view is not modified; the result is a new, extended view."""
    if not rows:
        raise HeaderError("no header rows supplied")
    if trusted is not None:
        return _extend(rows, trusted, checkpoint, pow, now, seed_hash_for)
    _check_shape(rows, checkpoint)
    heads, ids = _check_linkage(rows, checkpoint)
    _check_timestamps(rows, heads, now)
    cumulative = _check_difficulty(rows, heads, checkpoint)
    _check_pow(rows, checkpoint, pow, rng, sample, recent,
               seed_hash_for or _seed_lookup(ids, rows[0].height))
    timestamps = [h.timestamp for h in heads]
    if now - timestamps[-1] > STALE_TIP:
        raise HeaderError("stale tip")
    difficulties = [row.difficulty for row in rows]
    blobs = [row.blob for row in rows]
    return ChainView(rows[0].height, ids, timestamps, difficulties, cumulative, blobs,
                     checkpoint.height)


def _extend(rows: list, trusted: ChainView, checkpoint: Checkpoint, pow: PowBackend,
            now: int, seed_hash_for) -> ChainView:
    if rows[0].height != trusted.tip_height + 1:
        raise HeaderError(
            f"rows start at {rows[0].height}, not at the trusted tip {trusted.tip_height} + 1")
    for i in range(1, len(rows)):
        if rows[i].height != rows[i - 1].height + 1:
            raise HeaderError(f"non-contiguous heights at {rows[i].height}")
    ids = list(trusted.ids)
    timestamps = list(trusted.timestamps)
    difficulties = list(trusted.difficulties)
    cumulative = list(trusted.cumulative)
    blobs = list(trusted.blobs)
    seed = seed_hash_for or _seed_lookup(ids, trusted.first)
    limit = now + BLOCK_FUTURE_TIME_LIMIT
    for row in rows:
        try:
            head = parse_hashing_blob(row.blob)
        except ValueError as e:
            raise HeaderError(f"unparseable blob at height {row.height}: {e}") from e
        if head.prev_id != ids[-1]:
            raise HeaderError(f"broken linkage at height {row.height}")
        if head.timestamp > limit:
            raise HeaderError(f"timestamp too far in the future at height {row.height}")
        if len(timestamps) >= 60 and head.timestamp < _median(timestamps[-60:]):
            raise HeaderError(f"timestamp below median of previous 60 at height {row.height}")
        if row.height > checkpoint.height:
            window = DIFFICULTY_BLOCKS_COUNT
            expected = next_difficulty(timestamps[-window:], cumulative[-window:])
            if expected != row.difficulty:
                raise HeaderError(f"difficulty mismatch at height {row.height}")
        elif row.difficulty < 1:
            raise HeaderError(f"non-positive difficulty at height {row.height}")
        if not check_hash(pow.hash(row.blob, row.height, seed(row.height)), row.difficulty):
            raise HeaderError(f"proof-of-work invalid at height {row.height}")
        ids.append(block_id(row.blob))
        timestamps.append(head.timestamp)
        difficulties.append(row.difficulty)
        cumulative.append(cumulative[-1] + row.difficulty)
        blobs.append(row.blob)
    if now - timestamps[-1] > STALE_TIP:
        raise HeaderError("stale tip")
    return ChainView(trusted.first, ids, timestamps, difficulties, cumulative, blobs,
                     checkpoint.height)


def best_view(views: list):
    if not views:
        return None
    return min(views, key=lambda v: (-v.work, v.tip_id))
