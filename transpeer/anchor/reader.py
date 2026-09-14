"""The reader: the newcomer path over anchor-chain headers, tags,
venue shares and blobs (spec §6), weighting and the coverage rule
(§7-§8), seeding the peer store, and blob gossip over /blobs/index
(§5). Slice 3, task 8.
"""

import logging
import time
from dataclasses import dataclass, field

from ..peerstore import PeerStore, TranspeerEntry
from .blob import BlobError, decode_blob
from .blobdb import BlobDB, Commitment
from .fetch import AnchorClient
from .headers import Checkpoint, HeaderRow, best_view, parse_checkpoint, verify_headers
from .merkle import aux_slot, parse_tx_extra_mm_tag, verify_merkle_proof
from .monero import (
    DIFFICULTY_BLOCKS_COUNT, MONERO_BLOCK_TIME, hashing_blob, parse_block_blob,
)
from .powhash import PowBackend
from .share import VENUE_WINDOW, VENUES, parse_share, transpeer_aux, verify_share_pow
from .stores import AnchorStore, ShareStore
from .weight import Share as WeightShare, blob_weights, bootstrapped, coverage, transpeer_weights

logger = logging.getLogger(__name__)

MAX_SOURCES = 5
HEADER_PAGE = 720
SHARE_PAGE = 64
TOP_N_PUBLISH = 64


def venues_from_config(config) -> dict:
    """consensus id -> name, from --anchor-venues (empty means main,
    mini, nano); names resolve through share.VENUES, 64-hex strings are
    taken as consensus ids directly."""
    spec = (config.anchor_venues or "").strip()
    names = [s.strip() for s in spec.split(",") if s.strip()] if spec else ["main", "mini", "nano"]
    out: dict = {}
    for n in names:
        if len(n) == 64:
            try:
                out[bytes.fromhex(n)] = n
                continue
            except ValueError:
                pass
        if n in VENUES:
            out[VENUES[n]] = n
    return out


@dataclass
class ReaderState:
    tagged: int = 0
    resolved: int = 0
    coverage: float = 0.0
    bootstrapped: bool = False
    tip_height: int | None = None
    venues: dict = field(default_factory=dict)          # venue -> canonical tip share id
    weights: dict = field(default_factory=dict)          # (addr, port) -> weight
    published: list = field(default_factory=list)        # [(addr, port), ...]
    last_sync: float = 0.0


class Reader:
    def __init__(self, config, store: PeerStore, blobdb: BlobDB, anchor: AnchorStore,
                shares: dict, client: AnchorClient, pow: PowBackend, clock=time.time, rng=None):
        self.config = config
        self.store = store
        self.blobdb = blobdb
        self.anchor = anchor
        self.shares = shares
        self.client = client
        self.pow = pow
        self.clock = clock
        self.rng = rng
        self.state = ReaderState()
        self._cursors: dict = {}   # (addr, port) -> (since, after)

    @property
    def bootstrapped(self) -> bool:
        return self.state.bootstrapped

    # -- the newcomer path, spec §6-§8 --------------------------------------

    async def sync(self, sources: list) -> ReaderState:
        now = self.clock()
        sources = list(sources)[:MAX_SOURCES]
        checkpoint = parse_checkpoint(self.config.anchor_checkpoint)
        venues = venues_from_config(self.config)

        view = await self._step1_headers(sources, checkpoint, now)
        if view is None:
            self.state.bootstrapped = False
            self._log_state()
            return self.state

        tagged = await self._step2_coverage_window(sources, view)
        venue_tips, resolved = await self._step3_venue_leaves(sources, tagged, venues)
        canonical = await self._step4_canonical_fork(sources, venue_tips)
        await self._step5_blobs(sources, canonical)
        weights = self._step6_weights(canonical)
        published = await self._step7_seeding(weights, now)

        self.state = ReaderState(
            tagged=len(tagged), resolved=resolved,
            coverage=coverage(len(tagged), resolved),
            bootstrapped=bootstrapped(len(tagged), resolved),
            tip_height=view.tip_height, venues=dict(venue_tips),
            weights=weights, published=published, last_sync=now,
        )
        self._log_state()
        return self.state

    async def _step1_headers(self, sources: list, checkpoint: Checkpoint, now: float):
        """Headers: fetch, verify and keep the best-work candidate view
        per source; store the winner in the anchor store."""
        chain = self.config.anchor_chain
        views = []
        for addr, port in sources:
            try:
                tip = await self.client.fetch_tip(addr, port, chain)
                if tip is None:
                    logger.warning("READER: no tip from %s:%d", addr, port)
                    continue
                existing = self.anchor.view
                if existing is not None and existing.tip_height > checkpoint.height:
                    from_height = max(0, existing.tip_height - DIFFICULTY_BLOCKS_COUNT)
                else:
                    from_height = max(0, checkpoint.height - DIFFICULTY_BLOCKS_COUNT)
                rows = []
                cur = from_height
                while cur <= tip:
                    count = min(HEADER_PAGE, tip - cur + 1)
                    page = await self.client.fetch_headers(addr, port, chain, cur, count)
                    if not page:
                        break
                    rows.extend(page)
                    cur = page[-1].height + 1
                    if len(page) < count:
                        break
                if not rows:
                    logger.warning("READER: no headers from %s:%d", addr, port)
                    continue
                kwargs = {"rng": self.rng} if self.rng is not None else {}
                view = verify_headers(rows, checkpoint, self.pow, now, **kwargs)
            except ValueError as e:
                logger.warning("READER: headers from %s:%d rejected: %s", addr, port, e)
                continue
            views.append(view)
        view = best_view(views)
        if view is None:
            return None
        self.anchor.put_headers([
            HeaderRow(view.first + i, view.blobs[i], view.difficulties[i])
            for i in range(len(view.ids))
        ])
        self.anchor.view = view
        return view

    async def _step2_coverage_window(self, sources: list, view) -> dict:
        """Coverage window: fetch and verify coinbases, keep the
        merge-mining tag per tagged block."""
        chain = self.config.anchor_chain
        span = int(self.config.anchor_window_days * 86400 / MONERO_BLOCK_TIME)
        window_from = max(view.tip_height - span, view.first)
        tagged = {}
        for height in range(window_from, view.tip_height + 1):
            blob = self.anchor.block(height)
            if blob is None:
                for addr, port in sources:
                    fetched = await self.client.fetch_block(addr, port, chain, height)
                    if fetched is None:
                        continue
                    try:
                        if hashing_blob(fetched) != view.blobs[height - view.first]:
                            continue
                    except ValueError:
                        continue
                    blob = fetched
                    self.anchor.put_block(height, blob)
                    break
            if blob is None:
                continue
            try:
                tag = parse_tx_extra_mm_tag(parse_block_blob(blob).tx_extra)
            except ValueError:
                tag = None
            if tag is not None:
                tagged[height] = tag
        return tagged

    async def _step3_venue_leaves(self, sources: list, tagged: dict, venues: dict):
        """Venue leaves: resolve each tagged block's venue leaves to
        shares; the first (newest) share per venue is its canonical tip."""
        venue_tips: dict = {}
        resolved = 0
        for height in sorted(tagged, reverse=True):
            tag = tagged[height]
            used_slots = set()
            block_resolved = False
            for cid in venues:
                slot = aux_slot(cid, tag.nonce, tag.n_aux_chains)
                if slot in used_slots:
                    continue
                venue_store = self.shares.setdefault(cid, ShareStore(cid, None))
                share = venue_store.by_root(tag.root)
                if share is None:
                    raw = None
                    for addr, port in sources:
                        raw = await self.client.fetch_share_by_root(addr, port, cid, tag.root)
                        if raw is not None:
                            break
                    if raw is None:
                        continue
                    try:
                        share = parse_share(raw, cid)
                    except ValueError:
                        continue
                if (share.merkle_root != tag.root or share.n_aux_chains != tag.n_aux_chains
                        or share.aux_nonce != tag.nonce or not verify_share_pow(share, self.pow)):
                    continue
                venue_store.add(share)
                used_slots.add(slot)
                block_resolved = True
                if cid not in venue_tips:
                    venue_tips[cid] = share.id
            if block_resolved:
                resolved += 1
        return venue_tips, resolved

    async def _step4_canonical_fork(self, sources: list, venue_tips: dict) -> dict:
        """Canonical fork: walk each venue's tip back through the weight
        window, fetching missing ancestors."""
        canonical = {}
        for cid, tip_id in venue_tips.items():
            venue_store = self.shares.setdefault(cid, ShareStore(cid, None))
            chain = venue_store.walk(tip_id, VENUE_WINDOW)
            while chain and len(chain) < VENUE_WINDOW:
                parent = chain[-1].parent
                if parent == bytes(32) or venue_store.get(parent) is not None:
                    break
                added = 0
                for addr, port in sources:
                    raw_list = await self.client.fetch_shares(addr, port, cid, parent, SHARE_PAGE)
                    if not raw_list:
                        continue
                    batch_added = 0
                    prev = None
                    for raw in raw_list:
                        try:
                            share = parse_share(raw, cid)
                        except ValueError:
                            break
                        if not verify_share_pow(share, self.pow):
                            break
                        if prev is not None and (share.id != prev.parent
                                                  or share.height != prev.height - 1):
                            break
                        if venue_store.add(share):
                            batch_added += 1
                        prev = share
                    added += batch_added
                    if batch_added:
                        break
                if added == 0:
                    break
                chain = venue_store.walk(tip_id, VENUE_WINDOW)
            canonical[cid] = chain
        return canonical

    async def _step5_blobs(self, sources: list, canonical: dict) -> None:
        """Blobs: fetch and store the list blob each canonical share
        commits to, if not already held."""
        now = int(self.clock())
        for cid, chain in canonical.items():
            for share in chain:
                h = transpeer_aux(share)
                if h is None or self.blobdb.get(h) is not None:
                    continue
                blob = None
                for addr, port in sources:
                    blob = await self.client.fetch_blob(addr, port, h)
                    if blob is not None:
                        break
                if blob is None:
                    continue
                try:
                    decode_blob(blob)
                except BlobError:
                    continue
                commitment = Commitment(h, "share", cid.hex(), share.id.hex(), share.wallet,
                                        share.difficulty, share.timestamp)
                self.blobdb.add(blob, commitment, now)

    def _step6_weights(self, canonical: dict) -> dict:
        """Weights: difficulty-weighted, venue-additive (spec §7)."""
        bw: dict = {}
        for cid, chain in canonical.items():
            wshares = [
                WeightShare(id=s.id, venue=cid.hex(), height=s.height, parent=s.parent,
                            difficulty=s.difficulty, timestamp=s.timestamp, wallet=s.wallet,
                            aux={c: h for c, (h, _diff) in s.aux.items()})
                for s in chain
            ]
            for h, w in blob_weights(wshares).items():
                bw[h] = bw.get(h, 0) + w
        return transpeer_weights(bw, self.blobdb)

    async def _step7_seeding(self, weights: dict, now: float) -> list:
        """Seeding: seed the store with the top-weight transpeers,
        tagged published; un-tag entries that dropped out."""
        top = sorted(weights.items(), key=lambda kv: (-kv[1], kv[0]))[:TOP_N_PUBLISH]
        published = [entry for entry, _w in top]
        published_set = set(published)
        for addr, port in published:
            if self.store.get_transpeer(addr, port) is None:
                await self.store.add_transpeer(TranspeerEntry(addr, port, last_seen=int(now)))
            await self.store.set_published(addr, port, True)
        for entry in self.store.get_transpeers():
            if entry.published and (entry.addr, entry.port) not in published_set:
                await self.store.set_published(entry.addr, entry.port, False)
        return published

    def _log_state(self) -> None:
        s = self.state
        logger.info(
            "READER_STATE tagged=%d resolved=%d coverage=%.2f bootstrapped=%s tip=%s venues=%d published=%d",
            s.tagged, s.resolved, s.coverage, s.bootstrapped, s.tip_height, len(s.venues), len(s.published),
        )

    # -- blob gossip, spec §5 ------------------------------------------------

    async def gossip(self, addr: str, port: int) -> int:
        since, after = self._cursors.get((addr, port), (0, b""))
        rows, _next_since, _next_after = await self.client.fetch_index(addr, port, since, after)
        stored = 0
        ok = True
        for row in rows:
            try:
                processed, added = await self._gossip_row(addr, port, row)
            except ValueError:
                processed, added = False, 0
            stored += added
            if not processed:
                ok = False
        if ok and rows:
            last = rows[-1]
            try:
                self._cursors[(addr, port)] = (int(last["first_seen"]), bytes.fromhex(last["hash"]))
            except (KeyError, ValueError, TypeError):
                pass
        return stored

    async def _gossip_row(self, addr: str, port: int, row: dict):
        try:
            h = bytes.fromhex(row["hash"])
        except (KeyError, ValueError, TypeError):
            return False, 0
        if self.blobdb.get(h) is not None:
            return True, 0
        blob = await self.client.fetch_blob(addr, port, h)
        if blob is None:
            return False, 0
        verified = []
        for cdict in row.get("commitments", []):
            try:
                commitment = Commitment.from_dict(cdict)
            except (KeyError, ValueError, TypeError):
                continue
            if commitment.hash != h or commitment.kind == "template":
                continue
            ok_c = False
            if commitment.kind == "share":
                ok_c = await self._verify_share_commitment(addr, port, commitment)
            elif commitment.kind == "block":
                ok_c = await self._verify_block_commitment(addr, port, commitment)
            if ok_c:
                verified.append(commitment)
        if not verified:
            return True, 0
        now = int(self.clock())
        added_any = False
        for commitment in verified:
            if self.blobdb.add(blob, commitment, now):
                added_any = True
        return True, (1 if added_any else 0)

    async def _verify_share_commitment(self, addr: str, port: int, commitment: Commitment) -> bool:
        try:
            venue = bytes.fromhex(commitment.venue)
            share_id = bytes.fromhex(commitment.ref)
        except ValueError:
            return False
        raw = await self.client.fetch_share(addr, port, venue, share_id)
        if raw is None:
            return False
        try:
            share = parse_share(raw, venue)
        except ValueError:
            return False
        if not verify_share_pow(share, self.pow):
            return False
        return transpeer_aux(share) == commitment.hash

    async def _verify_block_commitment(self, addr: str, port: int, commitment: Commitment) -> bool:
        try:
            height_s, _hex_id = commitment.ref.split(":", 1)
            height = int(height_s)
        except ValueError:
            return False
        blob = self.anchor.block(height)
        if blob is None:
            blob = await self.client.fetch_block(addr, port, self.config.anchor_chain, height)
            if blob is None:
                return False
            view = self.anchor.view
            if view is None or not (view.first <= height <= view.tip_height):
                return False
            try:
                if hashing_blob(blob) != view.blobs[height - view.first]:
                    return False
            except ValueError:
                return False
            self.anchor.put_block(height, blob)
        try:
            tag = parse_tx_extra_mm_tag(parse_block_blob(blob).tx_extra)
        except ValueError:
            return False
        if tag is None:
            return False
        return verify_merkle_proof(commitment.hash, list(commitment.proof), commitment.path, tag.root)

    # -- faithfulness challenges, for Task 11 --------------------------------

    def verified_hashes(self, min_age: int) -> list:
        """Blob hashes stored with at least one verified commitment older
        than min_age seconds. Every commitment the reader holds was
        verified by sync or gossip before being stored."""
        now = self.clock()
        out = []
        for h, first_seen, commitments in self.blobdb.index_since(0, limit=1 << 30):
            if commitments and now - first_seen >= min_age:
                out.append(h)
        return out
