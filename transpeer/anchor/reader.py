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
from .headers import (Checkpoint, HEADER_LOOKBACK, HeaderError, HeaderRow, STALE_TIP,
                      best_view, parse_checkpoint, verify_headers)
from .merkle import aux_slot, parse_tx_extra_mm_tag, verify_merkle_proof
from .monero import MONERO_BLOCK_TIME, hashing_blob, parse_block_blob, seed_height
from .powhash import PowBackend
from .share import VENUE_WINDOW, VENUES, parse_share, transpeer_aux, verify_share_pow
from .stores import AnchorStore, ShareStore, venue_dir
from .weight import Share as WeightShare, blob_weights, bootstrapped, coverage, transpeer_weights

logger = logging.getLogger(__name__)

MAX_SOURCES = 5
HEADER_PAGE = 720
SHARE_PAGE = 64
TOP_N_PUBLISH = 64
# A tip further past the checkpoint than this is refused: a hostile tip
# of 10**18 would otherwise page the reader into an allocation death.
# About 1.5 years of Monero blocks; a release checkpoint older than that
# must be refreshed (spec §17.1).
MAX_BLOCKS_PAST_CHECKPOINT = 400_000
# Per-sync fetch budgets. A sync that runs out ends normally; the next
# cycle continues where it stopped.
MAX_BLOCK_FETCHES = 720
MAX_SHARE_BATCHES = 40
MAX_LEAF_FETCHES = 256
# Total timeout the reader gives each request to another transpeer.
CLIENT_TIMEOUT = 5.0
# Venues a sync will take from what sources advertise, on top of the
# configured ones (spec §6.4: venues are discovered from tags).
MAX_DISCOVERED_VENUES = 16
# A discovered venue that holds no shares and that no source has
# advertised for this long is forgotten again.
DISCOVERED_TTL = 86400
# A newcomer that has fetched less of the coverage window than this is
# never bootstrapped, whatever the coverage of what it did fetch.
MIN_WINDOW_FETCHED = 0.9


def coverage_from(view, anchor_window_days: float) -> int:
    """First height of the coverage window: anchor_window_days back from
    the tip, in expected Monero blocks, clamped to the view's start.
    Shared with node.py's _anchor_source_loop."""
    span = int(anchor_window_days * 86400 / MONERO_BLOCK_TIME)
    return max(view.tip_height - span, view.first)


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
    window_blocks: int = 0
    fetched_blocks: int = 0
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
        self.discovered: dict = {}   # discovered venue -> last advertised (reader clock)
        self._cursors: dict = {}   # (addr, port) -> (since, after)

    @property
    def bootstrapped(self) -> bool:
        return self.state.bootstrapped

    # -- the newcomer path, spec §6-§8 --------------------------------------

    async def sync(self, sources: list) -> ReaderState:
        now = self.clock()
        sources = list(sources)[:MAX_SOURCES]
        checkpoint = parse_checkpoint(self.config.anchor_checkpoint)

        try:
            view = await self._step1_headers(sources, checkpoint, now)
            if view is None:
                self.state.bootstrapped = False
                self._log_state()
                return self.state

            window_from = coverage_from(view, self.config.anchor_window_days)
            tagged, missing, fetched = await self._step2_coverage_window(
                sources, view, window_from)
            venues = await self._candidate_venues(sources)
            venue_tips, resolved = await self._step3_venue_leaves(sources, tagged, venues, view)
            canonical = await self._step4_canonical_fork(sources, venue_tips, view)
            await self._step5_blobs(sources, canonical)
            weights = self._step6_weights(canonical)
            published = await self._step7_seeding(weights, now)
        except (ValueError, TypeError, KeyError) as e:
            # Source data is untrusted: a sync abandoned on it keeps the
            # last good state rather than taking down the reader loop.
            logger.warning("READER: sync abandoned: %s", e)
            self._log_state()
            return self.state

        window_blocks = view.tip_height - window_from + 1
        tagged_total = len(tagged) + missing
        self._prune(view, checkpoint, canonical, window_from)
        self.state = ReaderState(
            tagged=tagged_total, resolved=resolved,
            coverage=coverage(tagged_total, resolved),
            bootstrapped=(bootstrapped(tagged_total, resolved)
                          and fetched >= MIN_WINDOW_FETCHED * window_blocks),
            tip_height=view.tip_height, window_blocks=window_blocks, fetched_blocks=fetched,
            venues=dict(venue_tips), weights=weights, published=published, last_sync=now,
        )
        self._log_state()
        return self.state

    def _venue_store(self, cid: bytes) -> ShareStore:
        """The store for a venue, created on first use so that venues
        discovered from tags are kept and served like configured ones."""
        store = self.shares.get(cid)
        if store is None:
            path = None if self.config.in_memory else venue_dir(self.config.data_dir, cid)
            store = ShareStore(cid, path)
            self.shares[cid] = store
        return store

    async def _candidate_venues(self, sources: list) -> dict:
        """Configured venues plus what the sources advertise at /venues
        (spec §6.4). At most MAX_DISCOVERED_VENUES discovered venues are
        kept in total; a discovered venue that holds no shares and that
        no source has advertised for DISCOVERED_TTL is forgotten."""
        venues = venues_from_config(self.config)
        now = self.clock()
        advertised = []
        for addr, port in sources:
            for cid in await self.client.fetch_venues(addr, port):
                if cid not in venues and cid not in advertised:
                    advertised.append(cid)
        for cid in advertised:
            if cid in self.discovered:
                self.discovered[cid] = now
        self._expire_discovered(now)
        for cid in advertised:
            if cid in self.discovered:
                continue
            if len(self.discovered) >= MAX_DISCOVERED_VENUES:
                break
            self.discovered[cid] = now
        for cid in self.discovered:
            venues[cid] = cid.hex()
        return venues

    def _expire_discovered(self, now: float) -> None:
        """Drop discovered venues that are both empty and unadvertised:
        the store object goes, any directory on disk is left alone."""
        for cid, last in list(self.discovered.items()):
            store = self.shares.get(cid)
            if now - last > DISCOVERED_TTL and (store is None or store.count() == 0):
                del self.discovered[cid]
                self.shares.pop(cid, None)
                logger.info("READER: forgetting idle empty venue %s", cid.hex())

    def _seed_for(self, view, height: int):
        """The RandomX seed hash for a block or share at `height`: the id
        of the block at its seed height, or None when the view does not
        reach that far back."""
        sh = seed_height(height)
        if view is None or not (view.first <= sh <= view.tip_height):
            return None
        return view.id_at(sh)

    def _prune(self, view, checkpoint: Checkpoint, canonical: dict, window_from: int) -> None:
        """Block blobs older than the coverage window and headers older
        than the lookback are dead weight; venue stores prune as P2Pool
        does, at four windows of age."""
        self.anchor.prune_blocks(max(0, window_from - 1))
        self.anchor.prune_headers(max(0, checkpoint.height - HEADER_LOOKBACK))
        for cid, chain in canonical.items():
            if chain:
                self._venue_store(cid).prune(chain[0].height)

    async def _step1_headers(self, sources: list, checkpoint: Checkpoint, now: float):
        """Headers: fetch, verify and keep the best-work candidate view
        per source; store the winner in the anchor store. With a view
        already verified, each source is asked only for what extends it
        and the extension is verified against that trusted prefix; a
        source on another chain (or a reorg) falls back to a full fetch
        from the lookback start."""
        chain = self.config.anchor_chain
        existing = self.anchor.view
        kwargs = {"rng": self.rng} if self.rng is not None else {}
        views = []
        for addr, port in sources:
            try:
                tip = await self.client.fetch_tip(addr, port, chain)
                if tip is None:
                    logger.warning("READER: no tip from %s:%d", addr, port)
                    continue
                if not (checkpoint.height <= tip <= checkpoint.height + MAX_BLOCKS_PAST_CHECKPOINT):
                    logger.warning("READER: %s:%d reports tip %d, out of bounds for "
                                   "checkpoint %d", addr, port, tip, checkpoint.height)
                    continue
                view = None
                if existing is not None and existing.tip_height >= checkpoint.height:
                    fresh = now - existing.timestamps[-1] <= STALE_TIP
                    if tip <= existing.tip_height and fresh:
                        views.append(existing)
                        continue
                    if not fresh:
                        # Spec §6.2: a stored view whose own tip has gone
                        # stale is not a current view, so a source that
                        # cannot extend it is offering nothing at all.
                        logger.warning("READER: %s:%d: stale stored view; refetching",
                                       addr, port)
                    rows = []
                    if tip > existing.tip_height:
                        rows = await self._fetch_header_range(
                            addr, port, chain, existing.tip_height + 1, tip)
                    if rows:
                        try:
                            view = verify_headers(rows, checkpoint, self.pow, now,
                                                  trusted=existing, **kwargs)
                        except HeaderError as e:
                            logger.warning("READER: %s:%d does not extend the stored tip "
                                           "(%s); refetching in full", addr, port, e)
                            view = None
                if view is None:
                    start = max(0, checkpoint.height - HEADER_LOOKBACK)
                    rows = await self._fetch_header_range(addr, port, chain, start, tip)
                    if not rows:
                        continue
                    view = verify_headers(rows, checkpoint, self.pow, now, **kwargs)
            except (ValueError, TypeError, KeyError) as e:
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

    async def _fetch_header_range(self, addr: str, port: int, chain: str,
                                  from_height: int, tip: int) -> list:
        """Page [from_height, tip] from one source. Returns [] when the
        source pages badly (empty, misaligned, non-contiguous or making
        no progress) rather than trusting a partial run."""
        rows = []
        cur = from_height
        while cur <= tip:
            count = min(HEADER_PAGE, tip - cur + 1)
            page = await self.client.fetch_headers(addr, port, chain, cur, count)
            if not page or page[0].height != cur:
                logger.warning("READER: %s:%d served an empty or misaligned "
                               "header page at %d", addr, port, cur)
                return []
            for i in range(1, len(page)):
                if page[i].height != page[i - 1].height + 1:
                    logger.warning("READER: %s:%d served a non-contiguous header page "
                                   "at %d", addr, port, cur)
                    return []
            # Never trust a page past the tip we asked for.
            page = [row for row in page if row.height <= tip]
            if not page:
                break
            rows.extend(page)
            progressed = page[-1].height + 1
            if progressed <= cur:
                logger.warning("READER: %s:%d header page made no progress at %d",
                               addr, port, cur)
                return []
            cur = progressed
            if len(page) < count:
                break
        if not rows:
            logger.warning("READER: no headers from %s:%d", addr, port)
        return rows

    async def _step2_coverage_window(self, sources: list, view, window_from: int):
        """Coverage window: fetch and verify coinbases, keep the
        merge-mining tag per tagged block. Returns the tags, the count of
        window blocks whose blob no source served (spec §8: they count as
        tagged and unresolved, so withholding cannot raise coverage) and
        the count of window blocks held."""
        chain = self.config.anchor_chain
        tagged = {}
        missing = 0
        fetched = 0
        budget = MAX_BLOCK_FETCHES
        for height in range(window_from, view.tip_height + 1):
            blob = self.anchor.block(height)
            if blob is None and budget > 0:
                for addr, port in sources:
                    if budget <= 0:
                        break
                    budget -= 1
                    try:
                        candidate = await self.client.fetch_block(addr, port, chain, height)
                        if candidate is None:
                            continue
                        if hashing_blob(candidate) != view.blobs[height - view.first]:
                            continue
                    except (ValueError, TypeError, KeyError, IndexError):
                        continue
                    blob = candidate
                    self.anchor.put_block(height, blob)
                    break
            if blob is None:
                missing += 1
                continue
            fetched += 1
            try:
                tag = parse_tx_extra_mm_tag(parse_block_blob(blob).tx_extra)
            except (ValueError, TypeError, KeyError):
                tag = None
            if tag is not None:
                tagged[height] = tag
        return tagged, missing, fetched

    async def _step3_venue_leaves(self, sources: list, tagged: dict, venues: dict, view):
        """Venue leaves: resolve each tagged block's venue leaves to
        shares; the first (newest) share per venue is its canonical tip."""
        venue_tips: dict = {}
        resolved = 0
        budget = MAX_LEAF_FETCHES
        for height in sorted(tagged, reverse=True):
            tag = tagged[height]
            used_slots = set()
            block_resolved = False
            for cid in venues:
                slot = aux_slot(cid, tag.nonce, tag.n_aux_chains)
                if slot in used_slots:
                    continue
                venue_store = self._venue_store(cid)
                share = venue_store.by_root(tag.root)
                if share is None:
                    raw = None
                    for addr, port in sources:
                        if budget <= 0:
                            break
                        budget -= 1
                        raw = await self.client.fetch_share_by_root(addr, port, cid, tag.root)
                        if raw is not None:
                            break
                    if raw is None:
                        continue
                    try:
                        share = parse_share(raw, cid)
                    except (ValueError, TypeError, KeyError):
                        continue
                seed = self._seed_for(view, share.txin_gen_height)
                if seed is None:
                    logger.warning("READER: share %s names height %d, outside the view",
                                   share.id.hex(), share.txin_gen_height)
                    continue
                if (share.merkle_root != tag.root or share.n_aux_chains != tag.n_aux_chains
                        or share.aux_nonce != tag.nonce
                        or not verify_share_pow(share, self.pow, seed)):
                    continue
                venue_store.add(share)
                used_slots.add(slot)
                block_resolved = True
                if cid not in venue_tips:
                    venue_tips[cid] = share.id
            if block_resolved:
                resolved += 1
        return venue_tips, resolved

    async def _step4_canonical_fork(self, sources: list, venue_tips: dict, view) -> dict:
        """Canonical fork: walk each venue's tip back through the weight
        window, fetching missing ancestors. Every fetched batch must be
        anchored to the parent id we asked for -- batch[0].id == parent,
        and each following share is the previous one's named parent, one
        height lower -- so a source cannot feed unrelated shares forever;
        the walk is also hard-capped at VENUE_WINDOW regardless of what
        any source does, and at MAX_SHARE_BATCHES batches per sync."""
        canonical = {}
        for cid, tip_id in venue_tips.items():
            venue_store = self._venue_store(cid)
            chain = venue_store.walk(tip_id, VENUE_WINDOW)
            batches = 0
            while chain and len(chain) < VENUE_WINDOW and batches < MAX_SHARE_BATCHES:
                parent = chain[-1].parent
                if parent == bytes(32) or venue_store.get(parent) is not None:
                    break
                added = 0
                for addr, port in sources:
                    batches += 1
                    raw_list = await self.client.fetch_shares(addr, port, cid, parent, SHARE_PAGE)
                    if not raw_list:
                        continue
                    batch_added = 0
                    expected_id = parent
                    prev_height = None
                    for raw in raw_list:
                        try:
                            share = parse_share(raw, cid)
                        except (ValueError, TypeError, KeyError):
                            logger.warning("READER: %s:%d served an unparseable share "
                                           "in venue %s", addr, port, cid.hex())
                            break
                        seed = self._seed_for(view, share.txin_gen_height)
                        if seed is None or not verify_share_pow(share, self.pow, seed):
                            logger.warning("READER: %s:%d served a share with invalid "
                                           "PoW in venue %s", addr, port, cid.hex())
                            break
                        if share.id != expected_id or (
                                prev_height is not None and share.height != prev_height - 1):
                            logger.warning("READER: %s:%d served a share batch not "
                                           "anchored to the requested parent in venue %s; "
                                           "dropping the rest of the batch", addr, port, cid.hex())
                            break
                        if venue_store.add(share):
                            batch_added += 1
                        expected_id = share.parent
                        prev_height = share.height
                        if len(chain) + batch_added >= VENUE_WINDOW:
                            break
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
                except (BlobError, ValueError, TypeError, KeyError):
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
            "READER_STATE tagged=%d resolved=%d coverage=%.2f bootstrapped=%s tip=%s "
            "window=%d fetched=%d venues=%d published=%d",
            s.tagged, s.resolved, s.coverage, s.bootstrapped, s.tip_height,
            s.window_blocks, s.fetched_blocks, len(s.venues), len(s.published),
        )

    # -- blob gossip, spec §5 ------------------------------------------------

    async def gossip(self, addr: str, port: int) -> int:
        since, after = self._cursors.get((addr, port), (0, b""))
        rows, next_since, next_after = await self.client.fetch_index(addr, port, since, after)
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
            # The response names next_since/next_after (spec §5) when the
            # page was full; when it wasn't, there is no next page, so
            # resume just after the last row we processed.
            if next_since is not None and next_after is not None:
                self._cursors[(addr, port)] = (next_since, next_after)
            else:
                last = rows[-1]
                try:
                    self._cursors[(addr, port)] = (int(last["first_seen"]), bytes.fromhex(last["hash"]))
                except (KeyError, ValueError, TypeError):
                    pass
        return stored

    async def gossip_entry(self, entry) -> int:
        """Gossip against a queried TranspeerEntry, for use as the client's
        after_query callback."""
        return await self.gossip(entry.addr, entry.port)

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
        seed = self._seed_for(self.anchor.view, share.txin_gen_height)
        if seed is None or not verify_share_pow(share, self.pow, seed):
            return False
        return transpeer_aux(share) == commitment.hash

    @staticmethod
    def _matches(blob: bytes, expected: bytes) -> bool:
        try:
            return hashing_blob(blob) == expected
        except (ValueError, TypeError, KeyError):
            return False

    async def _verify_block_commitment(self, addr: str, port: int, commitment: Commitment) -> bool:
        try:
            height_s, _hex_id = commitment.ref.split(":", 1)
            height = int(height_s)
        except ValueError:
            return False
        view = self.anchor.view
        if view is None or not (view.first <= height <= view.tip_height):
            return False
        expected = view.blobs[height - view.first]
        blob = self.anchor.block(height)
        if blob is not None and not self._matches(blob, expected):
            # The cache predates the current view (a reorg, or a blob
            # stored under another chain): do not read a tag out of it.
            blob = None
        if blob is None:
            blob = await self.client.fetch_block(addr, port, self.config.anchor_chain, height)
            if blob is None or not self._matches(blob, expected):
                return False
            self.anchor.put_block(height, blob)
        try:
            tag = parse_tx_extra_mm_tag(parse_block_blob(blob).tx_extra)
        except (ValueError, TypeError, KeyError):
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
