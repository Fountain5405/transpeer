"""Main transpeer node — orchestrates all components."""

import asyncio
import ipaddress
import logging
import os
import time

from aiohttp import web

from .client import TranspeerClient
from .config import (
    Config, EXTRACT_INTERVAL, QUERY_INTERVAL, SCAN_INTERVAL, QUERY_BATCH_SIZE,
    TIMESTAMP_BUCKET_SECS,
)
from .networks import get_network
from .peerstore import Peer, PeerStore
from .pow import solve as pow_solve, solve_simulated as pow_solve_sim
from .scanner import Scanner
from .server import TranspeerServer
from .verifier import verify_peers

log = logging.getLogger(__name__)


class Node:
    def __init__(self, config: Config):
        self.config = config
        self.node_id = os.urandom(4).hex()
        self.start_time = time.time()
        self.store = PeerStore(config)
        self.client = TranspeerClient(config, self.store)
        self.scanner = Scanner(config, self.store, self.client, self.node_id)
        self.server = None  # Created after networks are loaded
        self._networks = {}
        # (network, addr, port) -> (nonce, solution, bucket) for peers we
        # publish ourselves. A proof is valid for a whole timestamp bucket.
        self._local_proofs: dict[tuple[str, str, int], tuple[bytes, bytes, int]] = {}
        # addr -> time we last queued a daemon peer for a transpeer probe.
        self._daemon_peer_probed: dict[str, float] = {}
        # Chain-anchored publication (--anchor-publish); built in run().
        self.blobdb = None
        self.publisher = None
        self.auxrpc = None
        self._anchor_saved = (0, 0)
        # Chain-anchored reading (--anchor-read); built in run().
        self.reader = None
        for spec in config.networks:
            try:
                net = get_network(spec)
                net.share_white_list = config.share_white_list
                self._networks[net.name] = net
            except ValueError:
                log.warning("Unknown network: %s", spec)

    async def run(self):
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        )
        log.info("Starting transpeer node %s on port %d", self.node_id, self.config.port)
        log.info("Networks: %s", ", ".join(self._networks.keys()))

        await self.store.init()
        # Ports of the networks we run, for the native probe (--native-vouchers).
        self.config.native_ports = {
            name: net.default_port for name, net in self._networks.items()
        }
        self._sim_listeners = []
        if self.config.sim_daemon_listen:
            async def _accept_and_close(reader, writer):
                writer.close()
            for name, net in self._networks.items():
                srv = await asyncio.start_server(
                    _accept_and_close, self.config.bind, net.default_port)
                self._sim_listeners.append(srv)
                log.info("Sim daemon listener for %s on port %d", name, net.default_port)
        if self.config.anchor_publish:
            from .anchor.blobdb import BlobDB
            from .anchor.publisher import Publisher
            from .anchor.auxrpc import AuxRpcServer
            self._anchor_path = self.config.data_dir / "anchor_blobs.json"
            self.blobdb = BlobDB() if self.config.in_memory else BlobDB.load(self._anchor_path)
            self.publisher = Publisher(self.config, self.store, self.blobdb)
            self.auxrpc = AuxRpcServer(self.publisher, self.blobdb, self.config.aux_diff)
            log.info("Anchor publisher on: %d blobs loaded, aux RPC on %s:%d, aux_diff %d",
                     self.blobdb.blob_count(), self.config.aux_rpc_bind,
                     self.config.aux_rpc_port, self.config.aux_diff)

        if self.config.anchor_read:
            from .anchor.blobdb import BlobDB
            from .anchor.fetch import AnchorClient
            from .anchor.powhash import PowUnavailable, backend_for
            from .anchor.reader import Reader, venues_from_config
            from .anchor.stores import AnchorStore, ShareStore, venue_dir
            if self.blobdb is None:
                anchor_blobs_path = self.config.data_dir / "anchor_blobs.json"
                self.blobdb = (
                    BlobDB() if self.config.in_memory else BlobDB.load(anchor_blobs_path)
                )
                self._anchor_path = anchor_blobs_path
            self._anchor_store = AnchorStore(
                None if self.config.in_memory else self.config.data_dir / "anchor_chain.json"
            )
            self._anchor_store.load()
            self._share_stores = {}
            for venue in venues_from_config(self.config):
                store = ShareStore(
                    venue,
                    None if self.config.in_memory
                    else venue_dir(self.config.data_dir, venue),
                )
                store.load()
                self._share_stores[venue] = store
            anchor_client = AnchorClient(self.config)
            try:
                pow_backend = backend_for(self.config)
            except PowUnavailable as e:
                log.error("%s", e)
                raise SystemExit(2) from e
            self.reader = Reader(
                self.config, self.store, self.blobdb, self._anchor_store,
                self._share_stores, anchor_client, pow_backend,
            )
            self.scanner._idle_fn = lambda: self.reader.bootstrapped
            self.client.after_query = self.reader.gossip_entry

        self.server = TranspeerServer(
            self.config, self.store, self.node_id, self.start_time,
            network_names=list(self._networks.keys()),
            blobdb=self.blobdb, publisher=self.publisher,
            anchor_store=self._anchor_store if self.config.anchor_read else None,
            share_stores=self._share_stores if self.config.anchor_read else None,
        )

        try:
            # Start HTTP server
            app = self.server.create_app()
            runner = web.AppRunner(app)
            await runner.setup()
            site = web.TCPSite(runner, self.config.bind, self.config.port)
            await site.start()
            log.info("HTTP server listening on %s:%d", self.config.bind, self.config.port)

            if self.auxrpc is not None:
                aux_runner = web.AppRunner(self.auxrpc.create_app())
                await aux_runner.setup()
                await web.TCPSite(aux_runner, self.config.aux_rpc_bind, self.config.aux_rpc_port).start()
                log.info("Aux-chain RPC listening on %s:%d", self.config.aux_rpc_bind, self.config.aux_rpc_port)
                try:
                    is_loopback = ipaddress.ip_address(self.config.aux_rpc_bind).is_loopback
                except ValueError:
                    is_loopback = False
                if not is_loopback:
                    log.warning("Aux-chain RPC bound to %s: this interface trusts its caller; "
                                "restrict it to your own P2Pool node with a firewall.",
                                self.config.aux_rpc_bind)

            # Run periodic tasks
            await asyncio.gather(
                self._extract_loop(),
                self._scan_loop(),
                self._query_loop(),
                self._verify_loop(),
                self._prune_loop(),
                self._candidate_loop(),
                self._snapshot_loop(),
                self._anchor_loop(),
                self._reader_loop(),
            )
        finally:
            await self.store.close()

    async def _extract_peer_infos(self, name: str, network):
        """Get peer infos from daemon RPC, or static list if configured."""
        if self.config.static_peers and name in self.config.static_peers:
            from .networks.base import PeerInfo
            return [PeerInfo(addr=a, port=p) for a, p in self.config.static_peers[name]]
        return await network.extract_peers()

    async def _extract_loop(self):
        """Periodically extract peers from local daemons."""
        while True:
            for name, network in self._networks.items():
                try:
                    peer_infos = await self._extract_peer_infos(name, network)
                    now = int(time.time())
                    if not self.config.scan_legacy:
                        self._queue_daemon_peers(peer_infos, now)
                    for info in peer_infos:
                        # Only solve when we hold no proof for this peer in
                        # the current bucket. Re-solving every cycle cost
                        # one EquiX solve per peer per minute, and in
                        # simulation each solve is a blocking sleep.
                        cache_key = (name, info.addr, info.port)
                        cached = self._local_proofs.get(cache_key)
                        if cached and cached[2] == now // TIMESTAMP_BUCKET_SECS:
                            nonce, solution, bucket = cached
                        elif self.config.no_pow:
                            nonce, solution, bucket = b"\x00" * 16, b"\x00" * 16, 0
                        elif self.config.sim_pow:
                            nonce, solution, bucket = pow_solve_sim(
                                name, info.addr, info.port, self.config.difficulty,
                            )
                        else:
                            nonce, solution, bucket = pow_solve(
                                name, info.addr, info.port, self.config.difficulty,
                            )
                        self._local_proofs[cache_key] = (nonce, solution, bucket)
                        peer = Peer(
                            network=name,
                            addr=info.addr,
                            port=info.port,
                            last_seen=now,
                            sources=1,
                            verified=True,  # We got it from a local daemon
                            nonce=nonce,
                            effort=self.config.difficulty,
                            solution=solution,
                            timestamp_bucket=bucket,
                        )
                        await self.store.add_peer(peer)
                except Exception as e:
                    log.error("Failed to extract peers from %s: %s", name, e)
            await asyncio.sleep(EXTRACT_INTERVAL)

    def _queue_daemon_peers(self, peer_infos, now: int):
        """Discovery through the networks we already belong to: every peer
        our daemon talks to is a host that may also run a transpeer, so
        queue it for a probe on the transpeer port. These hosts are in a
        P2P relationship with us already; probing them is not blind
        scanning. Each address is queued at most once per six hours."""
        for info in peer_infos:
            last = self._daemon_peer_probed.get(info.addr, 0)
            if now - last >= 6 * 3600:
                self._daemon_peer_probed[info.addr] = now
                self.store.add_candidate(info.addr)

    async def _scan_loop(self):
        """Continuously scan random IPs for transpeers.

        Legacy profile: a burst, then a full interval's pause, as before.
        Paced profile: the batch itself spans the interval, so only the
        remainder is slept and the configured rate is the wire rate.
        """
        while True:
            t0 = time.monotonic()
            try:
                await self.scanner.scan_batch()
            except Exception as e:
                log.error("Scan error: %s", e)
            if self.config.scan_legacy:
                await asyncio.sleep(SCAN_INTERVAL)
            else:
                await asyncio.sleep(max(0.0, SCAN_INTERVAL - (time.monotonic() - t0)))

    async def _query_loop(self):
        """Periodically query a batch of known transpeers for their data.

        Uses rotation: queries the oldest-not-recently-queried transpeers
        first. Queries run concurrently within each batch to bound cycle time.
        """
        while True:
            await asyncio.sleep(QUERY_INTERVAL)
            batch = self.store.get_transpeers_for_query(QUERY_BATCH_SIZE)
            if not batch:
                continue
            total_known = len(self.store.get_transpeers())
            log.info("Querying batch of %d (of %d known transpeers)",
                     len(batch), total_known)

            async def _query_one(entry):
                try:
                    answered = await self.client.query_transpeer(entry)
                    self.store.mark_queried(entry.addr, entry.port,
                                            answered=bool(answered))
                except Exception as e:
                    log.error("Error querying transpeer %s: %s", entry.addr, e)

            await asyncio.gather(*(_query_one(e) for e in batch))

    async def _verify_loop(self):
        """Periodically verify peers are actually reachable.

        Uses network-specific handshake verification for networks we run
        (checks protocol magic bytes). Falls back to TCP-only for networks
        we don't run (can only check if port is open).
        """
        if self.config.no_verify:
            log.info("Verification disabled by --no-verify")
            return
        while True:
            await asyncio.sleep(EXTRACT_INTERVAL * 5)  # Less frequent than extraction
            # Verify all networks we have peers for, not just ones we run
            all_networks = self.store.get_all_networks()
            for name in all_networks:
                try:
                    plugin = self._networks.get(name)  # None if we don't run it
                    await verify_peers(self.store, name, network_plugin=plugin)
                except Exception as e:
                    log.error("Verification error for %s: %s", name, e)

    async def _prune_loop(self):
        """Periodically prune stale entries."""
        while True:
            await asyncio.sleep(3600)  # Every hour
            try:
                await self.store.prune_stale()
                log.info("Pruned stale entries")
            except Exception as e:
                log.error("Prune error: %s", e)

    async def _snapshot_loop(self):
        """Log the store's composition periodically (simulation metric).

        One line, parseable: transpeer addresses and peer counts keyed by
        the transpeer that supplied them, so an experiment can attribute
        the store to honest or attacker sources by IP.
        """
        interval = self.config.snapshot_interval
        if interval <= 0:
            return
        while True:
            await asyncio.sleep(interval)
            try:
                s = self.store.snapshot(networks=list(self._networks))
                log.info(
                    "STORE_SNAPSHOT transpeers=%d buckets=%d peers=%d "
                    "transpeer_addrs=%s peer_sources=%s voucher_hist=%s daemon_view=%s "
                    "tried_addrs=%s unrepresented=%s native_tp=%d",
                    s["transpeers"], s["buckets"], s["peers"],
                    ",".join(s["transpeer_addrs"]),
                    ";".join(f"{a}:{n}" for a, n in sorted(s["peer_sources"].items())),
                    ";".join(f"{k}:{v}" for k, v in sorted(s["voucher_hist"].items())),
                    "|".join(f"{net}:{','.join(srcs)}"
                             for net, srcs in s["daemon_view"].items()),
                    ",".join(s["tried_addrs"]),
                    "|".join(f"{net}:{n}" for net, n in s["unrepresented"].items()),
                    s["native_transpeers"],
                )
            except Exception as e:
                log.error("Snapshot error: %s", e)

    async def _candidate_loop(self):
        """Periodically probe IPs that queried us."""
        while True:
            await asyncio.sleep(30)
            try:
                await self.scanner.probe_candidates()
            except Exception as e:
                log.error("Candidate probe error: %s", e)

    async def _anchor_loop(self):
        """Re-curate the published list and persist the blob database."""
        if self.publisher is None:
            return
        while True:
            try:
                if self.publisher.refresh():
                    log.info("Anchor list body changed: %d entries",
                             len(self.publisher.curate()))
                if not self.config.in_memory:
                    state = (self.blobdb.blob_count(), self.blobdb.commitment_count())
                    if state != self._anchor_saved and state != (0, 0):
                        self.blobdb.save(self._anchor_path)
                        self._anchor_saved = state
            except Exception:  # noqa: BLE001
                log.exception("anchor loop")
            await asyncio.sleep(60)

    def _reader_sources(self) -> list:
        """Live transpeers first, then the rest, up to 5, as (addr, port)."""
        entries = self.store.get_transpeers()
        alive = [e for e in entries if e.alive]
        rest = [e for e in entries if not e.alive]
        ordered = alive + rest
        return [(e.addr, e.port) for e in ordered[:5]]

    async def _reader_loop(self):
        """Sync the reader against known transpeers: immediately, then
        every 60 seconds."""
        if self.reader is None:
            return
        while True:
            try:
                await self.reader.sync(self._reader_sources())
                if not self.config.in_memory:
                    self._anchor_store.save()
                    if self.publisher is None:
                        self.blobdb.save(self._anchor_path)
            except Exception:  # noqa: BLE001
                log.exception("reader loop")
            await asyncio.sleep(60)
