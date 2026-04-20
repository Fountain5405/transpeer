"""Main transpeer node — orchestrates all components."""

import asyncio
import logging
import os
import time

from aiohttp import web

from .client import TranspeerClient
from .config import (
    Config, EXTRACT_INTERVAL, QUERY_INTERVAL, SCAN_INTERVAL, QUERY_BATCH_SIZE,
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
        self.server = TranspeerServer(
            self.config, self.store, self.node_id, self.start_time,
            network_names=list(self._networks.keys()),
        )

        try:
            # Start HTTP server
            app = self.server.create_app()
            runner = web.AppRunner(app)
            await runner.setup()
            site = web.TCPSite(runner, self.config.bind, self.config.port)
            await site.start()
            log.info("HTTP server listening on %s:%d", self.config.bind, self.config.port)

            # Run periodic tasks
            await asyncio.gather(
                self._extract_loop(),
                self._scan_loop(),
                self._query_loop(),
                self._verify_loop(),
                self._prune_loop(),
                self._candidate_loop(),
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
                    for info in peer_infos:
                        if self.config.no_pow:
                            nonce, solution, bucket = b"\x00" * 16, b"\x00" * 16, 0
                        elif self.config.sim_pow:
                            nonce, solution, bucket = pow_solve_sim(
                                name, info.addr, info.port, self.config.difficulty,
                            )
                        else:
                            nonce, solution, bucket = pow_solve(
                                name, info.addr, info.port, self.config.difficulty,
                            )
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

    async def _scan_loop(self):
        """Continuously scan random IPs for transpeers."""
        while True:
            try:
                await self.scanner.scan_batch()
            except Exception as e:
                log.error("Scan error: %s", e)
            await asyncio.sleep(SCAN_INTERVAL)

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
                    await self.client.query_transpeer(entry)
                    self.store.mark_queried(entry.addr, entry.port)
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

    async def _candidate_loop(self):
        """Periodically probe IPs that queried us."""
        while True:
            await asyncio.sleep(30)
            try:
                await self.scanner.probe_candidates()
            except Exception as e:
                log.error("Candidate probe error: %s", e)
