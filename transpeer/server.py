"""HTTP server for the transpeer protocol."""

import time
from collections import defaultdict

from aiohttp import web

from .config import Config, PROTOCOL_VERSION, RATE_LIMIT_REQUESTS, RATE_LIMIT_WINDOW
from .peerstore import PeerStore


class TranspeerServer:
    def __init__(self, config: Config, store: PeerStore, node_id: str, start_time: float):
        self.config = config
        self.store = store
        self.node_id = node_id
        self.start_time = start_time
        self._rate_limits: dict[str, list[float]] = defaultdict(list)

    def _check_rate_limit(self, addr: str) -> bool:
        now = time.time()
        timestamps = self._rate_limits[addr]
        # Purge old entries
        self._rate_limits[addr] = [t for t in timestamps if now - t < RATE_LIMIT_WINDOW]
        if len(self._rate_limits[addr]) >= RATE_LIMIT_REQUESTS:
            return False
        self._rate_limits[addr].append(now)
        return True

    async def handle_transpeer(self, request: web.Request) -> web.Response:
        remote = request.remote
        if not self._check_rate_limit(remote):
            return web.json_response({"error": "rate limited"}, status=429)

        # Record requester as candidate transpeer
        self.store.add_candidate(remote)

        networks = self.config.networks
        peer_counts = {n: self.store.peer_count(n) for n in networks}

        return web.json_response({
            "protocol": PROTOCOL_VERSION,
            "node_id": self.node_id,
            "networks": networks,
            "peer_counts": peer_counts,
            "uptime": int(time.time() - self.start_time),
            "difficulty": self.config.difficulty,
        })

    async def handle_peers(self, request: web.Request) -> web.Response:
        remote = request.remote
        if not self._check_rate_limit(remote):
            return web.json_response({"error": "rate limited"}, status=429)

        network = request.match_info["network"]
        peers = self.store.get_peers(network, verified_only=True)

        return web.json_response({
            "network": network,
            "peers": [p.to_dict() for p in peers],
        })

    async def handle_transpeers(self, request: web.Request) -> web.Response:
        remote = request.remote
        if not self._check_rate_limit(remote):
            return web.json_response({"error": "rate limited"}, status=429)

        entries = self.store.get_transpeers()

        return web.json_response({
            "transpeers": [e.to_dict() for e in entries],
        })

    def create_app(self) -> web.Application:
        app = web.Application()
        app.router.add_get("/transpeer", self.handle_transpeer)
        app.router.add_get("/peers/{network}", self.handle_peers)
        app.router.add_get("/transpeers", self.handle_transpeers)
        return app
