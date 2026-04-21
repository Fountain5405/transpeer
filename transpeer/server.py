"""HTTP server for the transpeer protocol."""

import base64
import time
from collections import defaultdict, deque

from aiohttp import web

from .config import (
    Config, PROTOCOL_VERSION, RATE_LIMIT_REQUESTS, RATE_LIMIT_WINDOW,
    GOSSIP_SAMPLE_SIZE,
)
from .peerstore import PeerStore
from .pow import verify_handshake

# Adaptive handshake PoW parameters
LOAD_WINDOW_SECS = 60  # track abuse signals over 60s
LOAD_THRESHOLD = 30  # rate-limit hits per window before activating PoW
HANDSHAKE_MIN_EFFORT = 10
HANDSHAKE_MAX_EFFORT = 1000


class LoadTracker:
    """Tracks abuse signals to drive adaptive handshake PoW difficulty."""

    def __init__(self):
        self._rate_limit_hits: deque[float] = deque()
        self._last_recompute = 0.0
        self._current_difficulty = 0

    def record_rate_limit_hit(self):
        self._rate_limit_hits.append(time.time())

    def _prune(self, now: float):
        cutoff = now - LOAD_WINDOW_SECS
        while self._rate_limit_hits and self._rate_limit_hits[0] < cutoff:
            self._rate_limit_hits.popleft()

    def current_difficulty(self) -> int:
        """Return current required handshake PoW effort (0 = dormant)."""
        now = time.time()
        if now - self._last_recompute < 5:
            return self._current_difficulty
        self._last_recompute = now
        self._prune(now)

        hits = len(self._rate_limit_hits)
        if hits < LOAD_THRESHOLD:
            self._current_difficulty = 0
        else:
            # Scale: LOAD_THRESHOLD = HANDSHAKE_MIN_EFFORT, 10x threshold = MAX
            scale = (hits - LOAD_THRESHOLD) / (9 * LOAD_THRESHOLD)
            effort = HANDSHAKE_MIN_EFFORT + int(
                scale * (HANDSHAKE_MAX_EFFORT - HANDSHAKE_MIN_EFFORT)
            )
            self._current_difficulty = min(HANDSHAKE_MAX_EFFORT, effort)
        return self._current_difficulty


class TranspeerServer:
    def __init__(self, config: Config, store: PeerStore, node_id: str, start_time: float,
                 network_names: list[str] | None = None):
        self.config = config
        self.store = store
        self.node_id = node_id
        self.start_time = start_time
        self.network_names = network_names or config.networks
        self._rate_limits: dict[str, list[float]] = defaultdict(list)
        self.load_tracker = LoadTracker()

    def _check_rate_limit(self, addr: str) -> bool:
        now = time.time()
        timestamps = self._rate_limits[addr]
        # Purge old entries
        self._rate_limits[addr] = [t for t in timestamps if now - t < RATE_LIMIT_WINDOW]
        if len(self._rate_limits[addr]) >= RATE_LIMIT_REQUESTS:
            self.load_tracker.record_rate_limit_hit()
            return False
        self._rate_limits[addr].append(now)
        return True

    def _check_handshake_pow(self, request: web.Request) -> tuple[bool, int]:
        """Verify handshake PoW on the request.

        Returns (ok, required_effort). ok=True if no PoW needed or PoW valid.
        required_effort is the current difficulty (for reporting).
        """
        required_effort = self.load_tracker.current_difficulty()
        if required_effort == 0:
            return True, 0

        header = request.headers.get("X-Transpeer-PoW")
        if not header:
            return False, required_effort

        try:
            # Format: "bucket:nonce_b64:solution_b64"
            bucket_str, nonce_b64, solution_b64 = header.split(":", 2)
            bucket = int(bucket_str)
            nonce = base64.b64decode(nonce_b64)
            solution = base64.b64decode(solution_b64)
        except (ValueError, Exception):
            return False, required_effort

        accept_sim = self.config.sim_pow
        ok = verify_handshake(
            request.remote, self.node_id, nonce,
            required_effort, solution, bucket,
            accept_simulated=accept_sim,
        )
        return ok, required_effort

    def _pow_required_response(self, required_effort: int, client_ip: str) -> web.Response:
        """Build a 402 Payment Required response with the PoW challenge."""
        return web.json_response(
            {
                "error": "handshake PoW required",
                "effort": required_effort,
                "bucket": int(time.time()) // 3600,
                "node_id": self.node_id,
                "client_ip": client_ip,
            },
            status=402,
            headers={
                "X-Transpeer-Required-Effort": str(required_effort),
                "X-Transpeer-Node-Id": self.node_id,
                "X-Transpeer-Client-Ip": client_ip,
            },
        )

    async def handle_transpeer(self, request: web.Request) -> web.Response:
        """/transpeer is always free — it's the discovery endpoint and
        advertises the current handshake PoW difficulty."""
        remote = request.remote
        if not self._check_rate_limit(remote):
            return web.json_response({"error": "rate limited"}, status=429)

        # Record requester as candidate transpeer
        self.store.add_candidate(remote)

        networks = self.network_names
        peer_counts = {n: self.store.peer_count(n) for n in networks}

        return web.json_response({
            "protocol": PROTOCOL_VERSION,
            "node_id": self.node_id,
            "networks": networks,
            "peer_counts": peer_counts,
            "uptime": int(time.time() - self.start_time),
            "difficulty": self.config.difficulty,
            "handshake_effort": self.load_tracker.current_difficulty(),
        })

    async def handle_peers(self, request: web.Request) -> web.Response:
        remote = request.remote
        if not self._check_rate_limit(remote):
            return web.json_response({"error": "rate limited"}, status=429)

        ok, effort = self._check_handshake_pow(request)
        if not ok:
            return self._pow_required_response(effort, remote)

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

        ok, effort = self._check_handshake_pow(request)
        if not ok:
            return self._pow_required_response(effort, remote)

        entries = self.store.get_transpeers_for_gossip(
            GOSSIP_SAMPLE_SIZE, exclude_addr=remote,
        )

        return web.json_response({
            "transpeers": [e.to_dict() for e in entries],
        })

    def create_app(self) -> web.Application:
        app = web.Application()
        app.router.add_get("/transpeer", self.handle_transpeer)
        app.router.add_get("/peers/{network}", self.handle_peers)
        app.router.add_get("/transpeers", self.handle_transpeers)
        return app
