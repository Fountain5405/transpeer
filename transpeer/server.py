"""HTTP server for the transpeer protocol."""

import base64
import logging
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
LOAD_WINDOW_SECS = 60  # track request volume over 60s
LOAD_THRESHOLD = 300  # total requests per window before activating PoW
HANDSHAKE_MIN_EFFORT = 10
HANDSHAKE_MAX_EFFORT = 1000


class LoadTracker:
    """Tracks abuse signals to drive adaptive handshake PoW difficulty.

    Signal: total request volume (all endpoints combined) per minute.
    Normal gossip-loop activity is bounded (~20-80 req/min even in a busy
    network), so a threshold of 300/min reliably catches distributed
    floods that individually stay under the per-IP rate limit.
    """

    def __init__(self):
        self._requests: deque[float] = deque()
        self._last_recompute = 0.0
        self._current_difficulty = 0

    def record_request(self):
        self._requests.append(time.time())

    # Kept for backward compat; now just forwards to record_request
    def record_rate_limit_hit(self):
        pass  # rate-limit hits are already counted via record_request

    def _prune(self, now: float):
        cutoff = now - LOAD_WINDOW_SECS
        while self._requests and self._requests[0] < cutoff:
            self._requests.popleft()

    def current_difficulty(self) -> int:
        """Return current required handshake PoW effort (0 = dormant)."""
        now = time.time()
        if now - self._last_recompute < 5:
            return self._current_difficulty
        self._last_recompute = now
        self._prune(now)

        rate = len(self._requests)
        prev = self._current_difficulty
        if rate < LOAD_THRESHOLD:
            self._current_difficulty = 0
        else:
            # Scale: LOAD_THRESHOLD = HANDSHAKE_MIN_EFFORT, 10x threshold = MAX
            scale = (rate - LOAD_THRESHOLD) / (9 * LOAD_THRESHOLD)
            effort = HANDSHAKE_MIN_EFFORT + int(
                scale * (HANDSHAKE_MAX_EFFORT - HANDSHAKE_MIN_EFFORT)
            )
            self._current_difficulty = min(HANDSHAKE_MAX_EFFORT, effort)

        if prev != self._current_difficulty:
            logging.getLogger("transpeer.server").info(
                "HANDSHAKE_DIFFICULTY: %d -> %d (rate=%d/%ds)",
                prev, self._current_difficulty, rate, LOAD_WINDOW_SECS,
            )
        return self._current_difficulty


class TranspeerServer:
    def __init__(self, config: Config, store: PeerStore, node_id: str, start_time: float,
                 network_names: list[str] | None = None,
                 blobdb=None, publisher=None):
        self.config = config
        self.store = store
        self.node_id = node_id
        self.start_time = start_time
        self.network_names = network_names or config.networks
        self._rate_limits: dict[str, list[float]] = defaultdict(list)
        self.load_tracker = LoadTracker()
        self.blobdb = blobdb
        self.publisher = publisher

    def _check_rate_limit(self, addr: str) -> bool:
        now = time.time()
        # Record every request (including rate-limited ones) for load tracking
        self.load_tracker.record_request()
        timestamps = self._rate_limits[addr]
        self._rate_limits[addr] = [t for t in timestamps if now - t < RATE_LIMIT_WINDOW]
        if len(self._rate_limits[addr]) >= RATE_LIMIT_REQUESTS:
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

    async def handle_root(self, request: web.Request) -> web.Response:
        """A human-readable page for whoever looks up the port that probed
        them. Scanning etiquette: identify yourself, say what the probe
        was, and give a way to opt out and a way to complain."""
        contact = self.config.contact or "(operator has not set --contact)"
        text = (
            f"This host runs a {PROTOCOL_VERSION} peer-discovery node.\n"
            "\n"
            "If you are here because this address connected to TCP port "
            f"{self.config.port} on your network: that was a single TCP "
            "connect followed, if the port answered, by one HTTP GET of "
            "/transpeer. It looks for other nodes of this protocol and "
            "nothing else. No data on your host was read.\n"
            "\n"
            "Blind scanning runs at a few probes per second only while a "
            "node knows no other node, and stops once it does. To keep your "
            "prefix out of it, ask the operator below to add it to the "
            "node's scan exclude list, or publish it in the project's "
            "shared exclude list.\n"
            "\n"
            "Project: https://github.com/Fountain5405/transpeer\n"
            f"Operator contact: {contact}\n"
            f"Networks served here: {', '.join(self.network_names)}\n"
        )
        return web.Response(text=text, content_type="text/plain")

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

    # -- chain-anchored publication, spec §5 -------------------------------
    # Content-addressed data: no handshake proof-of-work, rate limit only.

    def _anchor_ready(self) -> bool:
        return self.blobdb is not None or self.publisher is not None

    async def handle_blob(self, request: web.Request) -> web.Response:
        if not self._anchor_ready():
            return web.json_response({"error": "anchor not configured"}, status=404)
        if not self._check_rate_limit(request.remote):
            return web.json_response({"error": "rate limited"}, status=429)
        try:
            h = bytes.fromhex(request.match_info["hash"])
            if len(h) != 32:
                raise ValueError
        except ValueError:
            return web.json_response({"error": "bad hash"}, status=400)
        blob = self.publisher.lookup(h) if self.publisher else None
        if blob is None and self.blobdb is not None:
            blob = self.blobdb.get(h)
        if blob is None:
            return web.json_response({"error": "unknown blob"}, status=404)
        return web.Response(body=blob, content_type="application/octet-stream")

    async def handle_blobs_index(self, request: web.Request) -> web.Response:
        if not self._anchor_ready():
            return web.json_response({"error": "anchor not configured"}, status=404)
        if not self._check_rate_limit(request.remote):
            return web.json_response({"error": "rate limited"}, status=429)
        try:
            since = int(request.query.get("since", "0"))
            limit = max(1, min(int(request.query.get("limit", "500")), 500))
            after = bytes.fromhex(request.query.get("after", ""))
            if after and len(after) != 32:
                raise ValueError
        except ValueError:
            return web.json_response({"error": "bad query"}, status=400)
        rows = self.blobdb.index_since(since, limit, after) if self.blobdb is not None else []
        blobs = [{"hash": h.hex(), "first_seen": fs, "commitments": [c.to_dict() for c in cs]}
                 for h, fs, cs in rows]
        full = len(rows) == limit
        return web.json_response({
            "blobs": blobs,
            "next_since": rows[-1][1] if full else None,
            "next_after": rows[-1][0].hex() if full else None,
        })

    def create_app(self) -> web.Application:
        app = web.Application()
        app.router.add_get("/transpeer", self.handle_transpeer)
        app.router.add_get("/", self.handle_root)
        app.router.add_get("/peers/{network}", self.handle_peers)
        app.router.add_get("/transpeers", self.handle_transpeers)
        app.router.add_get("/blob/{hash}", self.handle_blob)
        app.router.add_get("/blobs/index", self.handle_blobs_index)
        return app
