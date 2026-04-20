import argparse
from dataclasses import dataclass, field
from pathlib import Path


TRANSPEER_PORT = 7337
PROTOCOL_VERSION = "transpeer/1"

# PoW
DEFAULT_DIFFICULTY = 100
TIMESTAMP_BUCKET_SECS = 21600  # 6-hour PoW windows

# Scanner
SCAN_CONCURRENCY = 500
SCAN_TIMEOUT = 2.0  # seconds per probe

# Verifier
VERIFY_CONCURRENCY = 100
VERIFY_TIMEOUT = 5.0

# Peer management
PEER_PRUNE_AGE = 86400 * 7  # 7 days without verification
TRANSPEER_PRUNE_AGE = 86400 * 3  # 3 days without contact
EXTRACT_INTERVAL = 60  # seconds between local daemon queries
SCAN_INTERVAL = 10  # seconds between scan batches
QUERY_INTERVAL = 300  # seconds between querying known transpeers

# Transpeer tracking and query limits
MAX_TRANSPEERS_TRACKED = 500  # Total transpeers kept in local store
GOSSIP_SAMPLE_SIZE = 50  # Max transpeers returned in /transpeers response
QUERY_BATCH_SIZE = 20  # Number of transpeers queried per cycle (concurrent)
MAX_PEERS_PER_NETWORK = 2000  # Cap on peers stored per network

# Rate limiting
RATE_LIMIT_REQUESTS = 60  # per IP
RATE_LIMIT_WINDOW = 60  # seconds


@dataclass
class Config:
    port: int = TRANSPEER_PORT
    bind: str = "0.0.0.0"
    data_dir: Path = field(default_factory=lambda: Path.home() / ".transpeer")
    difficulty: int = DEFAULT_DIFFICULTY
    networks: list[str] = field(default_factory=lambda: ["monero", "wownero", "aeon"])
    scan_range: str | None = None  # CIDR block to scan (e.g., "11.0.0.0/24")
    in_memory: bool = False  # Skip SQLite, use in-memory only
    no_pow: bool = False  # Skip EquiX PoW (for simulation/testing)
    sim_pow: bool = False  # Use simulated PoW (sleep-based, Shadow-compatible)
    share_white_list: bool = False  # Share full white list instead of connected peers
    static_peers: dict[str, list[tuple[str, int]]] | None = None  # Preset peers per network
    no_verify: bool = False  # Disable peer verification loop (for simulation only)

    def __post_init__(self):
        if not self.in_memory:
            self.data_dir.mkdir(parents=True, exist_ok=True)
            self.db_path = self.data_dir / "peers.db"
        else:
            self.db_path = None


def parse_args() -> Config:
    parser = argparse.ArgumentParser(description="Transpeer node")
    parser.add_argument("--port", type=int, default=TRANSPEER_PORT)
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--data-dir", type=Path, default=Path.home() / ".transpeer")
    parser.add_argument("--difficulty", type=int, default=DEFAULT_DIFFICULTY)
    parser.add_argument(
        "--networks", nargs="+", default=["monero", "wownero", "aeon"],
        help="Networks to participate in",
    )
    parser.add_argument(
        "--scan-range", default=None,
        help="CIDR block to scan (e.g., 11.0.0.0/24). If unset, scans random IPv4.",
    )
    parser.add_argument(
        "--in-memory", action="store_true",
        help="Use in-memory storage only (no SQLite). Useful for simulation.",
    )
    parser.add_argument(
        "--no-pow", action="store_true",
        help="Disable EquiX proof-of-work (for simulation/testing only).",
    )
    parser.add_argument(
        "--sim-pow", action="store_true",
        help="Use simulated PoW (sleep-based, Shadow-compatible).",
    )
    parser.add_argument(
        "--share-white-list", action="store_true",
        help="Share full daemon white list instead of connected peers only.",
    )
    parser.add_argument(
        "--static-peers", default=None,
        help="Static peer list for simulation: 'network1:addr1:port1,addr2:port2;network2:...'",
    )
    parser.add_argument(
        "--no-verify", action="store_true",
        help="Disable peer verification loop (simulation/testing only).",
    )
    args = parser.parse_args()
    return Config(
        port=args.port,
        bind=args.bind,
        data_dir=args.data_dir,
        difficulty=args.difficulty,
        networks=args.networks,
        scan_range=args.scan_range,
        in_memory=args.in_memory,
        no_pow=args.no_pow,
        sim_pow=args.sim_pow,
        share_white_list=args.share_white_list,
        static_peers=_parse_static_peers(args.static_peers),
        no_verify=args.no_verify,
    )


def _parse_static_peers(spec: str | None) -> dict[str, list[tuple[str, int]]] | None:
    """Parse static peer spec: 'network:addr:port,addr:port;network:addr:port,...'"""
    if not spec:
        return None
    result: dict[str, list[tuple[str, int]]] = {}
    for net_spec in spec.split(";"):
        if not net_spec:
            continue
        parts = net_spec.split(":", 1)
        if len(parts) != 2:
            continue
        network, peers_str = parts
        peers = []
        for peer in peers_str.split(","):
            peer = peer.strip()
            if not peer:
                continue
            addr, _, port = peer.rpartition(":")
            if addr and port:
                peers.append((addr, int(port)))
        if peers:
            result[network] = peers
    return result
