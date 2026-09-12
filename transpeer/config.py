import argparse
from dataclasses import dataclass, field
from pathlib import Path


TRANSPEER_PORT = 7337
PROTOCOL_VERSION = "transpeer/1"
# Shown in the User-Agent of every request we make and on GET /, so a
# network operator who sees our probe can find out what it was.
PROJECT_URL = "https://github.com/Fountain5405/transpeer"


def user_agent(contact: str = "") -> str:
    """Identify the probe: protocol, project URL, and how to opt out."""
    ua = f"{PROTOCOL_VERSION} (+{PROJECT_URL}; peer discovery"
    if contact:
        ua += f"; opt-out: {contact}"
    return ua + ")"

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
    # Transpeer diversity buckets are IPv4 prefixes: /16 in production. A
    # simulation with a small scan range uses a longer prefix so it can
    # still hold many distinct buckets.
    subnet_prefix: int = 16
    # Bucketed policy: per-bucket admission cap on every discovery path,
    # eviction from the most crowded bucket, bucket-uniform query and gossip.
    bucketed: bool = False
    # Voucher counting: per-source peer cap and trust keyed by bucket, a
    # peer's credibility is the number of distinct buckets that reported it
    # (observed, not claimed), and get_peers ranks by it.
    vouchers: bool = False
    # Tried table: a transpeer that has answered our queries at least twice
    # is never evicted to make room for a newcomer.
    tried_table: bool = False
    # Log a STORE_SNAPSHOT line every N seconds (0 = off). Simulation metric.
    snapshot_interval: int = 0
    # Hand-off reserve: of the first `top` peers handed to the daemon, the
    # last K are chosen for reporter diversity (one per reporter bucket that
    # vouched for none of the ranked head) instead of by rank. 0 = off.
    handoff_reserve: int = 0
    # Native vouchers: a report counts extra when the reporting transpeer's
    # host answers on the network's P2P port, i.e. it verifiably runs the
    # daemon it is vouching for. Requires --vouchers.
    native_vouchers: bool = False
    # Simulation only: listen on each configured network's P2P port and close
    # connections, so native probes against this host succeed as they would
    # against a real daemon.
    sim_daemon_listen: bool = False
    # network -> P2P port for the networks this node runs; filled at startup
    # from the network plugins, used by the native probe. Not a CLI flag.
    native_ports: dict = field(default_factory=dict)
    # Scanning etiquette. Blind scanning of random IPv4 space is what gets
    # an address reported and blocklisted. The shot in the dark is for a
    # node that knows nobody, so by default the scanner runs only while
    # cold: scan_rate probes per second, spread with jitter rather than in
    # bursts, until scan_target_known transpeers have answered a query,
    # then scan_idle_rate (default 0: stop). Discovery continues through
    # gossip, through nodes that contact us, and through the local
    # daemon's own peers probed on the transpeer port. If the live count
    # falls back below the target, scanning resumes on its own. Blind
    # scanning skips the reserved ranges, a built-in list of sensitively
    # monitored netblocks, and any prefix in scan_exclude. scan_rate 0 (or
    # --no-scan) disables blind scanning entirely. scan_legacy restores the
    # pre-etiquette profile (bursts of SCAN_CONCURRENCY every SCAN_INTERVAL,
    # no backoff, no exclusions beyond reserved, no daemon-peer probing);
    # simulations use it so their results stay comparable.
    scan_rate: float = 4.0
    scan_idle_rate: float = 0.0
    scan_target_known: int = 3
    scan_exclude: str | None = None
    scan_legacy: bool = False
    # Free-text contact shown on GET / so a network operator who sees our
    # probes can reach us instead of reporting us.
    contact: str = ""

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
    parser.add_argument(
        "--subnet-prefix", type=int, default=16,
        help="Prefix length of a transpeer diversity bucket (default /16).",
    )
    parser.add_argument(
        "--bucketed", action="store_true",
        help="Bucketed transpeer policy: cap every discovery path per bucket, "
             "evict from the fullest bucket, query and gossip bucket-uniform.",
    )
    parser.add_argument(
        "--vouchers", action="store_true",
        help="Voucher counting: key per-source peer caps by bucket and rank "
             "peers by the number of distinct buckets that reported them.",
    )
    parser.add_argument(
        "--tried-table", action="store_true",
        help="Protect transpeers that have answered queries at least twice "
             "from eviction by newcomers.",
    )
    parser.add_argument(
        "--handoff-reserve", type=int, default=0,
        help="Reserve K of the daemon's peer slots for peers vouched by "
        "reporter buckets absent from the ranked head (requires --vouchers).",
    )
    parser.add_argument(
        "--native-vouchers", action="store_true",
        help="Rank peers first by vouchers from transpeers whose host answers "
        "on the network's P2P port (requires --vouchers).",
    )
    parser.add_argument(
        "--sim-daemon-listen", action="store_true",
        help="Simulation only: accept connections on each network's P2P port "
        "so native probes succeed.",
    )
    parser.add_argument(
        "--scan-rate", type=float, default=4.0,
        help="Blind-scan probes per second while cold (default 4; 0 disables "
        "blind scanning).",
    )
    parser.add_argument(
        "--no-scan", action="store_true",
        help="Never blind-scan: rely on gossip, on nodes that contact us and "
        "on the local daemon's peers. For residential lines and strict hosts.",
    )
    parser.add_argument(
        "--scan-idle-rate", type=float, default=0.0,
        help="Probes per second once --scan-target-known transpeers have "
        "answered (default 0: stop scanning).",
    )
    parser.add_argument(
        "--scan-target-known", type=int, default=3,
        help="Live (answering) transpeers at which blind scanning stops.",
    )
    parser.add_argument(
        "--scan-exclude", default=None,
        help="File of CIDR prefixes never to scan (one per line, # comments). "
        "Applies to blind scanning, not to an explicit --scan-range.",
    )
    parser.add_argument(
        "--scan-legacy", action="store_true",
        help="Pre-etiquette scan profile: bursts of 500 probes every 10 s, no "
        "idle backoff, no exclude file. Simulations use it for comparability.",
    )
    parser.add_argument(
        "--contact", default="",
        help="Operator contact shown on GET / for network operators who see "
        "our probes.",
    )
    parser.add_argument(
        "--snapshot-interval", type=int, default=0,
        help="Log store composition every N seconds (simulation metric).",
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
        subnet_prefix=args.subnet_prefix,
        bucketed=args.bucketed,
        vouchers=args.vouchers,
        tried_table=args.tried_table,
        handoff_reserve=args.handoff_reserve,
        native_vouchers=args.native_vouchers,
        sim_daemon_listen=args.sim_daemon_listen,
        scan_rate=0.0 if args.no_scan else args.scan_rate,
        scan_idle_rate=args.scan_idle_rate,
        scan_target_known=args.scan_target_known,
        scan_exclude=args.scan_exclude,
        scan_legacy=args.scan_legacy,
        contact=args.contact,
        snapshot_interval=args.snapshot_interval,
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
