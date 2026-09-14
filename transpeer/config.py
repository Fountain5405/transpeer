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
    # Chain-anchored publication (docs/spec-chain-anchored-publication.md).
    anchor_publish: bool = False
    anchor_chain: str = "monero"
    aux_rpc_bind: str = "127.0.0.1"
    aux_rpc_port: int = 7338
    aux_diff: int = 100000
    anchor_min_age: float = 14.0   # days a transpeer must have been known (spec 4.1 rule 1)
    anchor_max_new: float = 0.25   # share of entries allowed without a committed history (rule 5)
    anchor_sim_pow: bool = False
    # The reader: the newcomer path (spec §6-§8), blob gossip (§5).
    anchor_read: bool = False
    anchor_checkpoint: str = ""
    anchor_venues: str = ""
    anchor_window_days: float = 7.0
    anchor_monerod: str = ""
    anchor_observe: str = ""

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
        "--anchor-publish", action="store_true",
        help="Publish this node's curated transpeer list through a local "
        "P2Pool node's merge-mining interface (point p2pool at "
        "--merge-mine AUX_RPC_BIND:AUX_RPC_PORT WALLET). Default off.",
    )
    parser.add_argument("--anchor-chain", default="monero",
                        help="Anchor chain name written into the list blob.")
    parser.add_argument("--aux-rpc-bind", default="127.0.0.1",
                        help="Bind address of the aux-chain JSON-RPC server P2Pool polls.")
    parser.add_argument("--aux-rpc-port", type=int, default=7338,
                        help="Port of the aux-chain JSON-RPC server.")
    parser.add_argument(
        "--aux-diff", type=int, default=100000,
        help="aux_diff reported to P2Pool. Set it to the venue's minimum "
        "share difficulty so every share is reported back with its proof.",
    )
    parser.add_argument("--anchor-min-age", type=float, default=14.0,
                        help="Days a transpeer must have been known before it is published.")
    parser.add_argument("--anchor-max-new", type=float, default=0.25,
                        help="Largest share of published entries without a committed history.")
    parser.add_argument(
        "--anchor-sim-pow", action="store_true",
        help="Simulation only: SHA-256 in place of RandomX for anchor-chain "
        "and share proof-of-work.",
    )
    parser.add_argument(
        "--anchor-read", action="store_true",
        help="Run the reader: the newcomer path over the anchor chain and "
        "venue shares, and blob gossip. Requires --anchor-checkpoint.",
    )
    parser.add_argument(
        "--anchor-checkpoint", default="",
        help="HEIGHT:HASH of a trusted anchor-chain block, shipped with a "
        "release. Required by --anchor-read.",
    )
    parser.add_argument(
        "--anchor-venues", default="",
        help="Comma-separated venue names (resolved through the built-in "
        "table) or 64-hex consensus ids. Empty means main, mini and nano.",
    )
    parser.add_argument(
        "--anchor-window-days", type=float, default=7.0,
        help="Coverage window: the anchor chain's last N days (spec §8).",
    )
    parser.add_argument(
        "--anchor-monerod", default="",
        help="monerod JSON-RPC URL to fill the anchor store from directly.",
    )
    parser.add_argument(
        "--anchor-observe", default="",
        help="Comma-separated HOST:PORT list of P2Pool nodes to fill share "
        "stores from through the observer client.",
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
    if args.anchor_read and not args.anchor_checkpoint:
        parser.error("--anchor-read requires --anchor-checkpoint")
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
        anchor_publish=args.anchor_publish,
        anchor_chain=args.anchor_chain,
        aux_rpc_bind=args.aux_rpc_bind,
        aux_rpc_port=args.aux_rpc_port,
        aux_diff=args.aux_diff,
        anchor_min_age=args.anchor_min_age,
        anchor_max_new=args.anchor_max_new,
        anchor_sim_pow=args.anchor_sim_pow,
        anchor_read=args.anchor_read,
        anchor_checkpoint=args.anchor_checkpoint,
        anchor_venues=args.anchor_venues,
        anchor_window_days=args.anchor_window_days,
        anchor_monerod=args.anchor_monerod,
        anchor_observe=args.anchor_observe,
        snapshot_interval=args.snapshot_interval,
    )


def parse_observe(spec: str) -> list[tuple[bytes, str, int]]:
    """Parse --anchor-observe: comma-separated 'host:port' (venue from the
    port through VENUE_PORTS) or 'name@host:port'/'hex@host:port' (venue
    named explicitly). Returns [(consensus_id, host, port), ...]."""
    from .anchor.share import VENUES, VENUE_PORTS

    out: list[tuple[bytes, str, int]] = []
    spec = (spec or "").strip()
    if not spec:
        return out
    port_to_venue = {port: VENUES[name] for name, port in VENUE_PORTS.items()}
    for entry in spec.split(","):
        entry = entry.strip()
        if not entry:
            continue
        if "@" in entry:
            venue_spec, hostport = entry.split("@", 1)
        else:
            venue_spec, hostport = None, entry
        host, _, port_s = hostport.rpartition(":")
        if not host:
            raise ValueError(f"invalid --anchor-observe entry: {entry}")
        port = int(port_s)
        if venue_spec is None:
            consensus_id = port_to_venue.get(port)
            if consensus_id is None:
                raise ValueError(f"--anchor-observe: unknown port {port}, name the venue explicitly")
        elif venue_spec in VENUES:
            consensus_id = VENUES[venue_spec]
        elif len(venue_spec) == 64:
            consensus_id = bytes.fromhex(venue_spec)
        else:
            raise ValueError(f"--anchor-observe: unknown venue {venue_spec}")
        out.append((consensus_id, host, port))
    return out


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
