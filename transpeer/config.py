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

    def __post_init__(self):
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.data_dir / "peers.db"


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
    args = parser.parse_args()
    return Config(
        port=args.port,
        bind=args.bind,
        data_dir=args.data_dir,
        difficulty=args.difficulty,
        networks=args.networks,
    )
