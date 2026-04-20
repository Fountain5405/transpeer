import asyncio
import os
import sys
from pathlib import Path

from .config import parse_args
from .node import Node


def main():
    config = parse_args()

    # Shadow support: use SHADOW_HOST_NAME for per-node data directories
    shadow_host = os.environ.get("SHADOW_HOST_NAME")
    if shadow_host:
        config.data_dir = Path(f"/tmp/transpeer_{shadow_host}")
        config.data_dir.mkdir(parents=True, exist_ok=True)
        config.db_path = config.data_dir / "peers.db"

    node = Node(config)
    try:
        asyncio.run(node.run())
    except KeyboardInterrupt:
        print("\nShutting down.")
        sys.exit(0)


if __name__ == "__main__":
    main()
