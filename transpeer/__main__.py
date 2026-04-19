import asyncio
import sys

from .config import parse_args
from .node import Node


def main():
    config = parse_args()
    node = Node(config)
    try:
        asyncio.run(node.run())
    except KeyboardInterrupt:
        print("\nShutting down.")
        sys.exit(0)


if __name__ == "__main__":
    main()
