"""Fake P2P daemon for Shadow simulation.

Mimics a cryptocurrency daemon's JSON-RPC interface, serving a peer list.
Peers are other fake daemons in the simulation, passed via --peers arg.

Usage:
    python fake_daemon.py --network p2pa --rpc-port 10001 --p2p-port 10000 \
        --peers 11.0.0.2:10000,11.0.0.3:10000
"""

import argparse
import asyncio
import json
import logging

from aiohttp import web

log = logging.getLogger(__name__)


def parse_args():
    parser = argparse.ArgumentParser(description="Fake P2P daemon")
    parser.add_argument("--network", required=True, help="Network name (e.g., p2pa)")
    parser.add_argument("--rpc-port", type=int, required=True, help="JSON-RPC port")
    parser.add_argument("--p2p-port", type=int, required=True, help="P2P listen port")
    parser.add_argument("--peers", default="", help="Comma-separated list of addr:port peers")
    parser.add_argument("--bind", default="0.0.0.0")
    return parser.parse_args()


class FakeDaemon:
    def __init__(self, network, p2p_port, peers):
        self.network = network
        self.p2p_port = p2p_port
        self.peers = peers  # list of (addr, port)

    async def handle_rpc(self, request: web.Request) -> web.Response:
        """Handle JSON-RPC requests — only supports get_peer_list."""
        try:
            data = await request.json()
        except json.JSONDecodeError:
            return web.json_response({"error": "invalid json"}, status=400)

        method = data.get("method", "")
        if method == "get_peer_list":
            white_list = [{"host": addr, "port": port} for addr, port in self.peers]
            return web.json_response({
                "jsonrpc": "2.0",
                "id": data.get("id", "0"),
                "result": {
                    "white_list": white_list,
                    "gray_list": [],
                    "status": "OK",
                },
            })
        return web.json_response({"error": f"unknown method: {method}"}, status=400)

    async def handle_p2p(self, reader, writer):
        """Accept P2P connections — just respond with a magic header and close."""
        magic = f"{self.network}_HELLO".encode()
        writer.write(magic)
        await writer.drain()
        writer.close()
        await writer.wait_closed()


async def main():
    args = parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(message)s")

    peers = []
    if args.peers:
        for p in args.peers.split(","):
            addr, port = p.strip().rsplit(":", 1)
            peers.append((addr, int(port)))

    daemon = FakeDaemon(args.network, args.p2p_port, peers)

    # Start P2P listener
    p2p_server = await asyncio.start_server(daemon.handle_p2p, args.bind, args.p2p_port)
    log.info("P2P listener for %s on port %d (%d peers)", args.network, args.p2p_port, len(peers))

    # Start RPC server
    app = web.Application()
    app.router.add_post("/json_rpc", daemon.handle_rpc)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, args.bind, args.rpc_port)
    await site.start()
    log.info("RPC server for %s on port %d", args.network, args.rpc_port)

    # Run forever
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
