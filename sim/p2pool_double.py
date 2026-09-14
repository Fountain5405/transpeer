"""A minimal Python double of the P2Pool side of the P2P protocol, for
tests and (slice 4) the simulation oracle. Speaks the responder half of
the same handshake, block request/response and peer list exchange as
transpeer/anchor/p2p.py's P2PoolClient, reusing its codec functions.
"""

import asyncio
import os

from transpeer.anchor.p2p import (
    BLOCK_BROADCAST,
    BLOCK_REQUEST,
    FrameParser,
    HANDSHAKE_CHALLENGE,
    HANDSHAKE_SOLUTION,
    HASH_SIZE,
    CHALLENGE_SIZE,
    PEER_LIST_REQUEST,
    ProtocolError,
    check_pow,
    check_solution,
    compute_solution,
    encode_block_broadcast,
    encode_block_response,
    encode_handshake_challenge,
    encode_handshake_solution,
    encode_peer_list_response,
)


class _Connection:
    def __init__(self, double, reader, writer):
        self.double = double
        self.reader = reader
        self.writer = writer
        self.parser = FrameParser()
        self.our_challenge = os.urandom(CHALLENGE_SIZE)
        self.sent_peer_list = False
        self.closed = False

    async def run(self):
        try:
            peer_id = os.urandom(8)
            while peer_id == bytes(8):
                peer_id = os.urandom(8)
            self.writer.write(encode_handshake_challenge(self.our_challenge, peer_id))
            await self.writer.drain()

            while True:
                data = await self.reader.read(65536)
                if not data:
                    return
                try:
                    messages = self.parser.feed(data)
                except ProtocolError:
                    return
                for id_, payload in messages:
                    if not await self._dispatch(id_, payload):
                        return
        except (OSError, asyncio.CancelledError):
            pass
        finally:
            self.closed = True
            self.writer.close()
            self.double._connections.discard(self)

    async def _dispatch(self, id_, payload) -> bool:
        if id_ == HANDSHAKE_CHALLENGE:
            challenge = payload[:CHALLENGE_SIZE]
            # Incoming side does no PoW.
            solution, salt = compute_solution(
                challenge, self.double.consensus_id,
                int.from_bytes(os.urandom(8), "little"), pow_required=False)
            self.writer.write(encode_handshake_solution(solution, salt))
            await self.writer.drain()
            return True

        if id_ == HANDSHAKE_SOLUTION:
            solution = payload[:HASH_SIZE]
            salt = payload[HASH_SIZE:HASH_SIZE + CHALLENGE_SIZE]
            if not check_solution(self.our_challenge, self.double.consensus_id, salt, solution):
                return False
            if not check_pow(solution):
                return False
            return True

        if id_ == BLOCK_REQUEST:
            share_id = payload[:HASH_SIZE]
            if share_id == bytes(HASH_SIZE):
                blob = self.double.shares.get(self.double.tip, b"")
            else:
                blob = self.double.shares.get(share_id, b"")
            self.writer.write(encode_block_response(blob))
            await self.writer.drain()
            return True

        if id_ == PEER_LIST_REQUEST:
            first = not self.sent_peer_list
            self.sent_peer_list = True
            self.writer.write(encode_peer_list_response(self.double.peers, include_version=first))
            await self.writer.drain()
            return True

        # LISTEN_PORT and anything else the double doesn't act on.
        return True


class P2PoolDouble:
    """consensus_id: bytes; shares: {share_id: raw_bytes}; tip: share_id;
    peers: [(ip, port), ...] to hand out on PEER_LIST_REQUEST."""

    def __init__(self, consensus_id: bytes, shares: dict, tip: bytes, peers: list):
        self.consensus_id = consensus_id
        self.shares = shares
        self.tip = tip
        self.peers = peers
        self._server = None
        self._connections: set = set()
        self._tasks: set = set()

    @property
    def connections(self) -> int:
        return len(self._connections)

    async def start(self, port: int):
        async def _accept(reader, writer):
            conn = _Connection(self, reader, writer)
            self._connections.add(conn)
            task = asyncio.create_task(conn.run())
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)

        self._server = await asyncio.start_server(_accept, "127.0.0.1", port)

    async def stop(self):
        for conn in list(self._connections):
            conn.writer.close()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        self._connections.clear()
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def broadcast(self, raw: bytes):
        msg = encode_block_broadcast(raw)
        for conn in list(self._connections):
            if conn.closed:
                continue
            conn.writer.write(msg)
            await conn.writer.drain()
