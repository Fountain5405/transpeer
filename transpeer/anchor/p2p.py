"""P2Pool's peer-to-peer wire protocol: message codec, the observer
client (initiator side) and the shared framing constants used by both
the client and its double (sim/p2pool_double.py).

Transcribed from P2Pool v4.18 src/p2p_server.h / p2p_server.cpp
(P2PClient::on_read dispatch, on_block_request/response,
on_peer_list_request/response, send_handshake_solution,
check_handshake_solution) per excerpts/p2p_framing.txt and
excerpts/p2p_protocol.txt. Spec §17 (chain-anchored slice 3, task 12).

Framing: no length prefix. One id byte, then a fixed payload per id,
except the four size-prefixed message kinds (u32 LE size, then that
many bytes, size <= MAX_BLOCK_SIZE).
"""

import asyncio
import ipaddress
import os
import random

from .keccak import keccak256
from .share import MAX_BLOCK_SIZE

CHALLENGE_SIZE = 8
HASH_SIZE = 32
CHALLENGE_DIFFICULTY = 10000

# MessageId enum (p2p_server.h)
HANDSHAKE_CHALLENGE = 0
HANDSHAKE_SOLUTION = 1
LISTEN_PORT = 2
BLOCK_REQUEST = 3
BLOCK_RESPONSE = 4
BLOCK_BROADCAST = 5
PEER_LIST_REQUEST = 6
PEER_LIST_RESPONSE = 7
BLOCK_BROADCAST_COMPACT = 8
BLOCK_NOTIFY = 9
AUX_JOB_DONATION = 10
MONERO_BLOCK_BROADCAST = 11
LAST_MESSAGE_ID = MONERO_BLOCK_BROADCAST

# Fixed-size payloads, keyed by id (bytes after the id byte).
_FIXED_PAYLOAD_SIZE = {
    HANDSHAKE_CHALLENGE: CHALLENGE_SIZE + 8,
    HANDSHAKE_SOLUTION: HASH_SIZE + CHALLENGE_SIZE,
    LISTEN_PORT: 4,
    BLOCK_REQUEST: HASH_SIZE,
    PEER_LIST_REQUEST: 0,
    BLOCK_NOTIFY: HASH_SIZE,
}
# Size-prefixed payloads (u32 LE size, then that many bytes).
_SIZE_PREFIXED = {BLOCK_RESPONSE, BLOCK_BROADCAST, BLOCK_BROADCAST_COMPACT,
                  AUX_JOB_DONATION, MONERO_BLOCK_BROADCAST}

PEER_LIST_RESPONSE_MAX_PEERS = 16
SUPPORTED_PROTOCOL_VERSION = 0x00010004
_VERSION_PORT = 0xFFFF
_VERSION_MARKER = 0xFFFFFFFF


class ProtocolError(ValueError):
    pass


# --- encode -----------------------------------------------------------------

def encode_handshake_challenge(challenge: bytes, peer_id: bytes) -> bytes:
    assert len(challenge) == CHALLENGE_SIZE and len(peer_id) == 8
    return bytes([HANDSHAKE_CHALLENGE]) + challenge + peer_id


def encode_handshake_solution(solution: bytes, salt: bytes) -> bytes:
    assert len(solution) == HASH_SIZE and len(salt) == CHALLENGE_SIZE
    return bytes([HANDSHAKE_SOLUTION]) + solution + salt


def encode_listen_port(port: int) -> bytes:
    return bytes([LISTEN_PORT]) + port.to_bytes(4, "little", signed=True)


def encode_block_request(share_id: bytes) -> bytes:
    assert len(share_id) == HASH_SIZE
    return bytes([BLOCK_REQUEST]) + share_id


def encode_block_response(blob: bytes) -> bytes:
    return bytes([BLOCK_RESPONSE]) + len(blob).to_bytes(4, "little") + blob


def encode_block_broadcast(blob: bytes, compact: bool = False) -> bytes:
    id_ = BLOCK_BROADCAST_COMPACT if compact else BLOCK_BROADCAST
    return bytes([id_]) + len(blob).to_bytes(4, "little") + blob


def encode_peer_list_request() -> bytes:
    return bytes([PEER_LIST_REQUEST])


def _encode_peer_entry(is_v6: bool, addr16: bytes, port: int) -> bytes:
    assert len(addr16) == 16
    return bytes([1 if is_v6 else 0]) + addr16 + port.to_bytes(2, "little")


def _version_pseudo_peer() -> bytes:
    addr = bytearray(16)
    addr[0:4] = SUPPORTED_PROTOCOL_VERSION.to_bytes(4, "little")
    addr[4:8] = (0).to_bytes(4, "little")  # P2Pool version: unused by the double
    addr[8:12] = (0).to_bytes(4, "little")  # SoftwareID::P2Pool
    addr[12:16] = _VERSION_MARKER.to_bytes(4, "little")
    return _encode_peer_entry(False, bytes(addr), _VERSION_PORT)


def _ipv4_mapped(ip: str) -> bytes:
    packed = ipaddress.IPv4Address(ip).packed
    return b"\x00" * 10 + b"\xff\xff" + packed


def encode_peer_list_response(peers: list, include_version: bool = False) -> bytes:
    """peers: list of (ip_str, port). Encodes IPv4 as IPv4-mapped, IPv6 as
    the raw 16-byte address, v6 flag 0. Matches P2Pool's
    on_peer_list_request (excerpt lines 516-543): when include_version is
    set, the pseudo-peer overwrites slot 0 rather than being appended, so
    the total never exceeds PEER_LIST_RESPONSE_MAX_PEERS and the first
    real peer is dropped once the list is full."""
    real_limit = PEER_LIST_RESPONSE_MAX_PEERS - 1 if include_version else PEER_LIST_RESPONSE_MAX_PEERS
    entries = []
    for ip, port in peers[:real_limit]:
        addr = ipaddress.ip_address(ip)
        if addr.version == 4:
            entries.append(_encode_peer_entry(False, _ipv4_mapped(ip), port))
        else:
            entries.append(_encode_peer_entry(True, addr.packed, port))
    if include_version:
        entries.insert(0, _version_pseudo_peer())
    count = len(entries)
    if count > PEER_LIST_RESPONSE_MAX_PEERS:
        raise ProtocolError("too many peers for a single PEER_LIST_RESPONSE")
    return bytes([PEER_LIST_RESPONSE, count]) + b"".join(entries)


def decode_peer_list_response(payload: bytes) -> list:
    """payload excludes the id byte but includes the count byte. Returns
    [(ip_str, port), ...] skipping the version pseudo-peer (which falls
    out of the same filter, since 255.255.255.255 has first octet 255)
    and, per P2Pool's on_peer_list_response, any IPv4 address whose first
    octet is 0, 127 or >= 224 (raw_ip::is_localhost() plus the
    0.0.0.0/8 and 224.0.0.0/3 exclusions), and any entry with port 0."""
    if not payload:
        raise ProtocolError("empty PEER_LIST_RESPONSE payload")
    count = payload[0]
    body = payload[1:]
    if len(body) != count * 19:
        raise ProtocolError("PEER_LIST_RESPONSE size mismatch")
    out = []
    for i in range(count):
        entry = body[i * 19:(i + 1) * 19]
        is_v6 = entry[0] != 0
        addr16 = entry[1:17]
        port = int.from_bytes(entry[17:19], "little")
        if port == 0:
            continue
        # IPv4-mapped (bytes 10..12 == 0xFFFF) is treated as IPv4 regardless
        # of the v6 flag, same as P2Pool's is_ipv4_prefix() downgrade.
        is_ipv4 = (not is_v6) or addr16[10:12] == b"\xff\xff"
        if is_ipv4:
            first_octet = addr16[12]
            if first_octet == 0 or first_octet == 127 or first_octet >= 224:
                continue
            out.append((str(ipaddress.IPv4Address(addr16[12:16])), port))
            continue
        v6 = ipaddress.IPv6Address(addr16)
        if v6.is_loopback or v6 == ipaddress.IPv6Address(0):
            continue
        out.append((v6.compressed, port))
    return out


# --- handshake ----------------------------------------------------------

def compute_solution(challenge: bytes, consensus_id: bytes, start_salt: int, pow_required: bool):
    """Returns (solution, salt_bytes). If pow_required, iterates the salt
    from start_salt until the PoW check passes; else returns the first
    (unconditional, matching P2Pool's incoming side which does no PoW)."""
    salt = start_salt & ((1 << 64) - 1)
    while True:
        salt_bytes = salt.to_bytes(CHALLENGE_SIZE, "little")
        solution = keccak256(challenge + consensus_id + salt_bytes)
        if not pow_required or check_pow(solution):
            return solution, salt_bytes
        salt = (salt + 1) & ((1 << 64) - 1)


def check_pow(solution: bytes) -> bool:
    value = int.from_bytes(solution[24:32], "little")
    return (value * CHALLENGE_DIFFICULTY) < (1 << 64)


def check_solution(challenge: bytes, consensus_id: bytes, salt: bytes, solution: bytes) -> bool:
    return keccak256(challenge + consensus_id + salt) == solution


# --- framing --------------------------------------------------------------

class FrameParser:
    """Feed bytes in; get back complete (id, payload) messages. Raises
    ProtocolError on a malformed stream; the caller should close on that."""

    def __init__(self):
        self._buf = bytearray()

    def feed(self, data: bytes) -> list:
        self._buf += data
        out = []
        while True:
            msg = self._try_take_one()
            if msg is None:
                break
            out.append(msg)
        return out

    def _try_take_one(self):
        buf = self._buf
        if not buf:
            return None
        id_ = buf[0]
        if id_ > LAST_MESSAGE_ID:
            raise ProtocolError(f"unknown message id {id_}")

        if id_ == PEER_LIST_RESPONSE:
            if len(buf) < 2:
                return None
            n = buf[1]
            if n > PEER_LIST_RESPONSE_MAX_PEERS:
                raise ProtocolError("peer list response too long")
            total = 2 + 19 * n
            if len(buf) < total:
                return None
            payload = bytes(buf[1:total])
            del self._buf[:total]
            return id_, payload

        if id_ in _SIZE_PREFIXED:
            if len(buf) < 5:
                return None
            size = int.from_bytes(buf[1:5], "little")
            if size > MAX_BLOCK_SIZE:
                raise ProtocolError("block size too large")
            total = 5 + size
            if len(buf) < total:
                return None
            payload = bytes(buf[5:total])
            del self._buf[:total]
            return id_, payload

        size = _FIXED_PAYLOAD_SIZE.get(id_)
        if size is None:
            raise ProtocolError(f"unknown message id {id_}")
        total = 1 + size
        if len(buf) < total:
            return None
        payload = bytes(buf[1:total])
        del self._buf[:total]
        return id_, payload


# --- client -----------------------------------------------------------------

class P2PoolClient:
    """The observer side of P2Pool's P2P protocol: connects, completes
    the handshake (as the initiator, doing PoW), and serves block/peer
    requests it receives while asking for its own."""

    def __init__(self, host: str, port: int, consensus_id: bytes, on_share=None, timeout: float = 10.0):
        self.host = host
        self.port = port
        self.consensus_id = consensus_id
        self.on_share = on_share
        self.timeout = timeout
        self._reader = None
        self._writer = None
        self._parser = FrameParser()
        self._task = None
        self._block_pending: list = []
        self._peers_pending: list = []

    async def connect(self):
        loop = asyncio.get_running_loop()
        self._reader, self._writer = await asyncio.wait_for(
            asyncio.open_connection(self.host, self.port), self.timeout)

        our_challenge = os.urandom(CHALLENGE_SIZE)
        peer_id = os.urandom(8)
        while peer_id == bytes(8):
            peer_id = os.urandom(8)

        sent_solution = loop.create_future()
        recv_solution_ok = loop.create_future()

        self._our_challenge = our_challenge
        self._sent_solution_fut = sent_solution
        self._recv_solution_fut = recv_solution_ok

        self._writer.write(encode_handshake_challenge(our_challenge, peer_id))
        await self._writer.drain()

        self._task = asyncio.create_task(self._read_loop())

        try:
            await asyncio.wait_for(asyncio.gather(sent_solution, recv_solution_ok), self.timeout)
        except ConnectionError:
            await self.close()
            raise
        except (asyncio.TimeoutError, ProtocolError, OSError) as e:
            await self.close()
            raise ConnectionError(f"handshake failed: {e}") from e

    async def _read_loop(self):
        try:
            while True:
                data = await self._reader.read(65536)
                if not data:
                    self._fail_pending(ConnectionError("connection closed"))
                    return
                try:
                    messages = self._parser.feed(data)
                except ProtocolError as e:
                    self._fail_pending(ConnectionError(str(e)))
                    self._writer.close()
                    return
                for id_, payload in messages:
                    try:
                        await self._dispatch(id_, payload)
                    except ProtocolError as e:
                        self._fail_pending(ConnectionError(str(e)))
                        self._writer.close()
                        return
        except (OSError, ConnectionError) as e:
            self._fail_pending(e)
        except asyncio.CancelledError:
            raise

    def _fail_pending(self, exc):
        for fut in self._block_pending:
            if not fut.done():
                fut.set_exception(exc)
        self._block_pending.clear()
        for fut in self._peers_pending:
            if not fut.done():
                fut.set_exception(exc)
        self._peers_pending.clear()
        sent = getattr(self, "_sent_solution_fut", None)
        if sent is not None and not sent.done():
            sent.set_exception(exc)
        recv = getattr(self, "_recv_solution_fut", None)
        if recv is not None and not recv.done():
            recv.set_exception(exc)

    async def _dispatch(self, id_, payload):
        if id_ == HANDSHAKE_CHALLENGE:
            challenge = payload[:CHALLENGE_SIZE]
            solution, salt = compute_solution(
                challenge, self.consensus_id, random.getrandbits(64), pow_required=True)
            self._writer.write(encode_handshake_solution(solution, salt))
            await self._writer.drain()
            fut = getattr(self, "_sent_solution_fut", None)
            if fut is not None and not fut.done():
                fut.set_result(True)

        elif id_ == HANDSHAKE_SOLUTION:
            solution = payload[:HASH_SIZE]
            salt = payload[HASH_SIZE:HASH_SIZE + CHALLENGE_SIZE]
            fut = getattr(self, "_recv_solution_fut", None)
            if not check_solution(self._our_challenge, self.consensus_id, salt, solution):
                exc = ConnectionError("handshake solution mismatch")
                if fut is not None and not fut.done():
                    fut.set_exception(exc)
                raise ProtocolError(str(exc))
            if fut is not None and not fut.done():
                fut.set_result(True)

        elif id_ == LISTEN_PORT:
            pass

        elif id_ == BLOCK_REQUEST:
            self._writer.write(encode_block_response(b""))
            await self._writer.drain()

        elif id_ == BLOCK_RESPONSE:
            if not self._block_pending:
                return
            fut = self._block_pending.pop(0)
            if not fut.done():
                fut.set_result(payload if payload else None)

        elif id_ == BLOCK_BROADCAST:
            if self.on_share is not None:
                self.on_share(payload)

        elif id_ in (BLOCK_BROADCAST_COMPACT, BLOCK_NOTIFY, AUX_JOB_DONATION, MONERO_BLOCK_BROADCAST):
            pass

        elif id_ == PEER_LIST_REQUEST:
            self._writer.write(encode_peer_list_response([]))
            await self._writer.drain()

        elif id_ == PEER_LIST_RESPONSE:
            peers = decode_peer_list_response(payload)
            if self._peers_pending:
                fut = self._peers_pending.pop(0)
                if not fut.done():
                    fut.set_result(peers)

        else:
            raise ProtocolError(f"unhandled message id {id_}")

    async def request_block(self, share_id: bytes):
        loop = asyncio.get_running_loop()
        fut = loop.create_future()
        self._block_pending.append(fut)
        self._writer.write(encode_block_request(share_id))
        await self._writer.drain()
        return await asyncio.wait_for(fut, self.timeout)

    async def request_peers(self):
        loop = asyncio.get_running_loop()
        fut = loop.create_future()
        self._peers_pending.append(fut)
        self._writer.write(encode_peer_list_request())
        await self._writer.drain()
        return await asyncio.wait_for(fut, self.timeout)

    async def close(self):
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
            self._task = None
        if self._writer is not None:
            self._writer.close()
            self._writer = None
