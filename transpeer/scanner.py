"""Async IPv4 scanner for discovering transpeers."""

import asyncio
import logging
import random
import struct

from .client import TranspeerClient
from .config import Config, SCAN_CONCURRENCY, SCAN_TIMEOUT, TRANSPEER_PORT
from .peerstore import PeerStore

log = logging.getLogger(__name__)

# Reserved IPv4 ranges to skip (start, end) as integers
_RESERVED_RANGES = []


def _ip_to_int(ip: str) -> int:
    return struct.unpack("!I", bytes(int(o) for o in ip.split(".")))[0]


def _int_to_ip(n: int) -> str:
    return ".".join(str(b) for b in struct.pack("!I", n))


def _build_reserved():
    """Build list of reserved IPv4 ranges to skip during scanning."""
    if _RESERVED_RANGES:
        return
    ranges = [
        ("0.0.0.0", "0.255.255.255"),       # Current network
        ("10.0.0.0", "10.255.255.255"),      # RFC 1918
        ("100.64.0.0", "100.127.255.255"),   # Carrier-grade NAT
        ("127.0.0.0", "127.255.255.255"),    # Loopback
        ("169.254.0.0", "169.254.255.255"),  # Link-local
        ("172.16.0.0", "172.31.255.255"),    # RFC 1918
        ("192.0.0.0", "192.0.0.255"),        # IETF protocol assignments
        ("192.0.2.0", "192.0.2.255"),        # Documentation
        ("192.88.99.0", "192.88.99.255"),    # IPv6 to IPv4 relay
        ("192.168.0.0", "192.168.255.255"),  # RFC 1918
        ("198.18.0.0", "198.19.255.255"),    # Benchmarking
        ("198.51.100.0", "198.51.100.255"),  # Documentation
        ("203.0.113.0", "203.0.113.255"),    # Documentation
        ("224.0.0.0", "239.255.255.255"),    # Multicast
        ("240.0.0.0", "255.255.255.255"),    # Reserved/broadcast
    ]
    for start, end in ranges:
        _RESERVED_RANGES.append((_ip_to_int(start), _ip_to_int(end)))


def _is_reserved(ip_int: int) -> bool:
    for start, end in _RESERVED_RANGES:
        if start <= ip_int <= end:
            return True
    return False


def random_ip() -> str:
    """Generate a random non-reserved IPv4 address."""
    _build_reserved()
    while True:
        ip_int = random.randint(1, 0xFFFFFFFE)
        if not _is_reserved(ip_int):
            return _int_to_ip(ip_int)


class Scanner:
    def __init__(self, config: Config, store: PeerStore, client: TranspeerClient):
        self.config = config
        self.store = store
        self.client = client
        self._running = False

    async def _probe_ip(self, addr: str) -> bool:
        """Try to connect to an IP on the transpeer port."""
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(addr, TRANSPEER_PORT),
                timeout=SCAN_TIMEOUT,
            )
            writer.close()
            await writer.wait_closed()
        except (OSError, asyncio.TimeoutError):
            return False

        # Port is open — check if it speaks transpeer
        entry = await self.client.probe_transpeer(addr)
        if entry:
            log.info("Discovered transpeer at %s", addr)
            await self.store.add_transpeer(entry)
            return True
        return False

    async def scan_batch(self, count: int = SCAN_CONCURRENCY):
        """Scan a batch of random IPs."""
        ips = [random_ip() for _ in range(count)]
        tasks = [self._probe_ip(ip) for ip in ips]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        found = sum(1 for r in results if r is True)
        if found:
            log.info("Scan batch: found %d transpeers in %d probes", found, count)

    async def probe_candidates(self):
        """Probe IPs that have queried us (implicit self-announcement)."""
        candidates = self.store.pop_candidates()
        if not candidates:
            return
        log.info("Probing %d candidate transpeers", len(candidates))
        tasks = [self.client.probe_transpeer(addr) for addr in candidates]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for addr, result in zip(candidates, results):
            if isinstance(result, Exception) or result is None:
                continue
            await self.store.add_transpeer(result)
            log.info("Confirmed candidate transpeer at %s", addr)
