"""Async IPv4 scanner for discovering transpeers."""

import asyncio
import ipaddress
import logging
import random
import struct

from .client import TranspeerClient
from .config import (
    Config, SCAN_CONCURRENCY, SCAN_INTERVAL, SCAN_TIMEOUT, TRANSPEER_PORT,
)
from .peerstore import PeerStore

log = logging.getLogger(__name__)

# Reserved IPv4 ranges to skip (start, end) as integers
_RESERVED_RANGES = []

# Netblocks that blind scanning must also skip: the /8s allocated to the
# US Department of Defense and its agencies in the IANA IPv4 address
# space registry (DoD NIC, DISA, DLA, Army ISC, DSI). Probes into these
# draw the most aggressive abuse handling of any address space, and a
# discovery scan gains nothing from them. If an entry here is ever stale
# the cost is a little less coverage, so the list errs on the side of
# skipping. Applies to blind scanning only, not to an explicit
# --scan-range.
_SENSITIVE_CIDRS = [
    "6.0.0.0/8", "7.0.0.0/8", "11.0.0.0/8", "21.0.0.0/8", "22.0.0.0/8",
    "26.0.0.0/8", "28.0.0.0/8", "29.0.0.0/8", "30.0.0.0/8", "33.0.0.0/8",
    "55.0.0.0/8", "214.0.0.0/8", "215.0.0.0/8",
]
_SENSITIVE_RANGES = [
    (int(ipaddress.IPv4Network(c).network_address),
     int(ipaddress.IPv4Network(c).broadcast_address))
    for c in _SENSITIVE_CIDRS
]


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


def _in_ranges(ip_int: int, ranges) -> bool:
    return any(start <= ip_int <= end for start, end in ranges)


def load_exclusions(path: str | None) -> list[tuple[int, int]]:
    """Read a file of CIDR prefixes (one per line, `#` comments) into
    (start, end) integer ranges. Missing path -> empty list. A malformed
    line is an error: silently skipping it would mean scanning a prefix
    the operator meant to protect."""
    if not path:
        return []
    ranges = []
    with open(path) as f:
        for lineno, raw in enumerate(f, 1):
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            try:
                net = ipaddress.IPv4Network(line, strict=False)
            except ValueError as e:
                raise ValueError(f"{path}:{lineno}: not an IPv4 prefix: {line!r}") from e
            ranges.append((int(net.network_address), int(net.broadcast_address)))
    return ranges


def random_ip(exclude=(), skip_sensitive: bool = True) -> str:
    """Generate a random IPv4 address outside the reserved ranges, outside
    the sensitive netblocks (unless skip_sensitive is False), and outside
    `exclude` (extra (start, end) ranges)."""
    _build_reserved()
    while True:
        ip_int = random.randint(1, 0xFFFFFFFE)
        if _is_reserved(ip_int) or _in_ranges(ip_int, exclude):
            continue
        if skip_sensitive and _in_ranges(ip_int, _SENSITIVE_RANGES):
            continue
        return _int_to_ip(ip_int)


def random_ip_in_cidr(cidr: str) -> str:
    """Generate a random IP within a CIDR block."""
    network = ipaddress.IPv4Network(cidr, strict=False)
    # Skip network and broadcast addresses
    num_hosts = network.num_addresses - 2
    if num_hosts <= 0:
        return str(network.network_address + 1)
    offset = random.randint(1, num_hosts)
    return str(network.network_address + offset)


class Scanner:
    def __init__(self, config: Config, store: PeerStore, client: TranspeerClient,
                 node_id: str = ""):
        self.config = config
        self.store = store
        self.client = client
        self._running = False
        self._node_id = node_id
        self.interval = SCAN_INTERVAL
        self._exclude = [] if config.scan_legacy else load_exclusions(config.scan_exclude)
        self._idle = None  # last logged mode, to log transitions once
        if self._exclude:
            log.info("Scanner excluding %d operator-listed prefixes", len(self._exclude))

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
            # Don't add ourselves
            if entry.node_id == self._node_id:
                return False
            added = await self.store.add_transpeer(entry)
            if added:
                log.info("Discovered transpeer at %s (node_id=%s)", addr, entry.node_id)
            else:
                log.debug("Transpeer at %s rejected (subnet limit or duplicate)", addr)
            return added
        return False

    def _generate_ip(self) -> str:
        """Generate a random IP to scan, respecting scan_range config.

        An explicit --scan-range is the operator's own choice and is not
        filtered; the exclude file applies to blind scanning only."""
        if self.config.scan_range:
            return random_ip_in_cidr(self.config.scan_range)
        return random_ip(self._exclude, skip_sensitive=not self.config.scan_legacy)

    def current_rate(self) -> float:
        """Probes per second for the next batch under the paced profile:
        the cold rate until enough transpeers have answered a query, the
        idle rate (default 0, i.e. stop) after that. Re-evaluated every
        batch, so a node whose live transpeers all vanish starts scanning
        again by itself."""
        live = self.store.live_transpeer_count()
        idle = live >= self.config.scan_target_known
        if idle != self._idle:
            self._idle = idle
            log.info("Scan mode: %s (%d live transpeers)",
                     "idle" if idle else "cold", live)
        return self.config.scan_idle_rate if idle else self.config.scan_rate

    def _batch_size(self) -> int:
        if self.config.scan_legacy:
            if self.config.scan_range:
                # Scale batch size to range: scan ~half the range per batch
                net = ipaddress.IPv4Network(self.config.scan_range, strict=False)
                return min(SCAN_CONCURRENCY, max(1, (net.num_addresses - 2) // 2))
            return SCAN_CONCURRENCY
        rate = self.current_rate()
        if rate <= 0:
            return 0
        return max(1, min(SCAN_CONCURRENCY, int(round(rate * self.interval))))

    async def scan_batch(self, count: int | None = None):
        """Scan a batch of random IPs.

        Legacy profile: fire the whole batch at once. Paced profile: the
        batch is sized to the current rate and its probes are launched
        evenly across the scan interval, so the wire sees a steady trickle
        rather than a burst of SYNs that reads as a port sweep.
        """
        if count is None:
            count = self._batch_size()
        if count <= 0:
            return
        ips = set()
        for _ in range(count * 2):  # generate extras to deduplicate
            ip = self._generate_ip()
            ips.add(ip)
            if len(ips) >= count:
                break
        if self.config.scan_legacy:
            tasks = [self._probe_ip(ip) for ip in ips]
        else:
            # Even spacing with jitter: a steady trickle, and no fixed
            # cadence for a sensor to fingerprint.
            spacing = self.interval / len(ips)
            tasks = []
            for ip in ips:
                tasks.append(asyncio.ensure_future(self._probe_ip(ip)))
                await asyncio.sleep(spacing * random.uniform(0.5, 1.5))
        results = await asyncio.gather(*tasks, return_exceptions=True)
        found = sum(1 for r in results if r is True)
        if found:
            log.info("Scan batch: found %d transpeers in %d probes", found, len(ips))

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
