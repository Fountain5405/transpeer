"""IPv4 ranges no public peer can live in. Shared by the scanner (never
probe them blindly), the verifier and the native probe (never probe them
on another transpeer's word). Kept free of package imports so that
client, scanner and verifier can all use it without a cycle."""

import struct

_RESERVED = [
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


def ip_to_int(ip: str) -> int:
    return struct.unpack("!I", bytes(int(o) for o in ip.split(".")))[0]


def int_to_ip(n: int) -> str:
    return ".".join(str(b) for b in struct.pack("!I", n))


RESERVED_RANGES: list[tuple[int, int]] = [(ip_to_int(a), ip_to_int(b)) for a, b in _RESERVED]


def is_reserved_int(ip_int: int) -> bool:
    for start, end in RESERVED_RANGES:
        if start <= ip_int <= end:
            return True
    return False


def is_reserved_address(addr: str) -> bool:
    """True for an IPv4 literal in a reserved range, and for anything that
    is not an IPv4 literal at all."""
    try:
        return is_reserved_int(ip_to_int(addr))
    except (ValueError, TypeError, struct.error, AttributeError):
        return True
