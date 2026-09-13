"""The list blob, spec §3.1: a canonical byte string naming up to 64
transpeers, hashed with SHA-256 to make the aux leaf."""

import hashlib
import ipaddress
from dataclasses import dataclass

MAGIC = b"TPL1"
VERSION = 1
PERIOD_SECONDS = 1500
MAX_ENTRIES = 64
MAX_BLOB_SIZE = 1024

_RESERVED = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
    "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
    "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
)]


class BlobError(ValueError):
    """The bytes are not a canonical version-1 blob."""


class UnknownBlobVersion(BlobError):
    """Readers ignore these and do not count the commitment as unavailable."""


@dataclass(frozen=True)
class Blob:
    chain: str
    period: int
    entries: tuple[tuple[str, int], ...]


def is_reserved(ip: str) -> bool:
    a = ipaddress.IPv4Address(ip)
    return any(a in n for n in _RESERVED)


def period_of(unix: float) -> int:
    return int(unix) // PERIOD_SECONDS


def _entry_key(e: tuple[str, int]) -> tuple[int, int]:
    return int(ipaddress.IPv4Address(e[0])), e[1]


def _validate_entries(entries) -> list[tuple[str, int]]:
    if not 1 <= len(entries) <= MAX_ENTRIES:
        raise BlobError(f"count {len(entries)} not in 1..{MAX_ENTRIES}")
    out = []
    for ip, port in entries:
        try:
            ipaddress.IPv4Address(ip)
        except ValueError as e:
            raise BlobError(f"bad address {ip!r}") from e
        if not 1 <= port <= 65535:
            raise BlobError(f"bad port {port}")
        if is_reserved(ip):
            raise BlobError(f"reserved address {ip}")
        out.append((ip, port))
    out.sort(key=_entry_key)
    for a, b in zip(out, out[1:]):
        if a == b:
            raise BlobError(f"duplicate entry {a}")
    return out


def encode_blob(chain: str, period: int, entries) -> bytes:
    name = chain.encode("utf-8")
    if not 1 <= len(name) <= 255:
        raise BlobError("chain name length")
    if period < 0 or period >= 1 << 64:
        raise BlobError("period range")
    ents = _validate_entries(list(entries))
    out = bytearray(MAGIC)
    out.append(VERSION)
    out.append(len(name))
    out += name
    out += period.to_bytes(8, "little")
    out += len(ents).to_bytes(2, "little")
    for ip, port in ents:
        out += ipaddress.IPv4Address(ip).packed
        out += port.to_bytes(2, "little")
    if len(out) > MAX_BLOB_SIZE:
        raise BlobError("blob too large")
    return bytes(out)


def decode_blob(data: bytes) -> Blob:
    if len(data) > MAX_BLOB_SIZE:
        raise BlobError("blob too large")
    if data[:4] != MAGIC:
        raise BlobError("bad magic")
    if len(data) < 6:
        raise BlobError("truncated")
    if data[4] != VERSION:
        raise UnknownBlobVersion(f"version {data[4]}")
    n = data[5]
    if n == 0 or len(data) < 16 + n:
        raise BlobError("truncated header")
    try:
        chain = data[6:6 + n].decode("utf-8")
    except UnicodeDecodeError as e:
        raise BlobError("chain name not UTF-8") from e
    period = int.from_bytes(data[6 + n:14 + n], "little")
    count = int.from_bytes(data[14 + n:16 + n], "little")
    if len(data) != 16 + n + 6 * count:
        raise BlobError("length does not match count")
    raw = []
    for i in range(count):
        off = 16 + n + 6 * i
        raw.append((str(ipaddress.IPv4Address(data[off:off + 4])),
                    int.from_bytes(data[off + 4:off + 6], "little")))
    ents = _validate_entries(raw)
    if ents != raw:
        raise BlobError("entries not in canonical order")
    return Blob(chain, period, tuple(ents))


def blob_hash(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def with_period(body: bytes, period: int) -> bytes:
    n = body[5]
    return body[:6 + n] + period.to_bytes(8, "little") + body[14 + n:]


def list_body(data: bytes) -> bytes:
    """The blob with `period` zeroed: what a publisher's list *is*,
    independent of when it was reissued."""
    return with_period(data, 0)
