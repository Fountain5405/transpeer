"""Abstract base class for network plugins."""

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class PeerInfo:
    addr: str
    port: int


class Network(ABC):
    name: str
    default_port: int
    default_rpc_port: int

    @abstractmethod
    async def extract_peers(self, rpc_host: str = "127.0.0.1") -> list[PeerInfo]:
        """Extract peer list from a locally running daemon via RPC."""

    @abstractmethod
    async def verify_peer(self, addr: str, port: int) -> bool:
        """Probe a remote peer to check if it's running this network's daemon."""
