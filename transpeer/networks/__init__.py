from .base import Network
from .monero import MoneroNetwork
from .wownero import WowneroNetwork
from .aeon import AeonNetwork

REGISTRY: dict[str, type[Network]] = {
    "monero": MoneroNetwork,
    "wownero": WowneroNetwork,
    "aeon": AeonNetwork,
}


def get_network(name: str) -> Network:
    cls = REGISTRY.get(name)
    if cls is None:
        raise ValueError(f"Unknown network: {name}")
    return cls()
