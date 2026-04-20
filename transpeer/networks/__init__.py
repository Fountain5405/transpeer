from .base import Network
from .monero import MoneroNetwork
from .wownero import WowneroNetwork
from .aeon import AeonNetwork
from .generic import GenericNetwork

REGISTRY: dict[str, type[Network]] = {
    "monero": MoneroNetwork,
    "wownero": WowneroNetwork,
    "aeon": AeonNetwork,
}


def get_network(name: str) -> Network:
    """Get a network by name. Supports 'name:p2p_port:rpc_port' for generic networks."""
    # Check for generic format: "p2pa:10000:10001"
    if ":" in name:
        parts = name.split(":")
        if len(parts) == 3:
            net_name, p2p_port, rpc_port = parts
            return GenericNetwork(net_name, int(p2p_port), int(rpc_port))

    cls = REGISTRY.get(name)
    if cls is None:
        raise ValueError(f"Unknown network: {name}")
    return cls()
