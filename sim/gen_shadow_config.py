#!/usr/bin/env python3
"""Generate Shadow config for transpeer cross-network simulation.

Creates 5 synthetic P2P networks (p2pa-p2pe), each with 3 nodes.
Each node runs a fake daemon + a transpeer instance.
All transpeers scan the same IP range to discover each other.
"""

import yaml

NUM_NETWORKS = 5
NODES_PER_NETWORK = 3
TOTAL_NODES = NUM_NETWORKS * NODES_PER_NETWORK  # 15

BASE_IP = "11.0.0"
SCAN_RANGE = f"{BASE_IP}.0/28"  # 14 usable, we have 15 — use /27 for 30
SCAN_RANGE = f"{BASE_IP}.0/27"  # 30 usable addresses

# Port scheme per network:
# p2pa: p2p=10000, rpc=10001
# p2pb: p2p=10100, rpc=10101
# etc.
def network_ports(net_idx):
    base = 10000 + net_idx * 100
    return base, base + 1  # p2p_port, rpc_port

NETWORKS = [f"p2p{chr(ord('a') + i)}" for i in range(NUM_NETWORKS)]
TRANSPEER_PATH = "/home/lever65/transpeer"

config = {
    "general": {
        "stop_time": "600s",
        "model_unblocked_syscall_latency": True,
        "parallelism": 4,
    },
    "network": {
        "graph": {
            "type": "gml",
            "inline": """graph [
  node [
    id 0
    label "net0"
    bandwidth_down "100 Mbit"
    bandwidth_up "100 Mbit"
  ]
  edge [
    source 0
    target 0
    latency "50 ms"
    packet_loss 0.0
  ]
]""",
        },
    },
    "hosts": {},
}

node_idx = 0
for net_i, net_name in enumerate(NETWORKS):
    p2p_port, rpc_port = network_ports(net_i)

    # Collect all node IPs in this network for the peer list
    node_ips = []
    for j in range(NODES_PER_NETWORK):
        ip = f"{BASE_IP}.{node_idx + j + 1}"
        node_ips.append(f"{ip}:{p2p_port}")

    for j in range(NODES_PER_NETWORK):
        ip = f"{BASE_IP}.{node_idx + 1}"
        host_name = f"node{node_idx + 1}"

        # Peer list for this daemon: all other nodes in same network
        other_peers = [p for p in node_ips if not p.startswith(f"{ip}:")]
        peers_str = ",".join(other_peers)

        # Network spec for transpeer: "p2pa:10000:10001"
        net_spec = f"{net_name}:{p2p_port}:{rpc_port}"

        config["hosts"][host_name] = {
            "network_node_id": 0,
            "bandwidth_down": "100 Mbit",
            "bandwidth_up": "100 Mbit",
            "ip_addr": ip,
            "processes": [
                # Fake daemon
                {
                    "path": "python3",
                    "args": (
                        f"{TRANSPEER_PATH}/sim/daemons/fake_daemon.py "
                        f"--network {net_name} --rpc-port {rpc_port} "
                        f"--p2p-port {p2p_port} --peers {peers_str}"
                    ),
                    "environment": {
                        "PYTHONPATH": TRANSPEER_PATH,
                        "PYTHONUNBUFFERED": "1",
                    },
                    "start_time": "1s",
                    "expected_final_state": "running",
                },
                # Transpeer
                {
                    "path": "python3",
                    "args": (
                        f"-m transpeer --bind 0.0.0.0 --port 7337 "
                        f"--scan-range {SCAN_RANGE} --difficulty 1 "
                        f"--networks {net_spec} --in-memory --no-pow"
                    ),
                    "environment": {
                        "PYTHONPATH": TRANSPEER_PATH,
                        "PYTHONUNBUFFERED": "1",
                    },
                    "start_time": "3s",
                    "expected_final_state": "running",
                },
            ],
        }
        node_idx += 1

# Write config
with open("shadow_crossnet.yaml", "w") as f:
    yaml.dump(config, f, default_flow_style=False, sort_keys=False)

print(f"Generated shadow_crossnet.yaml with {TOTAL_NODES} nodes across {NUM_NETWORKS} networks")
print(f"Networks: {', '.join(NETWORKS)}")
print(f"IP range: {BASE_IP}.1 - {BASE_IP}.{TOTAL_NODES}")
print(f"Scan range: {SCAN_RANGE}")
