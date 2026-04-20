#!/usr/bin/env python3
"""Generate Shadow config for attacker simulation.

Scenario:
- 5 honest transpeer nodes running p2pa with real fake daemons
- 1 attacker node that floods the network with fake p2pa peers
- All nodes have PoW enabled at difficulty 100

The test measures:
1. How long does it take the attacker to generate N fake entries?
2. Do honest nodes accept or reject the fake entries?
3. Does peer verification catch the fakes (they won't respond on p2p port)?
"""

import yaml

TRANSPEER_PATH = "/home/lever65/transpeer"
SCAN_RANGE = "11.0.0.0/28"
DIFFICULTY = 100
ATTACKER_FAKE_PEERS = 50  # Attacker tries to inject 50 fake peers

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

# 5 honest nodes: run fake p2pa daemon + transpeer with PoW
p2p_port = 10000
rpc_port = 10001

for i in range(1, 6):
    ip = f"11.0.0.{i}"
    # Build peer list (other honest nodes)
    other_peers = ",".join(f"11.0.0.{j}:{p2p_port}" for j in range(1, 6) if j != i)

    config["hosts"][f"honest{i}"] = {
        "network_node_id": 0,
        "bandwidth_down": "100 Mbit",
        "bandwidth_up": "100 Mbit",
        "ip_addr": ip,
        "processes": [
            # Fake p2pa daemon
            {
                "path": "python3",
                "args": (
                    f"{TRANSPEER_PATH}/sim/daemons/fake_daemon.py "
                    f"--network p2pa --rpc-port {rpc_port} "
                    f"--p2p-port {p2p_port} --peers {other_peers}"
                ),
                "environment": {"PYTHONPATH": TRANSPEER_PATH, "PYTHONUNBUFFERED": "1"},
                "start_time": "1s",
                "expected_final_state": "running",
            },
            # Transpeer with simulated PoW (Shadow-compatible)
            {
                "path": "python3",
                "args": (
                    f"-m transpeer --bind 0.0.0.0 --port 7337 "
                    f"--scan-range {SCAN_RANGE} --difficulty {DIFFICULTY} "
                    f"--networks p2pa:{p2p_port}:{rpc_port} --in-memory --sim-pow"
                ),
                "environment": {"PYTHONPATH": TRANSPEER_PATH, "PYTHONUNBUFFERED": "1"},
                "start_time": "3s",
                "expected_final_state": "running",
            },
        ],
    }

# Attacker node at 11.0.0.6
config["hosts"]["attacker"] = {
    "network_node_id": 0,
    "bandwidth_down": "100 Mbit",
    "bandwidth_up": "100 Mbit",
    "ip_addr": "11.0.0.6",
    "processes": [
        {
            "path": "python3",
            "args": (
                f"{TRANSPEER_PATH}/sim/attacker.py "
                f"--target-network p2pa --target-port {p2p_port} "
                f"--num-fake-peers {ATTACKER_FAKE_PEERS} "
                f"--port 7337 --difficulty {DIFFICULTY} --sim-pow"
            ),
            "environment": {"PYTHONPATH": TRANSPEER_PATH, "PYTHONUNBUFFERED": "1"},
            "start_time": "3s",
            "expected_final_state": "running",
        },
    ],
}

with open("shadow_attacker.yaml", "w") as f:
    yaml.dump(config, f, default_flow_style=False, sort_keys=False)

print(f"Generated shadow_attacker.yaml")
print(f"  5 honest nodes (11.0.0.1-5) running p2pa + transpeer (difficulty={DIFFICULTY})")
print(f"  1 attacker (11.0.0.6) generating {ATTACKER_FAKE_PEERS} fake peers with PoW")
