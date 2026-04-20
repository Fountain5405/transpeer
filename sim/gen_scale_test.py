#!/usr/bin/env python3
"""Generate Shadow configs at various scales.

Uses --static-peers so each host runs ONE Python process (transpeer only),
no separate fake daemons. This keeps per-host memory low (~40MB) and
enables large-scale simulations.

Generates:
- Configurable number of honest transpeers across 10 P2P networks
- Some honest nodes run multiple networks
- Attacker nodes flooding random networks
"""

import argparse
import random
import yaml

TRANSPEER_PATH = "/home/lever65/transpeer"
NETWORKS = [f"p2p{chr(ord('a') + i)}" for i in range(10)]


def network_ports(net_idx):
    base = 10000 + net_idx * 100
    return base, base + 1


def idx_to_ip(idx):
    """Convert 1-based index to IP in 11.x.x.x range."""
    b2 = (idx >> 16) & 0xFF
    b3 = (idx >> 8) & 0xFF
    b4 = idx & 0xFF
    return f"11.{b2}.{b3}.{b4}"


def gen_config(num_honest, num_attackers, attacker_fake_peers, difficulty,
               stop_time, seed=42):
    random.seed(seed)
    total = num_honest + num_attackers

    # Scan range sized to the host count
    if total <= 250:
        scan_range = "11.0.0.0/24"
    elif total <= 4000:
        scan_range = "11.0.0.0/20"
    elif total <= 65000:
        scan_range = "11.0.0.0/16"
    else:
        scan_range = "11.0.0.0/8"

    # First pass: assign networks to each honest node
    honest_nets = []
    for i in range(num_honest):
        num_nets = random.choice([1, 1, 1, 1, 2, 2, 3])  # weighted toward 1
        nets = random.sample(NETWORKS, min(num_nets, len(NETWORKS)))
        honest_nets.append(nets)

    # Group nodes by network membership for peer assignment
    nodes_by_network: dict[str, list[int]] = {n: [] for n in NETWORKS}
    for i, nets in enumerate(honest_nets):
        for n in nets:
            nodes_by_network[n].append(i + 1)  # 1-based

    config = {
        "general": {
            "stop_time": f"{stop_time}s",
            "model_unblocked_syscall_latency": True,
            "parallelism": min(24, max(4, total // 100)),
        },
        "network": {
            "graph": {
                "type": "gml",
                "inline": """graph [
  node [
    id 0
    label "net0"
    bandwidth_down "1 Gbit"
    bandwidth_up "1 Gbit"
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

    # --- Honest nodes ---
    for i in range(num_honest):
        host_idx = i + 1
        ip = idx_to_ip(host_idx)
        nets = honest_nets[i]

        # Build static peer list per network: random sample of peers in same network
        static_parts = []
        network_specs = []
        for net_name in nets:
            net_idx = NETWORKS.index(net_name)
            p2p_port, _ = network_ports(net_idx)
            network_specs.append(f"{net_name}:{p2p_port}:{p2p_port+1}")

            peer_pool = [idx for idx in nodes_by_network[net_name] if idx != host_idx]
            sample_size = min(4, len(peer_pool))
            if sample_size > 0:
                sampled = random.sample(peer_pool, sample_size)
                peers = [f"{idx_to_ip(p)}:{p2p_port}" for p in sampled]
                static_parts.append(f"{net_name}:{','.join(peers)}")

        static_peers_arg = ";".join(static_parts) if static_parts else ""
        nets_arg = " ".join(network_specs)

        args = (
            f"-m transpeer --bind 0.0.0.0 --port 7337 "
            f"--scan-range {scan_range} --difficulty {difficulty} "
            f"--networks {nets_arg} --in-memory --no-pow --no-verify"
        )
        if static_peers_arg:
            args += f" --static-peers '{static_peers_arg}'"

        config["hosts"][f"honest{host_idx}"] = {
            "network_node_id": 0,
            "bandwidth_down": "100 Mbit",
            "bandwidth_up": "100 Mbit",
            "ip_addr": ip,
            "processes": [{
                "path": "python3",
                "args": args,
                "environment": {"PYTHONPATH": TRANSPEER_PATH, "PYTHONUNBUFFERED": "1"},
                "start_time": "3s",
                "expected_final_state": "running",
            }],
        }

    # --- Attacker nodes ---
    for i in range(num_attackers):
        host_idx = num_honest + i + 1
        ip = idx_to_ip(host_idx)

        target_net = random.choice(NETWORKS)
        target_port = network_ports(NETWORKS.index(target_net))[0]

        config["hosts"][f"attacker{i+1}"] = {
            "network_node_id": 0,
            "bandwidth_down": "100 Mbit",
            "bandwidth_up": "100 Mbit",
            "ip_addr": ip,
            "processes": [{
                "path": "python3",
                "args": (
                    f"{TRANSPEER_PATH}/sim/attacker.py "
                    f"--target-network {target_net} --target-port {target_port} "
                    f"--num-fake-peers {attacker_fake_peers} "
                    f"--port 7337 --difficulty {difficulty} --no-pow"
                ),
                "environment": {"PYTHONPATH": TRANSPEER_PATH, "PYTHONUNBUFFERED": "1"},
                "start_time": "3s",
                "expected_final_state": "running",
            }],
        }

    return config, total


def main():
    parser = argparse.ArgumentParser(description="Generate scale test Shadow config")
    parser.add_argument("--honest", type=int, default=50)
    parser.add_argument("--attackers", type=int, default=5)
    parser.add_argument("--fake-peers", type=int, default=100)
    parser.add_argument("--difficulty", type=int, default=100)
    parser.add_argument("--stop-time", type=int, default=600)
    parser.add_argument("--output", default="shadow_scale.yaml")
    args = parser.parse_args()

    config, total = gen_config(
        args.honest, args.attackers, args.fake_peers,
        args.difficulty, args.stop_time,
    )

    with open(args.output, "w") as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)

    print(f"Generated {args.output}")
    print(f"  {args.honest} honest + {args.attackers} attackers = {total} total hosts")
    print(f"  1 Python process per host (static peers, no separate daemons)")
    print(f"  Estimated memory: ~{total * 40} MB ({total * 40 / 1024:.1f} GB)")


if __name__ == "__main__":
    main()
