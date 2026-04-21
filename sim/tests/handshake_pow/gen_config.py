#!/usr/bin/env python3
"""Generate a Shadow config for the handshake-PoW experiment.

Scenario:
- 1 victim transpeer (the DoS target)
- N honest transpeers (normal peers in the network)
- M flooder transpeers hammering the victim
- Honest nodes discover each other by scanning and gossip
- Victim's load_tracker and difficulty adapt to flood volume
"""

import argparse
import yaml

TRANSPEER_PATH = "/home/lever65/transpeer"
NETWORK = "p2pa"
P2P_PORT = 10000
RPC_PORT = 10001
VICTIM_IP = "11.0.0.1"


def gen(num_honest, num_flooders, flood_rate, stop_time, solve_pow, scenario_name):
    total = 1 + num_honest + num_flooders
    # IP layout: 11.0.0.1 = victim, 11.0.0.2..N+1 = honest, then flooders
    scan_range = "11.0.0.0/24"

    # Build static peer lists for the p2pa network among honest nodes
    honest_ips = [f"11.0.0.{i}" for i in range(1, num_honest + 2)]  # include victim

    graph_inline = """graph [
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
]"""

    config = {
        "general": {
            "stop_time": f"{stop_time}s",
            "model_unblocked_syscall_latency": True,
            "parallelism": 8,
        },
        "network": {
            "graph": {"type": "gml", "inline": graph_inline},
        },
        "hosts": {},
    }

    def transpeer_host(name, ip, static_peers_arg):
        args = (
            f"-m transpeer --bind 0.0.0.0 --port 7337 "
            f"--scan-range {scan_range} --difficulty 100 "
            f"--networks {NETWORK}:{P2P_PORT}:{RPC_PORT} "
            f"--in-memory --sim-pow --no-verify"
        )
        if static_peers_arg:
            args += f" --static-peers '{static_peers_arg}'"
        config["hosts"][name] = {
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

    # Victim
    peers_str = ",".join(
        f"{ip}:{P2P_PORT}" for ip in honest_ips if ip != VICTIM_IP
    )
    transpeer_host("victim", VICTIM_IP, f"{NETWORK}:{peers_str}" if peers_str else "")

    # Honest peers
    for i in range(num_honest):
        ip = f"11.0.0.{i + 2}"
        peers_str = ",".join(
            f"{p}:{P2P_PORT}" for p in honest_ips if p != ip
        )
        transpeer_host(f"honest{i+1}", ip,
                       f"{NETWORK}:{peers_str}" if peers_str else "")

    # Flooders — start after honest nodes have a head start (60s simulated)
    for i in range(num_flooders):
        ip = f"11.0.1.{i + 1}"  # outside the honest /24 scan range
        solve_flag = "--solve-pow" if solve_pow else ""
        config["hosts"][f"flooder{i+1}"] = {
            "network_node_id": 0,
            "bandwidth_down": "100 Mbit",
            "bandwidth_up": "100 Mbit",
            "ip_addr": ip,
            "processes": [{
                "path": "python3",
                "args": (
                    f"{TRANSPEER_PATH}/sim/flooder.py "
                    f"--targets {VICTIM_IP} --target-port 7337 "
                    f"--rate {flood_rate} --network {NETWORK} "
                    f"--duration 0 --sim-pow {solve_flag}"
                ).strip(),
                "environment": {"PYTHONPATH": TRANSPEER_PATH, "PYTHONUNBUFFERED": "1"},
                "start_time": "60s",  # head start for honest nodes
                "expected_final_state": "running",
            }],
        }

    return config, total


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--honest", type=int, default=20)
    parser.add_argument("--flooders", type=int, default=5)
    parser.add_argument("--flood-rate", type=float, default=5.0,
                        help="Requests per second per flooder")
    parser.add_argument("--stop-time", type=int, default=600)
    parser.add_argument("--solve-pow", action="store_true",
                        help="Flooders actually solve PoW when challenged")
    parser.add_argument("--name", default="scenario")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    config, total = gen(
        args.honest, args.flooders, args.flood_rate,
        args.stop_time, args.solve_pow, args.name,
    )

    with open(args.output, "w") as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)

    print(f"Generated {args.output}: {total} total hosts")
    print(f"  1 victim, {args.honest} honest, {args.flooders} flooders")
    print(f"  Flood rate: {args.flood_rate} req/s/flooder = "
          f"{args.flooders * args.flood_rate} req/s total")
    print(f"  Flooders solve PoW: {args.solve_pow}")


if __name__ == "__main__":
    main()
