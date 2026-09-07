#!/usr/bin/env python3
"""Generate a Shadow config for the bootstrap_eclipse experiment.

Layout: scan range 11.0.0.0/16, buckets are /24s (--subnet-prefix 24 on
every node). See README.md for the design.

  honest i      -> 11.0.<i>.1               i in 0..H-1, one per bucket
  fresh node    -> 11.0.<H>.1               starts late, snapshot logging on
  attacker j    -> 11.0.<H+1 + j % S>.<1 + j // S>
                                            S attacker buckets, dealt round-robin

A /24 holds 254 hosts, so S is raised to the minimum that fits A when the
requested value is too small. The actual S is printed and written into the
config as a comment-like key under `general` is not allowed by Shadow, so the
runner reads it from this script's stdout instead.
"""

import argparse
import math
import os
import random
from pathlib import Path

import yaml

TRANSPEER_PATH = os.environ.get(
    "TRANSPEER_DIR", str(Path(__file__).resolve().parents[3]))
PYTHON_BIN = os.environ.get("TRANSPEER_PYTHON", "python3")
SIM_PARALLELISM = int(os.environ.get("SIM_PARALLELISM", "60"))

NETWORKS = [f"p2p{chr(ord('a') + i)}" for i in range(10)]
SCAN_RANGE = "11.0.0.0/16"
SUBNET_PREFIX = 24          # bucket size in simulation; production uses 16
HOSTS_PER_BUCKET = 254
MAX_ATTACKER_BUCKETS = 200  # leaves room for honest + fresh in the /16
TRANSPEER_PORT = 7337
# Attacker self-announce cadence. One request per (attacker, honest) pair is
# enough for admission; repeating refreshes last_seen. Matches QUERY_INTERVAL
# so the largest cells stay tractable: 1500 attackers x 50 targets / 300s is
# 250 req/s across the whole sim.
ANNOUNCE_INTERVAL = 300

# Honest peer model. Each network has a population of daemon peers (12.x.x.x,
# outside the scan range, nothing listens there) and each honest transpeer
# serves a sample of them, weighted so a few well-established peers appear
# in most lists. That overlap is what gives a real peer voucher depth. The
# fresh node's network is run by most honest nodes, the way one large
# network dominates a real deployment.
PEER_POPULATION = 200
PEERS_PER_NODE = 16          # 3 networks x 16 stays under BASE_PEERS_PER_SOURCE
POPULARITY_EXPONENT = 0.7    # weight 1/(rank+1)^e
PRIMARY_NET_SHARE = 0.6      # honest nodes running the fresh node's network


def network_ports(net_idx):
    base = 10000 + net_idx * 100
    return base, base + 1


def bucket_ip(bucket, host):
    assert 0 <= bucket <= 255 and 1 <= host <= HOSTS_PER_BUCKET, (bucket, host)
    return f"11.0.{bucket}.{host}"


def resolve_subnets(num_attackers, requested):
    """Turn the --attacker-subnets argument into an actual bucket count."""
    min_fit = max(1, math.ceil(num_attackers / HOSTS_PER_BUCKET))
    if requested == "concentrated":
        want = min_fit
    elif requested == "spread":
        want = min(num_attackers, MAX_ATTACKER_BUCKETS)
    else:
        want = int(requested)
    want = min(want, MAX_ATTACKER_BUCKETS, max(num_attackers, 1))
    return max(want, min_fit)


GRAPH = """graph [
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


def gen(num_honest, num_attackers, attacker_subnets, bucketed, stop_time,
        fresh_start, snapshot_interval, fake_peers, difficulty, seed,
        vouchers=False, coordinated=False):
    random.seed(seed)
    S = resolve_subnets(num_attackers, attacker_subnets)
    if num_honest + 1 + S > 256:
        raise SystemExit(f"{num_honest} honest + fresh + {S} attacker buckets "
                         f"exceed the 256 /24s in {SCAN_RANGE}")

    config = {
        "general": {
            "stop_time": f"{stop_time}s",
            "model_unblocked_syscall_latency": True,
            "parallelism": min(SIM_PARALLELISM,
                               max(4, num_honest + 1 + num_attackers)),
        },
        "network": {"graph": {"type": "gml", "inline": GRAPH}},
        "hosts": {},
    }

    policy_flags = f" --subnet-prefix {SUBNET_PREFIX}"
    if bucketed:
        policy_flags += " --bucketed"
    if vouchers:
        policy_flags += " --vouchers"

    def transpeer_process(args, start):
        return {
            "path": PYTHON_BIN,
            "args": args,
            "environment": {"PYTHONPATH": TRANSPEER_PATH, "PYTHONUNBUFFERED": "1"},
            "start_time": f"{start}s",
            "expected_final_state": "running",
        }

    def host(name, ip, process):
        config["hosts"][name] = {
            "network_node_id": 0,
            "bandwidth_down": "100 Mbit",
            "bandwidth_up": "100 Mbit",
            "ip_addr": ip,
            "processes": [process],
        }

    # --- Honest transpeers: one dominant network plus a few small ones ------
    fresh_net = "p2pa"
    others = [n for n in NETWORKS if n != fresh_net]
    honest_nets = []
    for _ in range(num_honest):
        nets = [fresh_net] if random.random() < PRIMARY_NET_SHARE else []
        nets += random.sample(others, random.choice([0, 0, 1, 1, 2]))
        if not nets:
            nets.append(random.choice(others))
        honest_nets.append(nets)

    def daemon_peer_ip(net, rank):
        return f"12.{NETWORKS.index(net)}.{rank // 250}.{rank % 250 + 1}"

    weights = [1.0 / (r + 1) ** POPULARITY_EXPONENT for r in range(PEER_POPULATION)]

    def sample_population(k):
        """k distinct ranks; popular ones far more likely."""
        chosen = set()
        while len(chosen) < k:
            chosen.add(random.choices(range(PEER_POPULATION), weights=weights, k=1)[0])
        return sorted(chosen)

    def static_peers_for(nets, k=PEERS_PER_NODE):
        parts = []
        for net in nets:
            p2p, _ = network_ports(NETWORKS.index(net))
            peers = ",".join(f"{daemon_peer_ip(net, r)}:{p2p}" for r in sample_population(k))
            parts.append(f"{net}:{peers}")
        return ";".join(parts)

    honest_ips = []
    for i, nets in enumerate(honest_nets):
        ip = bucket_ip(i, 1)
        honest_ips.append(ip)
        specs = " ".join(
            f"{n}:{network_ports(NETWORKS.index(n))[0]}:{network_ports(NETWORKS.index(n))[1]}"
            for n in nets)
        args = (f"-m transpeer --bind 0.0.0.0 --port {TRANSPEER_PORT} "
                f"--scan-range {SCAN_RANGE} --difficulty {difficulty} "
                f"--networks {specs} --in-memory --sim-pow --no-verify"
                + policy_flags)
        sp = static_peers_for(nets)
        if sp:
            args += f" --static-peers '{sp}'"
        host(f"honest{i+1}", ip, transpeer_process(args, 3))

    # --- Fresh node: one network, starts late, snapshots its store ----------
    fresh_bucket = num_honest
    fresh_ip = bucket_ip(fresh_bucket, 1)
    p2p, rpc = network_ports(NETWORKS.index(fresh_net))
    args = (f"-m transpeer --bind 0.0.0.0 --port {TRANSPEER_PORT} "
            f"--scan-range {SCAN_RANGE} --difficulty {difficulty} "
            f"--networks {fresh_net}:{p2p}:{rpc} --in-memory --sim-pow --no-verify"
            f" --snapshot-interval {snapshot_interval}" + policy_flags)
    # Two seeds only: a real fresh daemon knows a handful of addresses.
    args += f" --static-peers '{static_peers_for([fresh_net], k=2)}'"
    host("fresh", fresh_ip, transpeer_process(args, fresh_start))

    # --- Attackers: fake peers + self-announce to every honest transpeer ----
    announce = ",".join(honest_ips)
    first_attacker_bucket = num_honest + 1
    for j in range(num_attackers):
        bucket = first_attacker_bucket + (j % S)
        ip = bucket_ip(bucket, 1 + j // S)
        # Coordinated: every attacker targets the fresh node's network and
        # serves the same fake set, so each fake carries one voucher per
        # attacker subnet. Independent: random network, random fakes.
        target = fresh_net if coordinated else random.choice(NETWORKS)
        tport = network_ports(NETWORKS.index(target))[0]
        args = (f"{TRANSPEER_PATH}/sim/attacker.py "
                f"--target-network {target} --target-port {tport} "
                f"--num-fake-peers {fake_peers} --port {TRANSPEER_PORT} "
                f"--difficulty {difficulty} --sim-pow --serve-while-generating "
                f"--announce-targets {announce} "
                f"--announce-interval {ANNOUNCE_INTERVAL}")
        if coordinated:
            args += " --fake-seed 1"
        host(f"attacker{j+1}", ip, transpeer_process(args, 3))

    return config, S, first_attacker_bucket


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--honest", type=int, default=50)
    ap.add_argument("--attackers", type=int, default=50)
    ap.add_argument("--attacker-subnets", default="concentrated",
                    help="integer, 'concentrated' (fewest /24s that fit) "
                         "or 'spread' (one attacker per /24, up to 200)")
    ap.add_argument("--bucketed", action="store_true",
                    help="run all transpeer nodes with --bucketed")
    ap.add_argument("--vouchers", action="store_true",
                    help="run all transpeer nodes with --vouchers")
    ap.add_argument("--coordinated", action="store_true",
                    help="all attackers target the fresh node's network and "
                         "serve one shared fake set")
    ap.add_argument("--stop-time", type=int, default=900)
    ap.add_argument("--fresh-start", type=int, default=300)
    ap.add_argument("--snapshot-interval", type=int, default=60)
    ap.add_argument("--fake-peers", type=int, default=100)
    ap.add_argument("--difficulty", type=int, default=100)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--output", required=True)
    a = ap.parse_args()

    config, S, first_attacker_bucket = gen(
        a.honest, a.attackers, a.attacker_subnets, a.bucketed, a.stop_time,
        a.fresh_start, a.snapshot_interval, a.fake_peers, a.difficulty, a.seed,
        vouchers=a.vouchers, coordinated=a.coordinated)

    with open(a.output, "w") as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)

    total = a.honest + 1 + a.attackers
    print(f"Generated {a.output}: {total} hosts")
    print(f"  {a.honest} honest in buckets 0..{a.honest-1}, fresh in bucket {a.honest}")
    print(f"  {a.attackers} attackers across {S} buckets starting at {first_attacker_bucket}")
    policy = 'bucketed' if a.bucketed else 'current'
    if a.vouchers:
        policy += '+vouchers'
    print(f"  policy={policy} attackers={'coordinated' if a.coordinated else 'independent'}")
    # Machine-readable line for the runner.
    print(f"ECLIPSE_LAYOUT honest={a.honest} attackers={a.attackers} "
          f"attacker_subnets={S} first_attacker_bucket={first_attacker_bucket} "
          f"fresh_bucket={a.honest}")


if __name__ == "__main__":
    main()
