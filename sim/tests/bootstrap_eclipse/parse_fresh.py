#!/usr/bin/env python3
"""Extract eclipse metrics from the fresh node's stderr.

Classifies every IP by its /24 bucket (third octet) using the layout the
generator printed: buckets below `honest` are honest transpeers, `fresh` is
the node itself, and everything from `first_attacker_bucket` up is attacker.

Prints one CSV fragment on stdout:
  store_total,store_attacker_pct,honest_known,buckets,
  queries_total,query_attacker_pct,peers_total,peer_attacker_pct,
  multi_voucher_pct,daemon_attacker_pct,
  top20_honest_max_vouchers,top20_attacker_min_vouchers,
  tried_total,tried_honest,snapshots

multi_voucher_pct: share of peer entries reported by two or more distinct
buckets. daemon_attacker_pct: share of the top-20 peers per network, in the
order get_peers hands them out, whose source is an attacker.
top20_honest_max_vouchers / top20_attacker_min_vouchers: the deepest honest
entry and the shallowest attacker entry in that list, so the crossover
between honest voucher depth and attacker subnet count is visible.
"""

import argparse
import re
import sys

SNAP_RE = re.compile(
    r"STORE_SNAPSHOT transpeers=(\d+) buckets=(\d+) peers=(\d+) "
    r"transpeer_addrs=(\S*) peer_sources=(\S*)"
    r"(?: voucher_hist=(\S*) daemon_view=(\S*))?"
    r"(?: tried_addrs=(\S*))?")
QUERY_RE = re.compile(r"Querying transpeer (\d+\.\d+\.\d+\.\d+):\d+")


def classify(ip, honest, fresh, first_attacker):
    try:
        b = int(ip.split(".")[2])
    except (IndexError, ValueError):
        return "other"
    if b >= first_attacker:
        return "attacker"
    if b < honest:
        return "honest"
    if b == fresh:
        return "self"
    return "other"


def pct(part, whole):
    return f"{100.0 * part / whole:.1f}" if whole else "0.0"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("stderr")
    ap.add_argument("--honest", type=int, required=True)
    ap.add_argument("--fresh-bucket", type=int, required=True)
    ap.add_argument("--first-attacker-bucket", type=int, required=True)
    a = ap.parse_args()

    cls = lambda ip: classify(ip, a.honest, a.fresh_bucket, a.first_attacker_bucket)

    last_snap = None
    snapshots = 0
    queries = {"attacker": 0, "honest": 0, "self": 0, "other": 0}
    try:
        with open(a.stderr, errors="replace") as f:
            for line in f:
                m = QUERY_RE.search(line)
                if m:
                    queries[cls(m.group(1))] += 1
                    continue
                m = SNAP_RE.search(line)
                if m:
                    snapshots += 1
                    last_snap = m
    except FileNotFoundError:
        print("0,0.0,0,0,0,0.0,0,0.0,0.0,0.0,0,0,0,0,0")
        sys.exit(0)

    store_total = store_attacker = honest_known = buckets = 0
    peers_total = peers_attacker = 0
    multi = hist_total = dv_total = dv_attacker = 0
    hon_max, att_min = 0, None
    tried_total = tried_honest = 0
    if last_snap:
        store_total = int(last_snap.group(1))
        buckets = int(last_snap.group(2))
        addrs = [x for x in last_snap.group(4).split(",") if x]
        store_attacker = sum(1 for ip in addrs if cls(ip) == "attacker")
        honest_known = sum(1 for ip in addrs if cls(ip) == "honest")
        for item in last_snap.group(5).split(";"):
            if not item:
                continue
            src, _, n = item.rpartition(":")
            n = int(n)
            peers_total += n
            if src != "local" and cls(src) == "attacker":
                peers_attacker += n
        if last_snap.group(6) is not None:
            for item in last_snap.group(6).split(";"):
                if not item:
                    continue
                k, _, v = item.partition(":")
                hist_total += int(v)
                if int(k) >= 2:
                    multi += int(v)
        if last_snap.group(7):
            for net_block in last_snap.group(7).split("|"):
                _, _, srcs = net_block.partition(":")
                for item in srcs.split(","):
                    if not item:
                        continue
                    src, _, n = item.rpartition(":")
                    d = int(n) if n.isdigit() else 0
                    dv_total += 1
                    if src != "local" and cls(src) == "attacker":
                        dv_attacker += 1
                        att_min = d if att_min is None else min(att_min, d)
                    else:
                        hon_max = max(hon_max, d)
        if last_snap.group(8):
            for ip in last_snap.group(8).split(","):
                if not ip:
                    continue
                tried_total += 1
                if cls(ip) == "honest":
                    tried_honest += 1

    q_total = sum(queries.values())
    print(",".join([
        str(store_total), pct(store_attacker, store_total), str(honest_known), str(buckets),
        str(q_total), pct(queries["attacker"], q_total),
        str(peers_total), pct(peers_attacker, peers_total),
        pct(multi, hist_total), pct(dv_attacker, dv_total),
        str(hon_max), str(att_min or 0),
        str(tried_total), str(tried_honest),
        str(snapshots),
    ]))


if __name__ == "__main__":
    main()
