#!/usr/bin/env python3
"""Aggregate a bootstrap_eclipse results file over seeds.

Groups rows by scenario name with the trailing _s<seed> removed and prints,
for the chosen columns, mean and min-max over seeds. Rows whose status is
not 'ok' are skipped and counted.
"""
import csv, re, sys, statistics as st
from collections import defaultdict

DEFAULT_COLS = ["store_attacker_pct", "query_attacker_pct", "peer_attacker_pct",
                "daemon_attacker_pct", "top20_honest_max_vouchers",
                "top20_attacker_min_vouchers", "honest_known", "tried_honest"]

def main(path, cols):
    rows = [r for r in open(path) if r.strip() and not r.startswith("#")]
    rd = csv.DictReader(rows)
    groups, skipped = defaultdict(list), 0
    for r in rd:
        if r["status"] != "ok":
            skipped += 1; continue
        key = re.sub(r"_s\d+$", "", r["scenario"])
        groups[key].append(r)
    hdr = "%-46s %2s  " % ("cell", "n") + "  ".join("%-22s" % c for c in cols)
    print(hdr)
    for key, rs in groups.items():
        out = []
        for c in cols:
            v = [float(r[c]) for r in rs]
            out.append("%-22s" % ("%6.1f [%5.1f-%5.1f]" % (st.mean(v), min(v), max(v))))
        print("%-46s %2d  " % (key, len(rs)) + "  ".join(out))
    if skipped: print("skipped %d non-ok rows" % skipped)

if __name__ == "__main__":
    cols = sys.argv[2].split(",") if len(sys.argv) > 2 else DEFAULT_COLS
    main(sys.argv[1], cols)
