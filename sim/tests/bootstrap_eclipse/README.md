# bootstrap_eclipse

**Question**: an attacker runs thousands of transpeers so that a fresh node's
random scan finds mostly attacker transpeers. Does the eclipse succeed, and
does bucketed selection change the outcome?

This is a redesign of the matrix entry. The original charted how badly the
attack works against the current policy. This version crosses the attacker's
IP count with the attacker's subnet count and runs each cell under both the
current policy and a bucketed one, so the result tests a defense rather than
just measuring a loss.

## Hypothesis

Under the current policy the attacker's share of the fresh node's store and
queries tracks their share of responsive IPs, A / (A + H).

Under bucketed selection it tracks their share of distinct subnets,
S_a / (S_a + S_h), and is insensitive to A once every attacker subnet is full.

If the hypothesis holds, the cost of the attack moves from "rent IPs" to
"rent IPs in many distinct networks", which is the same lever Bitcoin's
address manager uses.

## Why the current policy loses on count

Three mechanisms found while reading the store, all measured here:

1. The /16 cap applies only to gossiped transpeers. Direct scan hits and
   the candidate path (any IP that sends one request is probed and admitted,
   `transpeer/scanner.py:152`) bypass it.
2. Eviction is by recency. The store holds 500; when full the least recently
   seen is dropped. An attacker that re-announces on a loop always looks
   freshest, so honest transpeers are the ones evicted.
3. Query rotation is oldest-queried-first with no diversity, so attacker
   share of queries equals attacker share of the store.

## Subnet modelling in simulation

Every sim so far has put all hosts in a single /16, because the IP allocator
only varied the second octet past host 65536. Real /16s are too sparse to
scan in fifteen simulated minutes, so the bucket prefix length is a node
flag: `--subnet-prefix 16` in production, `--subnet-prefix 24` here.

Layout inside the scan range `11.0.0.0/16`, buckets are /24s:

- honest transpeers: buckets 0..H-1, one per bucket
- fresh node: bucket H
- attacker transpeers: buckets H+1 onward, `--attacker-subnets` of them,
  IPs dealt round-robin across those buckets

A /24 holds 254 hosts, so an attacker with 1500 IPs cannot fit in one
bucket. The generator raises the subnet count to the minimum that fits and
records the actual value in results.

## Setup

- 50 honest transpeers, start at t=3s
- 1 fresh honest node, starts at t=300s, snapshot logging on
- A attacker transpeers, start at t=3s, each serving fake peers for a random
  network and self-announcing to every honest transpeer every 60s
- 20 min simulated; the fresh node runs for the final 15, which gives it
  three 300-second query cycles of 20 transpeers each

Scenario grid:

| axis | values |
|---|---|
| attacker IPs A | 50, 150, 500, 1500 |
| attacker subnets S_a | concentrated, 25, 100, spread |
| policy | current, bucketed |

"concentrated" is the minimum number of /24s that fit A. "spread" is
min(A, 200). Cells where S_a exceeds A are skipped.

## Bucketed policy (`--bucketed`)

- Per-bucket admission cap on every path: scan, candidate, gossip.
- Eviction from the most populated bucket first, oldest member within it.
- Query batch and gossip sample chosen bucket-uniform: pick a bucket at
  random, then the oldest-queried transpeer in it, repeat.

Deferred to a follow-up: a protected "tried" table for transpeers that have
answered across several cycles, and counting a peer's vouchers by distinct
bucket rather than by transpeer.

## Metrics (fresh node, end of run)

- `store_attacker_pct`: share of the transpeer store that is attacker IPs
- `query_attacker_pct`: share of queries issued that went to attacker IPs
- `peer_attacker_pct`: share of peer entries whose source transpeer is an
  attacker IP
- `honest_transpeers_known`: how many of the 50 honest transpeers the fresh
  node ended up knowing at all

## Pass/fail

Report the curve. The experiment passes as a defense test if, under
`--bucketed`, `store_attacker_pct` for A=1500 concentrated is within a few
points of A=50 concentrated, and both are far below the current-policy
value. It fails if bucketing merely shifts the curve down without flattening
it against A.
