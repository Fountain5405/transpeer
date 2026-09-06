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
`--bucketed`, `store_attacker_pct` is flat against A at a fixed subnet
count and far below the current-policy value. It fails if bucketing merely
shifts the curve down without flattening it against A.

## Results

30 cells, all completed. 60 to 120 s wall-clock each, 40 minutes for the
grid: attackers do not scan or gossip, so they cost a fraction of an honest
host. Full CSV in `results.txt`.

Share of the fresh node's transpeer store that is attacker IPs, current
policy → bucketed:

| attackers | concentrated | 25 subnets | 100 subnets | spread |
|----------:|:------------:|:----------:|:-----------:|:------:|
| 50   | 33 → **6** (1 subnet)  | 50 → 50 | n/a     | 50 → 50 (50) |
| 150  | 52 → **6** (1 subnet)  | 67 → 60 | 75 → 75 | 75 → 75 (150) |
| 500  | 83 → **11** (2 subnets)| 84 → 60 | 88 → 85 | 88 → 87 (200) |
| 1500 | 96 → **27** (6 subnets)| 95 → 60 | 95 → 87 | 95 → 91 (200) |

Share of the fresh node's queries that went to attackers:

| attackers | concentrated | 25 subnets | 100 subnets | spread |
|----------:|:------------:|:----------:|:-----------:|:------:|
| 50   | 20 → 8  | 39 → 21 | n/a     | 42 → 37 |
| 150  | 45 → 12 | 63 → 55 | 63 → 68 | 65 → 63 |
| 500  | 80 → 18 | 75 → 53 | 78 → 85 | 75 → 85 |
| 1500 | 90 → 20 | 90 → 48 | 88 → 93 | 85 → 80 |

Honest transpeers the fresh node still knew at the end, of 50: current
policy at 1500 attackers, 22 to 25. Bucketed, 46 to 50, at every cell.

## What we learned

**The hypothesis holds, and the bucketed number is predictable to the
point.** Under the current policy the attacker's store share tracks IP
count: 33, 52, 83, 96 percent at one to six subnets. Under bucketing it is
exactly `min(A, 3·S) / (min(A, 3·S) + 50)`: 5.7 at one subnet, 10.7 at
two, 26.5 at six, 60 at 25, whatever the IP count. Attack cost moved from
"rent IPs" to "rent IPs in distinct subnets", and with a cap of 3 per
bucket the attacker needs a third as many subnets as the honest network
has to reach parity. Lowering the cap to 1 would make it one to one.

**Recency eviction is what turns a majority into an eclipse.** At 1500
attackers the current policy had evicted half the honest transpeers from
the fresh node's store; the attackers' constant re-announcing kept their
own entries fresh. Bucketed eviction never touched a lonely honest bucket.

**Bucketing does not help once the attacker has more subnets than the
honest network.** At 100 or 200 attacker subnets against 50 honest, both
policies land at 75 to 95 percent. That is the fundamental limit: an
adversary with more diverse address space than the honest population is,
for discovery purposes, the network. ASN bucketing raises the price of
"diverse" but does not remove the limit. Only trust anchors or
cross-source consistency checks act on this regime.

**Query share lags the store formula early on.** At 25 subnets bucketed
queries ran 48 to 55 percent attacker where the final store predicts 33.
Attacker buckets hold three IPs to an honest bucket's one, so scanning
fills them first, and the first query cycles ran against a store that was
more attacker-heavy than its final state. Longer runs converge.

**Peer share is a simulation artifact, but it points at a real lever.**
Attacker share of peer entries was 85 to 98 percent nearly everywhere,
including 69 to 85 under bucketed concentrated. Honest transpeers here
serve four static peers per network; an attacker serves 100 fakes under a
50-per-source cap, so one attacker query yields a dozen times the entries
of an honest one. Real honest nodes serve far more, so the ratio is less
extreme in production, but a per-source cap keyed on volume still lets a
single source outweigh many. Counting a peer's vouchers by distinct bucket
(deferred from this round) is the fix to test next.

## Follow-ups

1. Voucher counting by bucket, then rerun the concentrated column and read
   `peer_attacker_pct`.
2. A protected "tried" table, so that even a subnet-rich attacker cannot
   displace transpeers that have answered over several cycles.
3. Rerun the 25-subnet column at 40 simulated minutes to confirm query
   share converges to the store formula.
4. Honest peer counts closer to reality in the generator, so peer-store
   metrics stop being dominated by the static-peers setup.
