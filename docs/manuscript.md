# Bucketed selection and voucher counting against Sybil eclipse of a cross-network peer-discovery overlay

**Status**: working draft, living document. Every number in this file traces
to a results file and a commit listed in §12. Claims are tagged in the
ledger in §13 as *measured*, *extrapolated* or *hypothesis*. Citations
marked `[verify]` are from memory and must be checked before submission.

Branch `bootstrap-eclipse` at the time of writing; see §12 for commits.

---

## Abstract (draft)

Transpeer is a peer-discovery overlay in which a node running any
participating peer-to-peer network can obtain bootstrap peers for any
other. Discovery is by random IPv4 scanning plus gossip, with EquiX
proof-of-work on published peer entries. We study the obvious attack on
such an overlay: an adversary who runs thousands of transpeers so that a
fresh node's scan finds mostly adversary-controlled ones and is fed
adversary-chosen peers. Reading the reference implementation, we find that
its subnet-diversity limit applies to one of three admission paths, that
recency-based eviction lets a re-announcing attacker displace honest
entries, and that query rotation carries no diversity, so the attacker's
share of a victim's attention equals their share of responsive IP
addresses. We propose two changes borrowed in spirit from Bitcoin's
address manager: *bucketed selection*, which caps admission per network
prefix on every path, evicts from the most crowded bucket, and selects
queries and gossip uniformly over buckets; and *voucher counting*, which
keys the per-source peer-acceptance budget by prefix, counts a peer's
sources as the distinct prefixes observed to report it, and hands peers to
the local daemon most-corroborated first. In Shadow simulations of 50
honest transpeers against 50 to 1500 attacker transpeers spread over 1 to
200 prefixes, the attacker's share of the victim's transpeer store follows
`min(A, cS) / (min(A, cS) + H)` for cap `c = 3`, attacker prefixes `S` and
honest transpeers `H`, independent of attacker IP count `A`. Under a
coordinated attacker that serves one shared fake peer set from every
prefix, the peers handed to the daemon stay entirely honest until the
attacker's prefix count reaches the number of distinct honest prefixes
that have reported a typical well-known peer, four in our layout, which
scales with the honest population and with the victim's uptime. Neither
change helps once the attacker controls more prefixes than the honest
network; we argue that bound is inherent to any discovery layer.

---

## 1. Introduction

Bootstrapping a peer-to-peer network requires a first contact. Most
networks hard-code seed nodes or DNS seeds, which are a central point of
failure and censorship. Transpeer's premise is that many independent
networks each already know a population of live peers, and that a shared
discovery layer lets a node on any of them find peers for all of them, so
a brute-force scan of IPv4 space is far more likely to hit *something*
useful than a scan for one network alone.

A shared discovery layer is also a shared target. If an adversary can make
most of the overlay's responsive addresses their own, every network's
bootstrap inherits the adversary's peer lists. This document records what
we have measured about that attack and about two defenses, in enough
detail to be reproduced.

Contributions so far:

1. Three concrete mechanisms in the reference implementation by which an
   attacker wins on raw IP count rather than on address diversity (§5).
2. Bucketed selection (§6.1) and voucher counting (§6.2), each behind a
   flag so the baseline stays testable.
3. A simulation framework (§7) in which a network prefix length is a node
   parameter, so subnet diversity can be modelled inside a scan range
   small enough to sweep in minutes of simulated time.
4. Measurements (§8) that pin the attacker's store share to a closed form,
   locate the crossover for a coordinated attacker, and show where the
   defenses stop applying.

---

## 2. Background and related work

**Sybil and eclipse attacks.** Douceur showed that without a trusted
authority or a scarce resource, identities are free and a minority can
present as a majority `[verify: Douceur, "The Sybil Attack", IPTPS 2002]`.
Heilman, Kendler, Zohar and Goldberg demonstrated eclipse of Bitcoin nodes
by filling their address tables from a modest number of hosts, and Bitcoin
Core's mitigations included bucketing addresses by `/16` prefix
("netgroup") and later by autonomous system via `asmap`, plus protected
"tried" entries and anchor connections `[verify: Heilman et al., "Eclipse
Attacks on Bitcoin's Peer-to-Peer Network", USENIX Security 2015; Bitcoin
Core asmap, 2020]`. Our bucketed selection is the same idea applied to a
discovery overlay rather than to a single network's address manager.

**Proof-of-work as a rate limiter.** Tor's proposal 327 uses EquiX as a
client puzzle whose difficulty rises with load on an onion service
`[verify: Tor proposal 327; tevador, EquiX]`. Transpeer already applies
EquiX to published peer entries and, since an earlier phase of this work,
as an adaptive handshake puzzle on query endpoints (§6.3). We note in §9
why proof-of-work does not address the Sybil problem itself.

**Address-space scarcity as identity cost.** Transpeer is IPv4-only by
design; the protocol document states that IPv4 scarcity provides natural
Sybil resistance. Our results qualify that: scarcity of *addresses* is not
the operative cost, scarcity of *addresses in distinct prefixes* is, and
only under a policy that measures the latter.

---

## 3. The transpeer/1 protocol

Specification in `PROTOCOL.md`; reference implementation in `transpeer/`.
Constants below are from `transpeer/config.py` and `transpeer/peerstore.py`
at commit `23d54d9` unless stated.

### 3.1 Design goal

A node that runs one or more peer-to-peer daemons (Monero, Wownero, Aeon,
or any network with a plugin) also runs a *transpeer*: a small HTTP
service that publishes the daemon's live peers and collects other
transpeers' publications. Any node that finds one transpeer, by any means,
can then obtain bootstrap peers for every participating network. The
intent is that a brute-force scan of IPv4 space, which is hopeless for one
network alone, becomes practical when every participating network's
transpeers are all valid hits.

### 3.2 Transport and identity

- TCP port 7337, HTTP/1.1, JSON bodies. IPv4 only; the specification
  cites IPv4 scarcity as the Sybil cost (revisited in §9).
- A transpeer's identity is its IPv4 address. A random `node_id` is
  generated per process start and serves only to let a scanner recognise
  itself and to bind handshake puzzles; it carries no trust.
- Per-source rate limit of 60 requests per 60 seconds, answered with 429.

### 3.3 Endpoints

**`GET /transpeer`** — discovery handshake, always free of proof-of-work.
Returns `protocol` (`"transpeer/1"`), `node_id`, `networks` served,
`peer_counts` per network, `uptime`, the entry-proof `difficulty` the
node requires, and the current `handshake_effort`. Any request to this
endpoint records the requester as a *candidate* transpeer (§3.5).

**`GET /peers/{network}`** — verified peer entries for one network. Each
entry is `{addr, port, last_seen, sources, proof}` where `proof` is
`{nonce, effort, solution, timestamp_bucket}` (§3.4). `sources` is the
number of transpeers the *sender* says reported the entry. Requires a
valid handshake proof when the node's load tracker has raised
`handshake_effort` above zero (§6.3).

**`GET /transpeers`** — a sample of up to 50 known transpeers,
`{addr, port, networks, last_seen}`, weighted toward recently seen ones
and excluding the requester. Same handshake requirement.

### 3.4 Entry proof-of-work

Every published peer entry carries an EquiX proof. The challenge binds the
entry to a six-hour window:

    timestamp_bucket = unix_time // 21600
    challenge = blake2b(network ":" addr ":" port ":" timestamp_bucket, 32 bytes)

The solver draws a 16-byte nonce (8-byte counter, 8 random bytes), runs
`equix_solve(challenge || nonce)`, and accepts a solution when
`blake2b(challenge || nonce || solution, 4 bytes)` as a little-endian
integer times `effort` does not exceed 2^32 − 1, incrementing the counter
otherwise. Verification reconstructs the challenge, checks the bucket is
current or previous (12-hour validity), calls `equix_verify`, and rechecks
the difficulty product. The specification quotes verification at about
50 µs; solving scales with `effort`. Default `effort` is 100. The
simulations replace solving with a sleep of the estimated duration.

Because the proof binds `(network, addr, port)`, a valid entry can be
relayed by any transpeer without re-solving, and a forged entry costs a
solve per fake. The proof does not bind the *publisher*, which is why it
limits spam but not identity (§9.4).

### 3.5 Discovery paths

Three paths feed a node's transpeer store; the distinction matters in §5.

- **Scan.** Random non-reserved IPv4 addresses (RFC 1918, loopback,
  link-local, multicast and documentation ranges skipped), 500 concurrent
  probes per 10-second batch with a 2-second timeout. A port-7337 TCP
  connect followed by `GET /transpeer` with the right `protocol` string
  is a transpeer. A `--scan-range` CIDR restricts the space; simulations
  use it.
- **Candidate** ("implicit self-announcement"). Every address that
  contacts `/transpeer` is queued; every 30 seconds the queue is probed
  and responders are admitted. Connecting to the overlay is registering
  with it.
- **Gossip.** Entries from `/transpeers` responses, admitted with the
  `gossiped` flag.

### 3.6 Node loops

The node runs six concurrent loops. *Extract* (every 60 s) reads the
local daemons' peer lists via each network plugin, solves an entry proof
per peer, and stores them as verified. *Scan* (every 10 s) runs one batch.
*Query* (every 300 s) selects 20 known transpeers, oldest-queried first,
and for each fetches `/transpeer`, `/peers/{network}` for every network
it serves, and `/transpeers`, merging the results. *Verify* (every 300 s)
probes stored peers. *Prune* (hourly) drops stale entries. *Candidate*
(every 30 s) probes the self-announcement queue.

### 3.7 Peer lifecycle and verification

Received → proof verified → probed → verified → re-probed → pruned. A
probe is a TCP connection to the peer's daemon port, with a
protocol-level handshake (magic bytes) for networks the node runs and a
bare port check otherwise. Only verified peers are served on
`/peers/{network}`; a never-verified peer that fails a probe is removed
and placed on a 30-minute cooldown, a previously verified one loses a
source count and its verified flag. Peers unseen for seven days and
transpeers uncontacted for three are pruned.

### 3.8 Defense layers present at the start of the study

| layer | rule | constant |
|-------|------|----------|
| per-source acceptance cap | new entries accepted from one transpeer | 50, +50 per 10 verifications at ≥ 80 % alive, reset below |
| subnet limit | transpeers per `/16`, gossiped entries only | 3 |
| store cap | transpeers kept, oldest-seen evicted when full | 500 |
| gossip sample | transpeers returned per `/transpeers` | 50 |
| query batch | transpeers queried per cycle | 20 |
| per-network peer cap | peer entries stored per network | 2000 |
| dead cooldown | before a failed never-verified peer is re-accepted | 1800 s |
| rate limit | requests per source | 60 / 60 s |
| entry proof | EquiX effort per published peer | 100 |
| handshake proof | adaptive EquiX effort on query endpoints | 0 dormant, up to 1000 |

### 3.9 Network plugins

A plugin names the network, its default P2P and RPC ports, how to extract
the daemon's peer list (Monero-family RPC by default; a bash script
dumping any daemon's list is the stated portability path), and how to
handshake with a peer for verification. Shipped plugins: `monero`
(18080/18081), `wownero` (34567/34568), `aeon` (11180/11181), and a
`generic` port-only plugin. Simulations use ten synthetic networks
`p2pa`..`p2pj` on ports 10000 onward via `--static-peers`.

### 3.10 Security assumptions as stated by the specification

Sybil resistance from IPv4 scarcity; spam resistance from entry
proof-of-work; no trust required because every node verifies
independently; automatic pruning. §5 and §9 examine the first of these.

---

## 4. Threat model

The adversary controls `A` responsive IPv4 addresses distributed over `S`
network prefixes, runs a transpeer on each, and may:

- answer scans and gossip like an honest transpeer;
- self-announce to honest transpeers on a schedule, exploiting the
  candidate path;
- serve arbitrary peer entries for any network, paying EquiX per entry;
- in the *coordinated* variant, serve the same fake peer set from every
  address, so each fake accumulates one report per adversary prefix.

The adversary does not run reachable daemons behind the fake entries; an
adversary who does is performing a daemon-level eclipse with real
infrastructure, which a discovery layer cannot distinguish from honest
service (§9.4).

The victim is a *fresh* honest node that joins late, knows two seed peers
for its own network, and runs for 15 simulated minutes. We measure the
adversary's share of (i) the victim's transpeer store, (ii) the queries the
victim issues, (iii) the peer entries in the victim's store, and (iv) the
first 20 peers the victim would hand its daemon.

The honest population is `H = 50` transpeers, one per prefix.

---

## 5. Why the baseline policy loses on count

Found by reading `transpeer/peerstore.py` and `transpeer/scanner.py` at
commit `23d54d9`, and confirmed by unit tests that pin the behaviour
(`tests/test_bucketed.py`).

1. **The `/16` cap covers one path of three.** It is checked only for
   gossiped entries, on the stated grounds that random scanning is
   inherently diverse. The candidate path performs no check at all
   (`scanner.py:152`), so any address that sends one request is admitted.
   An attacker with 500 addresses in one prefix can enter every honest
   store by sending one request each.
2. **Eviction is by recency.** The store holds 500; when full, the least
   recently seen entry is dropped. An attacker that re-announces on a loop
   always looks freshest, so honest entries are the ones evicted. This is
   what turns a majority into a total eclipse: at 1500 attackers the fresh
   node had lost half its honest transpeers (§8.4).
3. **Query rotation carries no diversity.** Each cycle queries the 20
   least recently queried entries, so the attacker's share of queries
   equals their share of the store.

A fourth finding concerns the simulations rather than the protocol: every
prior simulation had placed all hosts in a single `/16`, because the
address allocator only varied the second octet past host 65536. The
subnet limit had never been exercised.

---

## 6. Defenses

### 6.1 Bucketed selection (`--bucketed`)

A bucket is an address's `/N` prefix, `N = 16` in production and a node
parameter (`--subnet-prefix`) so simulations can use `/24`.

- **Admission**: at most `c = 3` transpeers per bucket on every path.
- **Eviction**: when full, drop the least recently seen member of the most
  populated bucket, never the newcomer's own bucket while another is tied
  for fullest; if the newcomer's bucket is the unique fullest, refuse the
  newcomer. A flood from one prefix can only displace itself.
- **Query selection**: visit buckets in random order taking the oldest
  queried member of each, wrapping until the batch of 20 is full.
- **Gossip selection**: pick a bucket uniformly, then a recent member.

### 6.2 Voucher counting (`--vouchers`)

A *voucher* for a peer is a transpeer that reported it.

- The per-source acceptance cap and verification trust are keyed by the
  source's bucket, so every attacker transpeer in one prefix shares one
  50-entry budget.
- A peer's source count is the number of distinct buckets *observed by
  this node* to report it. The `sources` value on the wire is ignored.
- `get_peers` returns entries most-corroborated first, so what the daemon
  receives is what the most independent prefixes agree on.

### 6.3 Adaptive handshake proof-of-work (prior work in this codebase)

Query endpoints require an EquiX handshake puzzle whose difficulty rises
with aggregate request volume and decays when load subsides, valid for a
one-hour bucket per client. Measured in §8.2. It addresses request floods,
not Sybil identity, and is present in every experiment below.

### 6.4 Protected tried table (`--tried-table`)

A transpeer that has answered this node's queries at least twice is
*tried*. Tried entries are excluded from eviction while any untried entry
exists; if every entry is tried, eviction falls back to the policy's
normal rule. Admission caps still apply to tried buckets, so the table
cannot be used to hold more than the cap. The threshold of two answers is
one more than a single successful probe, so an attacker cannot become
tried merely by being scanned. The table is meant for the established
node under a later flood; the bootstrap window, where nothing is tried
yet, is unaffected by design.

### 6.5 A fix found along the way

The peer-extraction loop re-solved EquiX for every locally published peer
every 60 seconds; proofs are valid for a 6-hour bucket. Commit `82070b2`
caches proofs per bucket. In production this was one solve per peer per
minute of wasted CPU. In simulation each solve is a blocking sleep, so
honest nodes in experiments before §8.7 were unresponsive for most of each
minute. This is recorded as a threat to validity in §10.

---

## 7. Method

**Simulator.** Shadow 3.2.0 (`v3.2.0-0-gdb81738`), one Python 3.12.14
process per simulated host running the real transpeer code, 60 worker
threads, `model_unblocked_syscall_latency` on. EquiX is replaced by a
sleep of the estimated solve time (`--sim-pow`) so Shadow can advance
virtual time; verification of proofs is a marker check. Peer verification
is disabled (`--no-verify`) because simulated peers have no daemon behind
them. SQLite is disabled (`--in-memory`).

**Machine.** 64-thread AMD Threadripper-class host, 251 GB RAM, 128 GB
Optane swap. Ubuntu 20.04, kernel 5.4.

**Address layout.** Scan range `11.0.0.0/16`; buckets are `/24`s, so the
range holds 256 buckets. Honest transpeers occupy buckets `0..H-1`, one
each; the fresh node bucket `H`; attackers buckets `H+1` onward, dealt
round-robin over `S` buckets. A `/24` holds 254 hosts, so `S` is raised to
the minimum that fits `A` where necessary and the actual value is
recorded. `S = "spread"` means `min(A, 200)`.

**Honest peer model** (from §8.7 on). Each of ten networks has a
population of 200 daemon peers at `12.x.x.x`, outside the scan range, with
nothing listening. Each honest transpeer serves 16 of them per network it
runs, sampled with weight `1/(rank+1)^0.7`. Sixty percent of honest nodes
run the fresh node's network. Before §8.7, each honest node served four
other honest transpeers' addresses as its peers, which pinned honest
voucher depth at four; see §8.6 and §10.

**Attacker model.** Each attacker transpeer answers all three endpoints,
serves 100 fake entries with valid simulated proofs for one network
(random per attacker, or the fresh node's network when coordinated),
begins serving at t = 3 s while proofs are still being generated, and
self-announces to every honest transpeer every 300 s. Coordinated
attackers share a seed for the fake set.

**Timeline.** Honest and attacker hosts start at t = 3 s; the fresh node at
t = 300 s; stop at t = 1200 s. The fresh node queries every 300 s, so it
completes three query cycles of 20.

**Metrics** are parsed from the fresh node's log. A `STORE_SNAPSHOT` line
every 60 s carries the transpeer store, per-source peer counts, a voucher
histogram, and the source and voucher depth of each of the first 20 peers
`get_peers` would return for the fresh node's network. Attacker and
honest are classified by bucket index.

**Seeds and variance.** The generator is seeded (42), so the honest
layout and attacker placement are identical across cells. The nodes' own
random choices (scan order, node identifiers, gossip samples) are not
seeded, so the fresh node's observations vary between cells of equal
configuration. Each cell was run once. See §10.

**Runtime.** Cells of 101 to 1551 hosts took 60 to 315 s wall-clock each.
The 30-cell grid of §8.4 took 40 minutes. Scale limits are in §8.1.

---

## 8. Results

### 8.1 Scale baseline (`sim/tests/scale_baseline/results.txt`)

All-honest hosts, 15 min simulated.

| hosts | wall-clock | run memory | MB/host |
|------:|-----------:|-----------:|--------:|
| 700  | 7.3 min  | 23 GB  | 33 |
| 1500 | 20.3 min | 60 GB  | 40 |
| 3000 | 43.1 min | 156 GB | 52 |

Memory per host grows with host count because each node's store scales
with the transpeers it knows. Wall-clock scaled between linear and
`N^1.35`. The practical ceiling on this machine is near 4000 hosts without
swap. The eclipse experiments need at most 1551.

### 8.2 Adaptive handshake proof-of-work (`sim/tests/handshake_pow/results.txt`, prior phase)

One victim, 20 honest, flooders at 0.8 req/s each, below the per-IP rate
limit. Peak difficulty and flooder outcomes over 15 simulated minutes:

| flooders | peak difficulty | 200 | 402 | solves | attacker CPU |
|---------:|----------------:|----:|----:|-------:|-------------:|
| 0   | 0    | 0      | 0      | 0   | 0 |
| 30  | 462  | 1,137  | 6,139  | 0   | 0 |
| 60  | 935  | 844    | 14,153 | 0   | 0 |
| 100 | 1000 | 1,412  | 22,941 | 0   | 0 |
| 100, solving | 1000 | 23,286 | 100 | 100 | 420 s |

Load keyed on aggregate volume catches distributed floods; non-solving
attackers are refused 94 percent of the time; solving attackers pay about
4 s of CPU per hour per source.

### 8.3 Attacker ratio (`sim/tests/attacker_ratio/results.txt`, prior phase)

600 hosts, 10/25/50 percent attackers injecting fake peers, all in one
`/16` (§5, finding 4). The honest observer discovered attackers at
population ratio but queried none within 15 minutes, because attackers
began serving only after 410 s of proof generation and rotation had not
reached them. This result should be read as a statement about the
attacker's start-up delay, not about the policy; §8.4 removes the delay.

### 8.4 Eclipse grid (`sim/tests/bootstrap_eclipse/results.txt`)

Independent attackers, 30 cells, current policy → bucketed. Attacker share
of the fresh node's transpeer store, percent:

| attackers | concentrated (S) | S = 25 | S = 100 | spread (S) |
|----------:|:----------------:|:------:|:-------:|:----------:|
| 50   | 33 → 6 (1)  | 50 → 50 | —       | 50 → 50 (50)  |
| 150  | 52 → 6 (1)  | 67 → 60 | 75 → 75 | 75 → 75 (150) |
| 500  | 83 → 11 (2) | 84 → 60 | 88 → 85 | 88 → 87 (200) |
| 1500 | 96 → 27 (6) | 95 → 60 | 95 → 87 | 95 → 91 (200) |

Attacker share of queries issued:

| attackers | concentrated | S = 25 | S = 100 | spread |
|----------:|:------------:|:------:|:-------:|:------:|
| 50   | 20 → 8  | 39 → 21 | —       | 42 → 37 |
| 150  | 45 → 12 | 63 → 55 | 63 → 68 | 65 → 63 |
| 500  | 80 → 18 | 75 → 53 | 78 → 85 | 75 → 85 |
| 1500 | 90 → 20 | 90 → 48 | 88 → 93 | 85 → 80 |

Honest transpeers retained by the fresh node, of 50: current policy at
1500 attackers, 22 to 25; bucketed, 46 to 50 in every cell.

Under bucketing the store share equals `min(A, 3S) / (min(A, 3S) + 50)`
in every cell to within a point: 5.7 at S = 1, 10.7 at S = 2, 26.5 at
S = 6, 60 at S = 25, whatever `A`.

### 8.5 Voucher counting, independent attacker (`results_vouchers.txt`)

Concentrated column, attacker share of peer entries, current → bucketed →
bucketed with vouchers: 85 → 69 → 43 at S = 1; 94 → 69 → 42 at S = 1;
97 → 81 → 58 at S = 2; 99 → 88 → 81 at S = 6. Under vouchers the attacker
holds exactly 50 entries per prefix. The daemon's top 20 read 0 percent
attacker in every cell, but see §8.6 for why that number was not yet a
ranking result.

### 8.6 Coordinated attacker, four-peer honest model (`results_coordinated.txt`)

All attackers target the fresh node's network with one shared fake set.
Daemon top 20, attacker share, current → bucketed → vouchers: 65 → 65 → 65
at S = 1 (two cells), 70 → 65 → 75 at S = 2, 70 → 65 → 100 at S = 6.

Two corrections were established here. The 65 percent common to every
one-prefix cell was honest supply: exactly seven honest peers existed for
the fresh node's network under the four-peer model, and a top-20 view
fills the rest with fakes under any ranking. And the 0 percent of §8.5 was
mostly because independent attackers pick random target networks, so few
of their fakes were on the fresh node's network at all. Ranking was
holding, but it could not be seen with seven honest candidates.

### 8.7 Coordinated attacker, population honest model (`results_coordinated_v2.txt`)

Forty cells. With the honest model of §7, 26 honest transpeers serve the
fresh node's network, 153 distinct peers exist, and the 20 most-listed
peers appear in 5 to 17 honest lists. Bucketed with vouchers:

| attacker prefixes | top-20 attacker share | deepest honest voucher count | shallowest attacker |
|------------------:|:---------------------:|:----------------------------:|:-------------------:|
| 1 (50, 150 attackers) | 0 %        | 10 to 13 | none in top 20 |
| 2 (500 attackers)     | 0 %        | 10       | none in top 20 |
| 6 (1500 attackers)    | 90 %       | 7        | 6  |
| 10                    | 80 to 100 % | 9 to 12 | 6 to 10 |
| 25 and up             | 100 %      | none     | 12 to 36 |

Transpeer store share again followed `min(A, 3S)/(min(A, 3S)+50)`. Under
the current policy at 1500 attackers the fresh node lost 18 to 22 of its
50 honest transpeers to eviction. The current policy's daemon view is
arrival order, not a ranking: it read 0 to 10 percent only because the
seeds and first honest query fill the first 20 slots.

### 8.8 Crossover fill (`results_crossover.txt`)

500 attackers, prefixes 3 to 8, bucketed with vouchers, coordinated:

| prefixes | top-20 attacker share | deepest honest | shallowest attacker |
|---------:|:---------------------:|:--------------:|:-------------------:|
| 3 | 0 %  | 6  | none |
| 4 | 55 % | 9  | 4 |
| 5 | 60 % | 9  | 5 |
| 6 | 65 % | 10 | 6 |
| 7 | 85 % | 10 | 7 |
| 8 | 90 % | 9  | 8 |

The attacker enters at four prefixes. The step is sharp because every fake
ties at exactly `S` vouchers and many honest peers in the top 20 had been
observed only three or four times. The share at `S` is, to first
approximation, the fraction of the honest top 20 whose observed depth is
at most `S`.

---

## 9. Analysis

### 9.1 Store share is a closed form

Under bucketed admission with cap `c`, `H` honest transpeers in distinct
buckets, and an attacker with `A` addresses in `S` buckets, the attacker's
share of the victim's transpeer store is

    min(A, c·S) / (min(A, c·S) + H)

matched to within a point in 24 of 24 bucketed cells across §8.4 and
§8.7. The attacker's IP count is irrelevant once each of their buckets is
full. With `c = 3` the attacker reaches parity at `S = H/3`; with `c = 1`
at `S = H`.

### 9.2 What reaches the daemon depends on voucher depth

Under voucher counting, a coordinated attacker's fakes each carry `S`
vouchers. A real peer carries as many vouchers as the distinct honest
buckets the victim has *heard report it*. The attacker displaces a real
peer when `S` exceeds that depth. In our layout the peers at the bottom of
the daemon's top 20 had depth 3 to 4 after 15 minutes, so the attacker
enters at `S = 4` and holds 90 percent at `S = 8`.

Depth has two multipliers the attacker does not control. It grows with
the number of honest transpeers on the network: the 20th-deepest peer sat
at roughly a fifth of the 26 honest transpeers on the network, so the
same skew at 1000 honest transpeers puts the crossover near 200 prefixes.
*(extrapolated)* And it grows with the victim's uptime: the fresh node had
observed 5 to 6 of a list depth of 17 for the top peers, because it had
queried each honest transpeer about once. *(extrapolated; see §11)*

### 9.3 Where the defenses stop

At 100 or 200 attacker prefixes against 50 honest, both policies give the
attacker 75 to 95 percent of the store and 100 percent of the daemon's
list. An adversary with more diverse address space than the honest
population is, for discovery purposes, the network. Bucketing by
autonomous system rather than by prefix raises the price of "diverse" but
does not remove the bound. What acts in that regime is outside discovery:
trust anchors, the daemon's own peer list as a cross-check, and
verification, which is disabled in these simulations and would mark
unreachable fakes dead within minutes.

### 9.4 What does not help

Proof-of-work on transpeer identity: compute is cheaper than addresses and
amortizes across victims. Liveness verification alone: an adversary
running real nodes passes it, and at that point the attack is a
daemon-level eclipse. Per-address rate limits: the adversary has thousands
of addresses by construction.

---

## 10. Threats to validity

- **Single run per cell.** The honest layout is seeded; the nodes' scan
  and query order are not. Observed honest depth varied from 6 to 13
  across equal-configuration cells, and the six-prefix cell read 65
  percent at 500 attackers and 90 at 1500. Store-share results are
  deterministic to within a point; daemon-view results near the
  crossover are not. Several seeds per cell are needed before quoting a
  crossover tighter than "four".
- **No peer verification.** Fakes are never probed. In production the
  verifier removes unreachable entries and contracts the source's
  budget; our numbers are therefore an upper bound on the attacker's
  peer-level reach, and a fair measure of transpeer-level reach.
- **Simulated proof-of-work.** Solve time is a sleep of the estimated
  duration; verification is a marker check.
- **Honest-node responsiveness before §8.7.** Until commit `82070b2`,
  honest nodes re-solved proofs every cycle and, in simulation, were
  blocked in sleep for most of each minute. Rows from §8.4 to §8.6 have
  honest nodes less responsive than they should have been. Store-share
  formulas still matched, but those rows should not be compared cell for
  cell with §8.7 and later.
- **Honest peer model.** Population 200, 16 per node, exponent 0.7, 60
  percent on the primary network, all chosen by judgement. The depth
  profile they produce (5 to 17 for the top 20) is plausible but not
  calibrated against a real network. The pre-§8.7 model pinned depth at
  four and produced the artifacts recorded in §8.6.
- **Prefix length.** `/24` stands in for `/16`. Nothing in the mechanism
  depends on the length, but density and scan dynamics differ.
- **Attacker cost model.** We count prefixes, not money. Renting `S`
  distinct `/16`s is the real cost and we have not priced it.
- **Fresh-node window.** Fifteen simulated minutes and three query
  cycles. Observed depth is far below list depth at that point; longer
  windows favour the defender (§9.2) and have not been run.
- **Handshake proof-of-work interaction.** Present in every run but not
  measured in the eclipse experiments. Attackers self-announce on the
  free endpoint, so it should not bind; unverified.
- **Corrections during the study.** Two conclusions were reversed after
  closer measurement (§8.6). They are kept in the record deliberately.

---

## 11. Future work

1. Several seeds per cell around the crossover, and a longer fresh-node
   window to measure how observed depth approaches list depth.
2. 200 honest transpeers, to test the depth-scales-with-population
   extrapolation. Needs a wider scan range or lower attacker bucket
   ceiling; 200 honest buckets plus attackers exceed the 256 `/24`s in a
   `/16`.
3. A protected "tried" table for transpeers that have answered over
   several cycles, so even a prefix-rich attacker cannot displace them.
4. Autonomous-system buckets via an asmap-style file.
5. Enable verification at scale, which requires lightweight fake daemons
   (see `TODO/bash_daemon_for_scale.md`), to measure the peer-level upper
   bound against the real behaviour.
6. Price the attack: `/16` rental cost by provider, so the cost statement
   in §9.2 is in currency.
7. Cross-source consistency checks (chain height and tip via the daemon
   handshake) as a defense in the regime of §9.3.

---

## 12. Reproducibility

Repository: `github.com/Fountain5405/transpeer`. Two branches at the time
of writing.

| commit | branch | content |
|--------|--------|---------|
| `23d54d9` | machine-migration-bootstrap | machine-independent sim infrastructure |
| `76da518` | machine-migration-bootstrap | scale_baseline (§8.1) |
| `de02f26` | bootstrap-eclipse | `--subnet-prefix`, `--bucketed`, snapshot logging, attacker self-announce, experiment |
| `b769837` | bootstrap-eclipse | eclipse grid results (§8.4) |
| `26096f0` | bootstrap-eclipse | `--vouchers` and rerun (§8.5) |
| `564b91d` | bootstrap-eclipse | coordinated attacker (§8.6) |
| `82070b2` | bootstrap-eclipse | honest peer model, proof cache, depth metric (§8.7) |
| `f00175e` | bootstrap-eclipse | crossover fill (§8.8) |
| `2b16d6a`, `bcd5169` | master (earlier) | adaptive handshake PoW and its experiment (§8.2) |
| `f98736a` | master (earlier) | attacker_ratio (§8.3) |

Each experiment folder under `sim/tests/` holds `gen_config.py`,
`run_experiment.sh`, committed `configs/*.yaml`, a `results*.txt` CSV with
a header recording machine, seed and simulated time, and a `README.md`
with the interpretation at the time. Runs:

    source sim/simenv.sh                       # machine-specific paths
    sim/tests/scale_baseline/run_experiment.sh
    sim/tests/bootstrap_eclipse/run_experiment.sh                          # §8.4
    RESULTS_FILE=results_vouchers.txt SUBNET_LEVELS=concentrated \
      POLICIES="current bucketed bucketed_vouchers" \
      sim/tests/bootstrap_eclipse/run_experiment.sh                        # §8.5
    ATTACKER_MODE=coordinated ... run_experiment.sh                        # §8.6-8.8

Unit checks: `tests/test_two_nodes.py` (24, real EquiX, default policy)
and `tests/test_bucketed.py` (25, both policies, no network).

---

## 13. Claims ledger

| # | claim | status | evidence |
|---|-------|--------|----------|
| 1 | The `/16` limit applies only to gossiped entries; scan and candidate paths bypass it | measured | code at `23d54d9`; `test_bucketed.py` admission checks |
| 2 | Recency eviction lets a re-announcing attacker displace honest entries | measured | §8.4, §8.7 honest-retained counts |
| 3 | Under the current policy attacker store share tracks IP count | measured | §8.4 |
| 4 | Under bucketing attacker store share is `min(A,3S)/(min(A,3S)+H)` | measured, 24/24 cells | §8.4, §8.7 |
| 5 | Bucketing retains honest transpeers at every attacker size tested | measured | §8.4, §8.7 |
| 6 | Neither policy helps at `S >= 2H` | measured | §8.4, §8.7 spread cells |
| 7 | Voucher counting caps attacker peer entries at 50 per prefix | measured | §8.5 |
| 8 | Under vouchers a coordinated attacker is absent from the daemon's top 20 at `S <= 3` and enters at `S = 4` | measured, one seed | §8.8 |
| 9 | Crossover equals observed depth of the honest peers at the bottom of the top 20 | measured, one layout | §8.7, §8.8 depth columns |
| 10 | Depth scales with honest transpeers on the network | extrapolated | §9.2 |
| 11 | Depth grows with victim uptime | extrapolated | §9.2 |
| 12 | Query share under bucketing lags the store formula early and converges | hypothesis | §8.4 query table; not rerun longer |
| 13 | Verification would remove unreachable fakes within minutes | hypothesis | not simulated |
| 14 | ASN bucketing raises attack cost without changing the bound | hypothesis | not implemented |

---

## Appendix A. Record of corrections

- §8.5 first reported a clean daemon view as a ranking win. §8.6 showed it
  was mostly attacker network choice. Corrected in commit `564b91d`.
- §8.6 first read the 65 percent floor as ranking failure. It was honest
  supply under the four-peer model. Corrected in the same commit.
- The runner's memory guard first projected 40 MB per host from the
  previous machine; §8.1 measured 33 to 52. The 5000-host baseline was
  aborted by the guard and has not been rerun.
