# Bucketed selection and voucher counting against Sybil eclipse of a cross-network peer-discovery overlay

**Status**: working draft, living document. Every number in this file traces
to a results file and a commit listed in §13. Claims are tagged in the
ledger in §14 as *measured*, *extrapolated* or *hypothesis*. Citations
marked `[verify]` are from memory and must be checked before submission.

Branch `bootstrap-eclipse` at the time of writing; see §13 for commits.

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

Four paths feed a node's transpeer store; the distinction matters in §5.

- **Scan.** Random IPv4 addresses, skipping reserved ranges (RFC 1918,
  loopback, link-local, multicast, documentation) and, since the
  etiquette revision (§3.7), a built-in list of sensitively monitored
  netblocks and any operator-listed prefix. A port-7337 TCP connect
  followed by `GET /transpeer` with the right `protocol` string is a
  transpeer. A `--scan-range` CIDR restricts the space; simulations use
  it, together with `--scan-legacy` (500 concurrent probes per 10-second
  batch, 2-second timeout, no backoff), the profile every experiment in
  §8 ran under.
- **Candidate** ("implicit self-announcement"). Every address that
  contacts `/transpeer` is queued; every 30 seconds the queue is probed
  and responders are admitted. Connecting to the overlay is registering
  with it.
- **Gossip.** Entries from `/transpeers` responses, admitted with the
  `gossiped` flag.
- **Daemon peers.** Every peer the local daemon is connected to is queued
  for a transpeer-port probe, at most once per six hours per address
  (etiquette revision; off under `--scan-legacy`). A host already in a
  P2P relationship with us may run a transpeer beside its daemon, and
  probing it is not blind scanning. This is the path a node that has
  stopped scanning keeps discovering through.

### 3.6 Node loops

The node runs six concurrent loops. *Extract* (every 60 s) reads the
local daemons' peer lists via each network plugin, solves an entry proof
per peer, and stores them as verified. *Scan* (every 10 s) runs one batch,
fired at once under the legacy profile and spread across the interval
under the production profile (§3.7).
*Query* (every 300 s) selects 20 known transpeers, oldest-queried first,
and for each fetches `/transpeer`, `/peers/{network}` for every network
it serves, and `/transpeers`, merging the results. *Verify* (every 300 s)
probes stored peers. *Prune* (hourly) drops stale entries. *Candidate*
(every 30 s) probes the self-announcement queue.

### 3.7 Scanning etiquette

Blind scanning is the behaviour that gets an address reported to abuse
databases, listed by community blocklists and cut off under hosting
providers' acceptable-use policies, and the original profile (50
unsolicited connects per second per node, indefinitely) would have earned
that. The shot in the dark is for a node that knows nobody, so the
production profile treats scanning as a bootstrap mechanism only:

- **Cold only.** A node scans at `--scan-rate` (default 4 per second,
  probes spread across the interval with jitter) until
  `--scan-target-known` transpeers (default 3) have answered a query,
  then stops. If the live count later falls below the target, scanning
  resumes. Discovery continues through gossip, candidates and daemon
  peers.
- **Exclusions.** Reserved ranges and the US DoD `/8`s are never
  blind-scanned; `--scan-exclude` adds an operator file. An explicit
  `--scan-range` is not filtered.
- **Identification.** Every request carries a User-Agent naming the
  protocol, the project URL and the operator's opt-out contact; `GET /`
  on the transpeer port explains the probe to whoever looks up the
  address that touched them.
- **No-scan mode.** `--no-scan` for residential lines and strict hosts.

Stopping the scan after first contact has a security cost that the
experiments in §8 did not measure: the first transpeer a cold node finds
becomes, until gossip and daemon peers widen the view, its only source of
further transpeers. Bucketing caps what one gossip source can fill and
the daemon-peer path is outside the attacker's control, but the window
between first contact and a diversified store is a target for a
first-contact eclipse and is listed in §11.

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
every 60 seconds; proofs are valid for a 6-hour bucket. Commit `04653c4`
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
issues two query batches of 20 within the window; a third begins at the
stop time. (An earlier draft said three; see Appendix A.)

**Metrics** are parsed from the fresh node's log. A `STORE_SNAPSHOT` line
every 60 s carries the transpeer store, per-source peer counts, a voucher
histogram, and the source and voucher depth of each of the first 20 peers
`get_peers` would return for the fresh node's network. Attacker and
honest are classified by bucket index.

**Seeds and variance.** From §8.9 on, one seed drives both the generator
(honest layout, attacker placement) and Shadow's `general.seed`, from
which every simulated host's randomness derives. Two runs of one config
are therefore identical, provided the worker count is also unchanged
(§10), and a replica is a different seed. Before §8.9
the Shadow seed was left at its default, so cells of equal configuration
would have been identical and the variance reported in §8.8 came from
configs that differed in host count. §8.9 has five seeds per cell; every
other experiment has one. See §10.

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
at most `S`. §8.9 replicates this with five seeds.

### 8.9 Crossover replicas (`results_crossover_seeds.txt`)

Five seeds per cell, each seeding both the generator and Shadow. 500
attackers, 15-minute window, bucketed with vouchers, coordinated.

| prefixes | top-20 attacker share, mean (min, max) | store share across seeds |
|---------:|:--------------------------------------:|:------------------------:|
| 3 | 2 (0, 10)   | 15.0 to 15.3 |
| 4 | 26 (5, 45)  | 19.0 to 19.4 |
| 5 | 61 (45, 75) | 22.7 to 23.1 |
| 6 | 76 (60, 85) | 26.1 to 26.5 |
| 8 | 88 (85, 95) | 32.0 to 32.4 |

Store share is deterministic to within half a point across seeds, as the
closed form predicts. The daemon-view share near the crossover varies by
about ±20 points between seeds. The attacker enters at four prefixes in
five of five replicas and holds a majority from five. The single-seed 55
percent at four prefixes in §8.8 was at the high end of its range.

### 8.10 Depth against uptime (`results_uptime_*_seeds.txt`)

Five seeds, 500 attackers, prefixes 4 and 6, fresh node started at 300 s
and measured at windows of 15, 30, 60 and 120 minutes. Mean over seeds
with the range in brackets; the count in parentheses is the number of
seeds in which the attacker held at least one of the 20 slots. The
single-seed originals are in `results_uptime_*.txt`.

| window | queries issued | S = 4 top-20 share | S = 6 top-20 share | deepest honest, S = 4 |
|-------:|---------------:|:------------------:|:------------------:|:---------------------:|
| 15 min  | 40  | 27 % [0–45] (4/5) | 68 % [65–75] (5/5) | 12.6 [10–14] |
| 30 min  | 100 | 0 % (0/5)         | 33 % [20–45] (5/5) | 18.8 [15–22] |
| 60 min  | 220 | 0 % (0/5)         | 21 % [0–35] (4/5)  | 21.0 [17–24] |
| 120 min | 460 | 0 % (0/5)         | 20 % [0–35] (4/5)  | 21.0 [17–24] |

At four prefixes the attacker is out of the daemon's list by the
30-minute mark in every seed. At six it persists: four of five seeds
still give it 15 to 35 percent of the list after two hours, each fake
carrying exactly six vouchers, one per attacker bucket. The fifth seed
excluded it from 60 minutes on. Persistence is decided not by the deepest
honest peer but by how many honest peers the layout puts deeper than six:
seed 2 has the shallowest layout (deepest honest 17) and gives the
attacker its largest share.

Observed honest depth is identical at 60 and 120 minutes in every seed
(23, 17, 21, 20, 24), so it reaches its layout ceiling within the hour.
Seed 1's per-minute snapshots, below, put that at minute 50.

From the 120-minute run's per-minute snapshots, at four prefixes the
attacker peaks at 15 of 20 slots in minute 10, right after the first query
batch, falls to 9 by minute 15, 4 by minute 20, and is gone from minute
25 on. At six prefixes the peak is 19 of 20 at minute 10, 11 at minute 30,
and 6 from minute 40 onward, where it stays: fourteen honest peers end up
deeper than six and the remaining six slots go to fakes. Observed honest
depth reaches its ceiling of 23, the list depth of the seed-1 layout, by
minute 50. The bootstrap window for a four-prefix attacker is minutes 10
to 25; a six-prefix attacker against 50 honest transpeers does not need a
window.

### 8.11 200 honest transpeers (`results_h200_*_seeds.txt`)

Five seeds, 200 honest transpeers of which about 120 serve the fresh
node's network, 500 attackers, prefixes 8 to 48. The fresh node knew all
200 honest transpeers by the end of even the 15-minute window in every
seed. Top-20 attacker share is the mean [range] with the number of seeds
in which the attacker held a slot; the depth columns give the deepest
honest peer (mean over seeds) and the shallowest fake in the top 20
(mean over the seeds where one is present).

| prefixes | 15 min: share | honest max / attacker min | 60 min: share | honest max / attacker min |
|---------:|:-------------:|:-------------------------:|:-------------:|:-------------------------:|
| 8  | 5 % [0–20] (2/5)    | 16 / 4  | 0 % (0/5)          | 59 / none |
| 16 | 47 % [0–75] (4/5)   | 14 / 6  | 8 % [0–30] (2/5)   | 52 / 13   |
| 24 | 79 % [65–95] (5/5)  | 14 / 9  | 36 % [10–55] (5/5) | 54 / 17   |
| 32 | 78 % [55–100] (5/5) | 11 / 9  | 58 % [15–80] (5/5) | 53 / 22   |
| 48 | 93 % [85–100] (5/5) | 9 / 11  | 81 % [70–90] (5/5) | 51 / 30   |

At 60 minutes the attacker enters the list between 16 and 24 prefixes
(two of five seeds at 16, all five at 24) and holds a majority at 32
(mean 58 percent, three of five seeds above half). Against 50 honest
(§8.9, §8.10) entry was at 4 prefixes and majority at 5. Honest
transpeers on the network rose 4.6-fold (26 to about 120); the entry
crossover rose 4- to 6-fold and the majority crossover 6.4-fold. The
single-seed run had put entry between 24 and 32 because seed 1 alone
shows 0 percent at 24 prefixes, where the five-seed mean is 36 percent
(Appendix A). The deepest honest peer rose about 2.6-fold (21 to 54 on
average, 41 to 67 across seeds), less than linearly, because a peer
cannot be reported by more transpeers than serve the network and the top
peers were already in most lists.

Two further observations hold across seeds. The attacker's observed
depth is throttled by the victim's query budget exactly as the honest
side's is: with 32 to 48 attacker prefixes the fresh node had seen 9 to
11 vouchers per fake at 15 minutes and 22 to 30 at 60. And at 15 minutes
the larger honest network already did slightly better than the small one
at the same window (honest depth 14 to 16 against 12 to 13), because
many honest transpeers report the same popular peers and the victim's 40
queries land mostly on honest transpeers.

### 8.12 Tried table against late attackers (`results_tried_late_seeds.txt`)

Five seeds. The fresh node starts at 300 s; 1500 attackers start at
1500 s, after it has completed four query batches; measured at 3000 s.
Means over seeds with ranges; tried entries are given as total (honest).

| policy | prefixes | honest retained (of 50) | tried entries (honest) | store share | top-20 share |
|--------|---------:|:-----------------------:|:----------------------:|:-----------:|:------------:|
| current                    | 6   | 40.4 [38–44] | —                   | 91.7 | 0, arrival order |
| current + tried            | 6   | 48.6 [48–49] | 40.2 [39–42] (39.8) | 90.1 | 0, arrival order |
| bucketed + vouchers        | 6   | 50 [50–50]   | —                   | 26.2 | 8 % [0–30] (2/5) |
| bucketed + vouchers + tried| 6   | 50 [50–50]   | 45.0 [44–48] (44.6) | 26.1 | 6 % [0–30] (1/5) |
| current                    | 200 | 40.4 [38–44] | —                   | 91.7 | 0, arrival order |
| current + tried            | 200 | 48.6 [48–49] | 40.2 [39–42] (39.8) | 90.1 | 0, arrival order |
| bucketed + vouchers        | 200 | 50 [50–50]   | —                   | 89.8 | 100 (5/5) |
| bucketed + vouchers + tried| 200 | 50 [50–50]   | 35.2 [32–39] (34.8) | 89.8 | 100 (5/5) |

Under the current policy an established node lost 6 to 12 of 50 honest
transpeers to 25 minutes of flood, against 18 to 28 for a fresh node
(§8.4, §8.7); the tried table kept 48 or 49 in every seed. Under
bucketing the tried table changed nothing: fullest-bucket eviction
already never touches a bucket holding a single honest entry, and all 50
were retained in every seed with or without it. A fake that answers
queries can become tried too: one reached the threshold in five of the
forty cells, never more than one per cell (the single-seed run had none).
The tried table does not act on peer ranking, so at 200 prefixes the
fakes took the daemon's list in every seed, and at six prefixes the
attacker reached the list of an established node in two of five seeds
without the table and one with it, the same persistence seen in §8.10.

### 8.13 Hand-off reserve against a corral (`results_reserve5.txt`, `results_reserve10.txt`, `results_reserve5_h200.txt`)

Five seeds. Fifty honest transpeers, 1500 coordinated attackers, a
15-minute window, prefixes from 6 to 200, with `--handoff-reserve` at
K = 5 and K = 10 against plain voucher ranking. Top-20 attacker share as
mean [range]; in parentheses, the seeds in which at least one honest peer
reached the daemon's list. "Unrepresented" is the number of reporter
buckets with no peer in the ranked head before the reserve pass, which
under a corral is the number of honest reporters the victim had heard
from.

| prefixes | vouchers only | K = 5 | K = 10 | unrepresented, K = 5 |
|---------:|:-------------:|:-----:|:------:|:--------------------:|
| 6   | 80 % [75–85] (5/5)  | 76 % [70–80] (5/5) | 76 % (5/5) | 0.0 |
| 25  | 100 % (0/5)         | 89 % [80–95] (5/5) | 89 % (5/5) | 9.8 [7–13] |
| 50  | 100 % (0/5)         | 88 % [85–90] (5/5) | 89 % [85–90] (5/5) | 8.2 [6–10] |
| 100 | 100 % (0/5)         | 92 % [85–95] (5/5) | 92 % (5/5) | 4.4 [2–7] |
| 200 (spread) | 100 % (0/5) | 94 % [90–100] (4/5) | 94 % (4/5) | 2.6 [0–5] |

Without the reserve, from 25 prefixes up, no seed put a single honest
peer in front of the daemon. With it, every seed did at 25, 50 and 100
prefixes, and four of five at 200, at one to four slots of twenty. That
is the property the reserve was built for: one honest connection is
enough for the daemon to see the real chain (§9.6). Two limits are
visible in the table. K = 10 produced rows identical to K = 5, seed by
seed, because a pick covers every bucket that vouched for it and the
honest reporters form one or two clusters, so the reserve is exhausted
after a couple of picks. And the reserve can only represent reporters
the victim has actually heard from: with 40 queries spread bucket-uniform
over 250 buckets, the victim heard from 2 to 13 honest reporters at 25
prefixes and 0 to 5 at 200, and the seed that heard none stayed at 100
percent. The bottleneck is the query budget, not the reserve size.

The cost side, measured at 200 honest transpeers, 500 attackers and a
60-minute window, where rank alone gives a small attacker little:

| prefixes | vouchers only | K = 5 |
|---------:|:-------------:|:-----:|
| 8  | 0 % (0/5 seeds with any attacker)    | 5 % [5–5] |
| 16 | 13 % [0–45]                          | 16 % [5–40] |

At 8 prefixes the attacker's eight buckets are unrepresented, its fakes
carry eight vouchers, above the two-voucher gate, and the reserve hands
its cluster exactly one slot in every seed. At 16 the reserve adds about
one slot to a share the attacker was already winning by rank in some
seeds. One slot is the reserve's floor price for any cluster of two or
more prefixes below the crossover.

### 8.14 Native vouchers against cheap and full attackers (`results_native_cheap.txt`, `results_native_full.txt`)

Five seeds. Fifty honest transpeers, 500 coordinated attackers, a
15-minute window, prefixes 6, 8 and 25. Under `--native-vouchers` a
report counts first by vouchers from transpeers whose host answered a
TCP probe on the network's daemon port. The cheap attacker announces and
serves fakes but opens no daemon port; the full attacker
(`--attacker-native`) opens one per address.

| prefixes | vouchers only | native, cheap attacker | native, full attacker |
|---------:|:-------------:|:----------------------:|:---------------------:|
| 6  | 66 % [55–85]  | 0 % (0/5) | 74 % [70–85] |
| 8  | 85 % [75–95]  | 0 % (0/5) | 83 % [60–95] |
| 25 | 100 %         | 0 % (0/5) | 100 %        |

The cheap attacker's fakes carry no native voucher and rank below every
honest peer that has one; the daemon's list was entirely honest in all
fifteen cells. The full attacker matched plain voucher ranking within
seed noise. The defense is a cost transfer and nothing more: it removes
the announce-only version of the attack and prices the other one at a
daemon per address. The simulated check is a TCP connect, which a
listener satisfies; a deployment should use the network plugin's
protocol handshake, which the verifier already supports for networks the
node runs, so that the price is a real daemon.

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

Depth has two multipliers the attacker does not control, both measured
on five seeds. It grows with the number of honest transpeers on the
network: entry moved from 4 prefixes at 26 honest transpeers on the
network to 16 to 24 at about 120, and majority from 5 to 32, a 4- to
6.4-fold rise for a 4.6-fold rise in honest count (§8.11). Extrapolating
the same ratio, a network with 1000 honest transpeers would put entry
near 150 prefixes and majority near 250; that step remains an
extrapolation. And it grows with the victim's uptime: at four prefixes
the attacker held up to 15 of 20 slots in the tenth minute and none from
the 30-minute mark in any of five seeds, and observed honest depth
reached its layout ceiling within the hour in every seed (§8.10). The
attack window is the first half hour after a node joins. Uptime does not
rescue a node from an attacker already past the crossover: at six
prefixes against 50 honest the attacker kept 15 to 35 percent of the list
after two hours in four of five seeds.

The victim's query budget throttles both sides equally (§8.11), so the
crossover in prefixes is a ratio of honest to attacker *reporting*
capacity, not of raw depth; batch size and query interval are therefore
design parameters of the defense as well as of load.

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

### 9.4 The tried table is redundant under bucketing

Protecting entries that have answered twice fixed the residual honest loss
of the current policy for an established node (40 to 49 of 50 retained)
and did nothing under bucketing, where fullest-bucket eviction already
protects any bucket holding a lone honest entry. It also does not act on
the daemon's peer ranking. We keep it as a cheap belt for deployments
that cannot adopt bucketing, and note that under bucketing with cap 3 the
case it guards against does not arise.

### 9.5 What does not help

Proof-of-work on transpeer identity: compute is cheaper than addresses and
amortizes across victims. Liveness verification alone: an adversary
running real nodes passes it, and at that point the attack is a
daemon-level eclipse. Per-address rate limits: the adversary has thousands
of addresses by construction.

### 9.6 The reserve is proportional representation; native vouchers are a cost transfer

Voucher ranking is winner-takes-all: past the crossover the attacker
holds every slot. The hand-off reserve changes the rule for the last K
slots to something like proportional representation among reporter
clusters, and the measured effect is exactly what that predicts. Under a
corral every honest reporter is unrepresented in the ranked head by
construction, so the reserve reaches honest peers in every seed where
the victim heard from any (§8.13); the attacker can dilute it only by
adding reporter buckets that vouch for nothing in the head, which costs
prefixes and buys a share, never the whole list; and below the
crossover the same symmetry hands a small attacker cluster one slot,
which the two-voucher gate keeps at one. One honest slot is enough in
principle, because a daemon that connects to one real peer syncs the
heavier chain and reorganises away from a fork; the reserve's job is to
make a total corral impossible rather than to win the list. Its reach
is bounded by the reporters the victim has queried, which is the query
budget of §9.2 again, and which the proposal of §12 removes by letting a
newcomer read every publisher's list at once.

Native vouchers do not change any crossover. They split the attacker
population in two: the announce-only attacker, whom they eliminate at
every prefix count tested, and the attacker who runs a daemon per
address, whom they leave exactly where voucher ranking left them
(§8.14). The defense is worth having because the cheap attack is the
one most likely to be tried, and because the price it sets, one real
daemon per vouching address, is the same price a corral has to pay
anyway.

---

## 10. Threats to validity

- **Seeds.** Every experiment from §8.9 on has five seeds per cell.
  Store share is deterministic to within half a point across seeds; the
  daemon-view share varies by 20 to 45 points between seeds near a
  crossover (§8.11: 10 to 55 percent at 24 prefixes), so a single cell
  says little and each crossover is a band, not a line. Experiments
  before §8.9 are one seed, and there the Shadow seed was not varied, so
  the §8.8 variance came from host-count differences rather than
  replicas.
- **Worker count.** Shadow reproduces a run exactly for a given seed
  *and* worker count (`general.parallelism`): a seed-1 rerun of the
  15-minute uptime cells at 60 workers matched the single-seed rows in
  every column, and a rerun at 30 workers matched the five-seed rows. Across worker counts the
  layout-determined columns (store total and share, honest known,
  buckets, queries issued) are identical but the timing-dependent ones
  (query and peer attacker share, daemon view, observed depth) shift by a
  few points, because event ordering between hosts changes. The five-seed
  files were run at 30 workers and their seed-1 rows therefore differ
  from the single-seed files, run at 60. Results headers record the
  worker count; a replica is a different seed at the same worker count.
- **Reserve and native windows.** §8.13 at 50 honest is a 15-minute
  window, where the victim has heard from few reporters; longer windows
  would raise the number of unrepresented honest buckets and the honest
  slots with them, and were not run. The 200-honest cost cells are at 60
  minutes. §8.14 is 15 minutes at three prefix counts.
- **No peer verification.** Fakes are never probed. In production the
  verifier removes unreachable entries and contracts the source's
  budget; our numbers are therefore an upper bound on the attacker's
  peer-level reach, and a fair measure of transpeer-level reach.
- **Simulated proof-of-work.** Solve time is a sleep of the estimated
  duration; verification is a marker check.
- **Honest-node responsiveness before §8.7.** Until commit `04653c4`,
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
- **Fresh-node window.** Fifteen simulated minutes and two query
  batches in the grid experiments. Observed depth is far below list
  depth at that point; §8.10 and §8.11 extend the window to two hours and
  one hour respectively.
- **Handshake proof-of-work interaction.** Present in every run but not
  measured in the eclipse experiments. Attackers self-announce on the
  free endpoint, so it should not bind; unverified.
- **Corrections during the study.** Two conclusions were reversed after
  closer measurement (§8.6). They are kept in the record deliberately.

---

## 11. Future work

0. Follow-ups to §8.13 and §8.14. The reserve's pick rule takes one
   peer per reporter cluster; a per-bucket nomination rule would lift
   the honest slots from about two to up to K under a naive corral, at
   the price of up to min(K, S) slots for a below-crossover attacker
   instead of one, and is a design choice to measure rather than a fix.
   The reserve at longer windows. Native vouchers with the plugin
   handshake rather than a TCP connect. Then bootstrap latency under the
   etiquette scan profile of §3.7 (every run so far used `--scan-legacy`)
   and the first-contact window that profile opens, which the coverage
   rule of §12 would close if adopted; and the venue-oracle experiment
   of the specification's test plan, which would put a number on the
   crossover in hashrate.
1. Honest counts beyond 200, to test whether the crossover keeps scaling
   linearly. Needs a `/15` scan range or a smaller attacker bucket
   ceiling, since 200 honest buckets plus attackers already fill most of
   a `/16`.
2. Query budget as a defense parameter: batch size and interval set how
   fast both honest and attacker depth are observed (§9.2); measure the
   bootstrap window against them.
3. Tie-breaking at equal depth. Fakes tie honest peers exactly at `S`;
   the current tie-break is verified flag then recency, and a deliberate
   rule (older first, or verified only) may shift the crossover by one.
4. Autonomous-system buckets via an asmap-style file.
5. Enable verification at scale, which requires lightweight fake daemons
   (see `TODO/bash_daemon_for_scale.md`), to measure the peer-level upper
   bound against the real behaviour.
6. Price the attack: `/16` rental cost by provider, so the cost statement
   in §9.2 is in currency.
7. Cross-source consistency checks (chain height and tip via the daemon
   handshake) as a defense in the regime of §9.3.

---

## 12. Proposed extension: chain-anchored publication

This section is a proposal, not a result. Nothing in it has been built
or measured. It is recorded here because the analysis in §9 and the
defenses of §8.13 and §8.14 end at a limit, and the
proposal is the only design found so far that moves the limit rather
than the price.
The specification is `docs/spec-chain-anchored-publication.md`; this
section gives the reasoning.

### 12.1 The limit

Every defense in §6 rests on one scarce resource: address diversity. An
adversary with more distinct prefixes than the honest population has,
for discovery purposes, become the network (§9.3). The hand-off reserve
keeps a few honest peers on the daemon's list past that point, but only
among reporters the victim has actually queried, and at two hundred
prefixes and fifteen minutes that was a handful (§8.13). Two further
facts sharpen the limit. A move to an anonymity network such as I2P
removes prefixes altogether, since a destination has no street, and
with them every measured defense except native vouchers. And a corral
is internally consistent: from inside an attacker's world every check
passes, because every check compares data the attacker supplied against
other data the attacker supplied. What is missing is a resource the
attacker cannot mint, and a yardstick from outside the attacker's world.

### 12.2 The design

Proof-of-work on the network's own chain supplies both, and P2Pool
supplies the way to reach it without changing anything.

- **Publication is mining.** A transpeer operator who mines on P2Pool
  runs a sidecar that poses as a merge-mined aux chain. P2Pool's
  existing merge-mining support then carries the hash of the operator's
  curated transpeer list as an aux leaf in every share the operator's
  node produces and in every Monero block it finds. The leaf is bound at
  mining time by the share's proof-of-work; nothing is signed after the
  fact and nothing can be equivocated. Monero's consensus, monerod,
  P2Pool and the mining software are all untouched. The specification
  also gives a second route, a P2Pool share-format change that puts the
  field in every share (§12.5).
- **Blobs live beside their hashes.** Every transpeer keeps a
  content-addressed table: the list bytes and the hash that names them,
  plus the shares and blocks in which the hash was committed. The chain
  is the index; the overlay is the storage; a row verifies itself.
  Nothing but hashes ever reaches the ledger, and only transpeer
  addresses, which are public servers, are ever listed.
- **Weight is work.** A transpeer's weight is the verified difficulty
  of the shares whose leaves commit to blobs listing it, summed across
  every P2Pool sidechain, with no per-venue quota. A venue the attacker
  creates and mines alone is worth exactly the attacker's work.
- **The yardstick.** To show a fresh tip, an attacker must show the
  real Monero chain. Its coinbases carry the merge-mining tags of every
  block P2Pool found, so a newcomer can read, from data the attacker
  cannot forge, what fraction of tagged blocks the venues it can see
  account for. Below half, it is in a corner and keeps discovering.
  This also replaces the scanner's stop condition of §3.7: a node stops
  knocking when it can see most of the mining, not when three doors
  have opened, which closes the first-contact window recorded there.
- **Faithfulness is testable.** Because blobs are content-addressed,
  any node can ask any transpeer for any committed blob and check the
  answer. A transpeer that cannot serve what others can is withholding,
  and is ranked out. Withholding, the one attack the yardstick could
  not attribute, becomes a per-node verdict.
- **Garbage costs its publisher.** Optionally, P2Pool nodes run by
  transpeer operators refuse to build on shares from a wallet whose
  committed list failed a tolerant, cached, store-based check. With an
  aware majority of a sidechain's hashrate, such shares are orphaned and
  the wallet forfeits its reward. A share carrying no commitment is
  never judged, so miners who do not run transpeer are unaffected.

### 12.3 Why P2Pool rather than the main chain

Publication rights follow the work, and on P2Pool the work is spread
across everyone. A home CPU solo-mining Monero finds a block about once
a year, so a design anchored to main-chain blocks hands publication to
a handful of pool operators. The same CPU finds a P2Pool share every few
days on the main sidechain and every few hours on the mini and nano
sidechains. The published set is therefore the union of thousands of
independently curated lists from thousands of independent operators,
weighted by CPU-time on an ASIC-resistant hash: the honest transpeer
population of §7, but with a weighting resource the attacker cannot
mint. Multiple sidechains add resilience and publisher diversity; the
no-quota rule is what keeps them from adding attack surface. And the
aggregation has already happened when the newcomer arrives: it reads
every publisher's list from the whole window in one pass, which removes
the query-budget bottleneck that limited the reserve.

### 12.4 Security argument

| adversary | outcome | binding constraint |
|---|---|---|
| addresses or prefixes, no mining | cannot publish | work |
| private venue, own hashrate | worth its work; yardstick exposes the sliver | anchor-chain tags |
| whole world of attacker nodes | coverage fails; newcomer keeps discovering | anchor-chain tags |
| withholding while showing the real chain | attributed per node | content addressing |
| stale tip, private fork of a real venue | rejected | freshness, canonical-fork rule |
| garbage from a real wallet | weight of its work; reward forfeited under the policy layer | mining policy |
| majority of one sidechain | dominates that venue; must also dominate tagged blocks overall | all P2Pool hashrate |
| majority of Monero | out of scope | consensus |

Every row reduces to the same threshold: to corral a newcomer the
attacker must find more than half of the Monero blocks that P2Pool
finds, continuously, and lose the corral the moment it stops. That
threshold is the same for every network that carries the anchor, and it
is independent of prefix count.

### 12.5 Costs and dependencies

The engineering is entirely in the sidecar: an aux-chain RPC server on
the publishing side; an observer client for each sidechain, verification
of Monero headers from the release checkpoint with RandomX in light
mode, coinbase Merkle proofs and tag parsing on the reading side; the
blob database and its endpoints; weighting, coverage, challenges; and
optionally the policy hook. Header verification for a year-old
checkpoint is a good fraction of an hour on a small machine, reduced by
sampling. The P2Pool interface facts the design rests on were verified against
the v4.18 source on 2026-09-13 and are recorded in the specification's
§15: the merge-mining RPC and tag layout are as described, every share's
sidechain data lists each merge-mined chain's aux hash explicitly, the
merge-mining client reports every share that meets the aux difficulty
together with its Merkle proof, and P2Pool nodes keep about twelve
hours of shares. Two findings changed the design: the client drops an
aux job whose hash has not changed for thirty minutes, so a published
list carries a period field that rotates its hash without changing its
content; and P2Pool already contains, behind a compile-time flag, an
aux-job donation message signed with the author's key that puts one job
into every node's templates, which is a third route, a maintainer-
curated anchor list with the whole venue's work behind it, recorded in
the specification as such. P2Pool's share of Monero's hashrate, read from the
three observers the same day, was 6.65 percent on the main sidechain,
0.42 on mini and 0.07 on nano, about 7 percent together against a
reported peak above 18 percent in May 2025; half of it is about 210
megahashes per second, on the order of ten to twenty thousand CPUs.

The no-change route has an early-adoption weakness worth stating: the
honest weight behind published lists is the hashrate of miners who run
a sidecar, so an attacker must beat the participants, not the venue,
and while participants are a few percent of P2Pool that is cheap. The
second route in the specification closes the gap by changing P2Pool's
share format so that every share carries the field, with P2Pool filling
it by default from a built-in probe of its own peers' transpeer port,
which is the daemon-peer path executed by P2Pool itself. Under that
route the honest weight is the venue's whole hashrate from the first
day, availability in the window is provided by the sidechain itself,
and the price is a sidechain fork coordinated through a P2Pool release.
The two routes compose: the first is the proof of concept and the
second is what to ask the maintainer for.

### 12.6 What it does not solve

Discovery inherits the anchor chain's security and no more: for a chain
that can be 51-percented cheaply, the anchor is exactly as weak, and the
clearnet defenses of §6 remain the ones doing the work there. That
ceiling is not hypothetical even for Monero: in August 2025 the Qubic
project claimed a majority of the network's hashrate and produced
reorganisations reported at 6 and 18 blocks deep. An anchored newcomer
during such an episode follows whichever chain the majority extends,
which is all a chain-anchored design can promise, and the clearnet
defenses keep working regardless. An
attacker who is a newcomer's entire first view can still delay it, only
not mislead it. The policy layer's verdicts are heuristics with
tolerances, and they bite only once aware miners are a majority.
Networks without a P2Pool-like venue need main-chain commitments and
therefore miner cooperation. And it is unmeasured; the venue-oracle
experiment in the specification's test plan and §11 item 0 would put a
number on the crossover in hashrate.

---

## 13. Reproducibility

Repository: `github.com/Fountain5405/transpeer`. All work is on `master`.
On 2026-09-11 the `bootstrap-eclipse` branch was rebased onto
`machine-migration-bootstrap` and both were merged into master; the
rebase rewrote the eclipse commit hashes, and this table gives the
post-rebase values (old to new: `de02f26`→`83b3596`, `b769837`→`d9f09e4`,
`26096f0`→`22c3ec4`, `564b91d`→`aeb783d`, `82070b2`→`04653c4`,
`f00175e`→`c451560`, `c8c2134`→`f5e575d`, `f1c683f`→`47feb92`).

| commit | content |
|--------|---------|
| `23d54d9` | machine-independent sim infrastructure |
| `76da518` | scale_baseline (§8.1) |
| `83b3596` | `--subnet-prefix`, `--bucketed`, snapshot logging, attacker self-announce, experiment |
| `d9f09e4` | eclipse grid results (§8.4) |
| `22c3ec4` | `--vouchers` and rerun (§8.5) |
| `aeb783d` | coordinated attacker (§8.6) |
| `04653c4` | honest peer model, proof cache, depth metric (§8.7) |
| `c451560` | crossover fill (§8.8) |
| `f5e575d` | `--tried-table`, Shadow seed, `--attacker-start`, replicas, `run_followups.sh`; protocol section |
| `47feb92` | §8.9 single-seed follow-ups (uptime, 200 honest, tried table) |
| `9d7a474` | `run_replicas.sh` |
| `6bdf442` | five-seed replicas (§8.10 to §8.12), `aggregate_seeds.py`, determinism caveat |
| `85191de` | `--handoff-reserve`, `--native-vouchers`, scanning etiquette (§3.7), `run_defenses.sh` |
| `e24a708`, `983490f` | `docs/defenses-explained.md`; §12 and `docs/spec-chain-anchored-publication.md` |
| results commit following `983490f` | §8.13, §8.14, §9.6, this revision |
| `2b16d6a`, `bcd5169` | adaptive handshake PoW and its experiment (§8.2), earlier |
| `f98736a` | attacker_ratio (§8.3), earlier |
| `TBD` | chain-anchored publication, slices 1–2: blob, Merkle, blob DB, weighting, publisher, aux RPC, blob endpoints (no measurements) |

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
    sim/tests/bootstrap_eclipse/run_followups.sh                           # §8.9, single-seed §8.10-8.12
    sim/tests/bootstrap_eclipse/run_replicas.sh                            # §8.10-8.12, five seeds
    sim/tests/bootstrap_eclipse/run_defenses.sh                            # §8.13, §8.14
    python sim/tests/bootstrap_eclipse/aggregate_seeds.py <results_file>   # mean and range over seeds

Unit checks: `tests/test_two_nodes.py` (24, real EquiX, default policy)
`tests/test_bucketed.py` (47: both policies, vouchers, the tried table,
the reserve and native vouchers, no network) and `tests/test_scanner.py`
(19: exclusions, rate selection, pacing).

---

## 14. Claims ledger

| # | claim | status | evidence |
|---|-------|--------|----------|
| 1 | The `/16` limit applies only to gossiped entries; scan and candidate paths bypass it | measured | code at `23d54d9`; `test_bucketed.py` admission checks |
| 2 | Recency eviction lets a re-announcing attacker displace honest entries | measured | §8.4, §8.7 honest-retained counts |
| 3 | Under the current policy attacker store share tracks IP count | measured | §8.4 |
| 4 | Under bucketing attacker store share is `min(A,3S)/(min(A,3S)+H)` | measured, 24/24 cells | §8.4, §8.7 |
| 5 | Bucketing retains honest transpeers at every attacker size tested | measured | §8.4, §8.7 |
| 6 | Neither policy helps at `S >= 2H` | measured | §8.4, §8.7 spread cells |
| 7 | Voucher counting caps attacker peer entries at 50 per prefix | measured | §8.5 |
| 8 | Under vouchers a coordinated attacker is absent from the daemon's top 20 at `S = 3` (mean 2 %) and enters at `S = 4` (mean 26 %, five of five seeds), majority from `S = 5` | measured, five seeds | §8.9 |
| 9 | Crossover equals observed depth of the honest peers at the bottom of the top 20 | measured, five layouts per H | §8.8, §8.10, §8.11 depth columns |
| 10 | Crossover scales about linearly with honest transpeers on the network (entry 4, majority 5 at 26; entry 16 to 24, majority 32 at about 120) | measured, five seeds per H | §8.11 |
| 11 | Attacker excluded at `S = 4` by the 30-minute mark in every seed; observed honest depth saturates at layout depth within 60 minutes in every seed | measured, five seeds | §8.10 |
| 15 | Victim's query budget throttles observed attacker depth as much as honest depth | measured, five seeds | §8.11 |
| 16 | Tried table restores honest retention under the current policy (38 to 44 without, 48 to 49 with, of 50) and is redundant under bucketing | measured, five seeds | §8.12 |
| 17 | An established node under the current policy loses fewer honest transpeers to a flood than a fresh one (6 to 12 vs 18 to 28) | measured, five seeds | §8.12 vs §8.4, §8.7 |
| 19 | A six-prefix attacker against 50 honest transpeers keeps 15 to 35 percent of the daemon's list after two hours of victim uptime | measured, four of five seeds | §8.10 |
| 20 | A fake that answers queries can become tried; at most one per cell, in 5 of 40 cells | measured, five seeds | §8.12 |
| 21 | Under voucher ranking a coordinated attacker with 25 or more prefixes against 50 honest holds 100 % of the daemon's list at 15 minutes; the hand-off reserve puts 1 to 4 honest peers on it in 5/5 seeds at 25, 50 and 100 prefixes and 4/5 at 200 | measured, five seeds | §8.13 |
| 22 | Reserve size beyond the number of honest reporter clusters adds nothing: K = 10 rows identical to K = 5 | measured, five seeds | §8.13 |
| 23 | The reserve's reach is bounded by reporters the victim has queried; at 200 prefixes one seed in five heard none and stayed at 100 % | measured, five seeds | §8.13 |
| 24 | The reserve's floor cost is one slot (5 %) to any below-crossover attacker cluster of two or more prefixes (200 honest, 8 prefixes, 5/5 seeds) | measured, five seeds | §8.13 |
| 25 | Native vouchers reduce an announce-only attacker to 0 % of the daemon's list at 6, 8 and 25 prefixes (15/15 cells) and leave an attacker with a daemon port per address where voucher ranking left it | measured, five seeds | §8.14 |
| 18 | Entry crossover near 150 and majority near 250 prefixes at 1000 honest transpeers | extrapolated | §9.2 |
| 12 | Query share under bucketing lags the store formula early and converges | hypothesis | §8.4 query table; not rerun longer |
| 13 | Verification would remove unreachable fakes within minutes | hypothesis | not simulated |
| 14 | ASN bucketing raises attack cost without changing the bound | hypothesis | not implemented |

---

## Appendix A. Record of corrections

- §8.5 first reported a clean daemon view as a ranking win. §8.6 showed it
  was mostly attacker network choice. Corrected in commit `aeb783d`.
- §8.6 first read the 65 percent floor as ranking failure. It was honest
  supply under the four-peer model. Corrected in the same commit.
- The runner's memory guard first projected 40 MB per host from the
  previous machine; §8.1 measured 33 to 52. The 5000-host baseline was
  aborted by the guard and has not been rerun.
- §7 first stated the fresh node completes three query cycles in the
  15-minute window. It issues two; the third begins at the stop time.
  Corrected with §8.9.
- §8.8 attributed run-to-run variance to unseeded node randomness. Shadow
  seeds all host randomness from its config; the variance came from host
  counts differing between cells. Corrected with §8.9, which varies the
  Shadow seed explicitly.
- §8.11 (single seed) put the 200-honest entry crossover between 24 and
  32 prefixes. Five seeds put entry between 16 and 24 and majority at 32;
  seed 1 alone shows 0 percent at 24, where the mean is 36. Corrected
  with the five-seed revision, which also revised the 1000-honest
  extrapolation (claim 18).
- §8.12 (single seed) stated that no attacker entry became tried. Across
  five seeds one fake reached the threshold in 5 of 40 cells. Corrected
  with the five-seed revision.
- The 2026-09-11 rebase rewrote the eclipse commit hashes. Every hash in
  this document was updated to the post-rebase value; the mapping is in
  §13.
- §7 and the contributor notes stated that two runs of one config are
  identical. That holds only at a fixed worker count; the seed-1 rows of
  the five-seed files (30 workers) differ from the single-seed files (60
  workers) in the timing-dependent columns. Recorded in §10 with the
  five-seed revision.
