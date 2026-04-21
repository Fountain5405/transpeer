# Transpeer Shadow Simulation Test Matrix

This directory contains Shadow-based network simulations for transpeer. Each
test lives in its own folder with:
- `gen_config.py` — generates Shadow YAML configs for this test's scenarios
- `run_experiment.sh` — runs all scenarios sequentially, captures metrics
- `configs/` — generated Shadow configs (committed so tests are reproducible)
- `data/` — per-scenario Shadow output (gitignored, too large)
- `results.txt` — CSV summary of each scenario's metrics
- `README.md` — writeup of what was found

## Running a test

```bash
cd sim/tests/<test_name>
./run_experiment.sh
```

Results are appended to `results.txt` and log output to `run.log`.

## Test matrix

| ID | Category | Purpose | Status |
|----|----------|---------|--------|
| [scale_baseline](#scale_baseline) | Scale | Find upper bound of hosts on this machine | partial (700 confirmed) |
| [cross_network](#cross_network) | Discovery | Verify cross-network peer propagation | done |
| [attacker_ratio](attacker_ratio/) | Attack | Impact of N% attackers injecting fake peers | done |
| [handshake_pow](handshake_pow/) | Defense | Adaptive handshake PoW under distributed flood | done |
| [sybil_subnet](#sybil_subnet) | Attack | /16 subnet domination via Sybil transpeers | pending |
| [slow_burn_inject](#slow_burn_inject) | Attack | Slow-drip injection under per-source cap | pending |
| [bootstrap_eclipse](#bootstrap_eclipse) | Attack | Attacker saturates network before honest nodes | pending |
| [distributed_ddos_multi](#distributed_ddos_multi) | Attack | Distributed flood across many victim transpeers | pending |
| [long_running](#long_running) | Stability | Store / cache / rotation behavior over hours | pending |
| [honest_under_attack](#honest_under_attack) | UX | Bootstrapping honest node succeeds under attack | pending |
| [discovery_density](#discovery_density) | Discovery | Scan success vs network density | pending |

---

## Test details

### scale_baseline
**Purpose**: measure how many hosts Shadow + transpeer can simulate on this machine.

**Setup**:
- Vary host count: 55, 200, 500, 700
- 15-min simulated time
- 1 Python process per host (`--static-peers`, `--no-verify`)
- `--sim-pow` (no effect if no actual attackers, but should be on)

**Metrics**: peak RSS, real-run time, simulated time advance rate, honest1 unique transpeers discovered.

**Current results** (pre-tuned gossip):
- 55 hosts: 0.3 GB, 41 s real
- 200 hosts: 9 GB, 6 min real
- 500 hosts: 19 GB, 20 min real
- 700 hosts: 27 GB + 2.3 GB swap, 27 min real

**What we learned**: memory is ~40 MB/host. Runtime scales super-linearly with hosts due to N² gossip cost. 700 is near the ceiling on a 31 GB machine. Tuned gossip (gossip sample 50 instead of full list) cut /transpeers payloads 10× and reduced runtime ~17% at 500 hosts.

---

### cross_network
**Purpose**: verify that a transpeer running network A can discover peers for networks B, C, D, E through the overlay, without running any of them.

**Setup**: 15 hosts, 5 networks (p2pa-p2pe), 3 hosts per network, 5 min simulated.

**Current results**: node1 (runs p2pa only) received verified peers from p2pb, p2pc, p2pd, p2pe via other transpeers. Cross-network propagation confirmed.

**Status**: done. Kept as a smoke test.

---

### attacker_ratio (folder: `attacker_ratio/`)
**Purpose**: measure the impact of increasing attacker population on honest node behavior (peer-injection attack).

**Setup**:
- 600 total hosts
- Attacker percentages: 10%, 25%, 50%
- 15 min simulated time
- Each attacker generates 100 fake peers with `--sim-pow` (~4.1s per peer at difficulty=100)

**Metrics**: unique transpeers discovered (honest1), queries to attackers, peers received from attackers.

**Current results**: honest1 discovered attackers at population ratio (11%, 29%, 57%) but queried 0 of them in all trials. EquiX delay (410s per attacker) + rotation policy (prefer oldest `last_queried`, stable-sort by insertion) gave honest nodes a head start that lasted the full 15-min window.

**What to investigate next**: longer sim time to see if attackers eventually get queried once rotation cycles through.

---

### handshake_pow (folder: `handshake_pow/`)
**Purpose**: measure adaptive handshake PoW effectiveness against distributed request floods.

**Setup**:
- 1 victim transpeer, 20 honest transpeers, variable flooders
- Flooders send 0.8 req/s each (below per-IP rate limit)
- Scenarios: 0, 30, 60, 100 flooders (no PoW solving); 100 flooders (solving)
- 15 min simulated time

**Metrics**: victim peak difficulty, flooder 200/402/429 counts, PoW solves, total attacker CPU time.

**Current results**:
| Scenario | Peak difficulty | 200 | 402 | 429 | Solves | CPU |
|----------|-----------------|-----|-----|-----|--------|-----|
| baseline | 0 | 0 | 0 | 0 | 0 | 0 |
| 30 flooders | 462 | 1,137 | 6,139 | 0 | 0 | 0 |
| 60 flooders | 935 | 844 | 14,153 | 0 | 0 | 0 |
| 100 flooders | 1000 | 1,412 | 22,941 | 0 | 0 | 0 |
| 100 + solving | 1000 | 23,286 | 100 | 0 | 100 | 420s |

**What we learned**: load tracker keyed on total request volume correctly catches distributed floods. Non-solving attackers get 94% 402'd. Solving attackers get ~23K requests through for ~4s of CPU each (1-hour cache amortizes well). Max difficulty 1000 ≈ 4s per solve.

---

### sybil_subnet
**Purpose**: verify the /16 subnet limit on gossiped transpeers prevents Sybil domination.

**Setup**:
- 100 honest transpeers across varied /16s
- 1 "injector" attacker transpeer that gossips a large list of fake transpeers all in a single /16
- Measure: how many of those fakes get accepted by a honest node's store

**Expected result**: no more than 3 transpeers per /16 accepted (MAX_TRANSPEERS_PER_SUBNET).

**Pass/fail**: pass if honest store has ≤ 3 transpeers from the attacker's chosen /16 after gossip.

**Status**: pending.

---

### slow_burn_inject
**Purpose**: verify the per-source ramp-up cap handles a patient attacker who publishes fakes slowly enough to grow their cap over time.

**Setup**:
- 20 honest transpeers
- 1 attacker transpeer that publishes entries slowly (1 entry/min) and verifies some entries to pass the 80% threshold
- 4-hour simulated time
- Attacker mixes real peers (redirecting to their own fake daemons) and obvious fakes

**Expected result**: attacker's cap may grow if they include enough verifiable entries, but verification kills the fakes → trust contracts back to base.

**Pass/fail**: store doesn't end up dominated by attacker entries after 4h.

**Status**: pending. Requires actual peer verification to work (need fake daemons or sim-only verify hook).

---

### bootstrap_eclipse
**Purpose**: what if an attacker runs the majority of transpeers a fresh node finds during bootstrap? Can they eclipse the honest network?

**Setup**:
- 50 honest transpeers
- N attacker transpeers (vary N: 50, 150, 500, 1500)
- 1 "fresh" honest node that starts late, measures its peer store after 10 min
- Each attacker serves its own peers; fresh node reaches either real monero peers or attacker fakes

**Expected result**: as attacker count grows, fresh node picks up more attacker IPs. Random scanning provides some uniformity but doesn't fully resist.

**Metrics**: % of fresh node's final peer store that came from attacker sources.

**Pass/fail**: report the curve — is there a threshold where attack becomes too effective?

**Status**: pending.

---

### distributed_ddos_multi
**Purpose**: distributed flood against many victim transpeers simultaneously (realistic DDoS).

**Setup**:
- 50 honest transpeers (all potential victims)
- 200 flooders, each hits a random victim every second
- Per-victim load ≈ 4 req/s (below individual per-IP rate limits but aggregate adds up)

**Metrics**: per-victim peak difficulty, honest node's ability to complete queries during attack.

**Pass/fail**: honest nodes can still complete query cycles with <50% failure rate.

**Status**: pending.

---

### long_running
**Purpose**: verify store stability, cache expiry, rotation catches late attackers over long simulated time.

**Setup**:
- 50 honest + 10 attackers
- 6-hour simulated time
- Log peer store sizes every 10 min, verify cache expirations happen

**Expected result**:
- Store sizes plateau (don't grow unbounded)
- Handshake PoW cache entries expire at bucket boundaries
- Query rotation eventually cycles to every known transpeer (including late-joining attackers)
- Dead peer cooldowns clear

**Pass/fail**: no unbounded growth, rotation is fair over 6h, caches expire correctly.

**Status**: pending.

---

### honest_under_attack
**Purpose**: UX metric — can an honest user bootstrap successfully while the network is under distributed flood?

**Setup**:
- 20 honest transpeers + active flooders
- 1 "fresh" honest node starts 5 min in
- Measure: time to first verified peer, total peers after 15 min, % of queries succeeded

**Pass/fail**: fresh node gets at least 5 verified peers within 15 min of sim time, regardless of flood intensity.

**Status**: pending.

---

### discovery_density
**Purpose**: how does scan-based discovery perform as transpeer density drops?

**Setup**:
- 50 honest transpeers across varying scan ranges: /24 (250 addresses), /20 (4K), /16 (65K), /8 (16M)
- Measure: time to first discovery, total unique discovered after 30 min

**Expected result**: density inversely proportional to discovery time. /24 finds peers in seconds, /8 may take a long time.

**Pass/fail**: quantify how density affects bootstrap time so we can recommend scan-range parameters.

**Status**: pending.

---

## Shared infrastructure

All tests use:
- `sim/gen_scale_test.py` (or test-local `gen_config.py`) for config generation
- Shadow 3.2.0 from `/home/lever65/monerosim_dev/shadowformonero/build/src/main/shadow`
- Python 3.12 with transpeer deps installed

Simulation flags used consistently:
- `--in-memory`: skip SQLite (Shadow FS issues)
- `--sim-pow`: simulate EquiX via `time.sleep()` so Shadow can advance its clock
- `--no-verify`: disable peer verification loop (because simulated peers have no TCP listener unless we wire one up)
- `--static-peers`: transpeer fakes its daemon peer list via CLI, saving a Python process per host

## Metric extraction conventions

Per-scenario CSV columns should include:
- Scenario ID
- Real run time (seconds)
- Peak memory (MB)
- Host counts (honest, attackers, flooders, victims)
- Primary defense metric (difficulty peak, entries accepted, % blocked)
- Secondary cost metric (attacker CPU time, honest CPU time)

## Known limitations

- **No peer verification at scale**: because `--static-peers` entries have no TCP listener, `--no-verify` must be used. Verification defense tested only at smaller scale with Python fake_daemon.py. See `TODO/bash_daemon_for_scale.md`.
- **Sim-pow dummy proofs**: simulated PoW uses a magic marker that both sides recognize. Real EquiX verification is bypassed in sim mode.
- **Memory ceiling**: ~700 hosts on a 31 GB machine. Bigger tests need a bigger machine or optimizations.
