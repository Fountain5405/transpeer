# Transpeer handoff — context for a new machine

Use this as the initial prompt when opening Claude Code on a new machine.

## What this project is

**Transpeer** is a cross-network P2P peer discovery overlay protocol. A node
running transpeer alongside its crypto daemon (Monero, Wownero, etc.) can
discover peers for *any* participating network through the overlay, not just
the networks it runs. The goal is to make P2P bootstrapping more robust by
letting different cryptocurrencies and other P2P networks share the discovery
layer.

Repo: https://github.com/Fountain5405/transpeer (I have write access as
`Fountain5405`). Branch: `master`.

## Where we are in the work

Formal protocol spec `transpeer/1` is written (see `PROTOCOL.md`). Core
implementation is in Python/aiohttp. EquiX proof-of-work is integrated via
ctypes bindings to tevador's C library. All defense layers are in place:
per-source cap with trust-based ramp-up, /16 subnet limits, dead-peer
cooldown, per-network peer caps, transpeer-tracking caps with oldest eviction,
gossip sample bounding, adaptive handshake PoW (dormant-until-abuse,
Tor-inspired).

We've been running Shadow simulations to test the protocol at scale. The
Shadow install on the previous machine is at
`/home/lever65/monerosim_dev/shadowformonero/`. **The new machine will need
its own Shadow build.** See bootstrap section.

## Test matrix and priorities

See `sim/tests/README.md` for the full matrix. Done so far:
- `cross_network` — verifies peer propagation across networks
- `attacker_ratio` — 600 hosts, 10/25/50% attackers injecting fake peers
- `handshake_pow` — adaptive handshake PoW under distributed flood

**Next up, in order:**
1. `bootstrap_eclipse` — attacker-majority network scenario
2. `sybil_subnet` — /16 subnet limit verification
3. `honest_under_attack` — UX metric during attack
4. `distributed_ddos_multi` — flood across many victims
5. `long_running` — store/cache/rotation stability over hours
6. `discovery_density` — scan success vs network density

(We decided to skip `slow_burn_inject` — it needs working verification at
scale, which would require investing in a bash fake-daemon first.)

## Why we're migrating machines

Previous machine is a Ryzen 9 3900X with 31 GB RAM. That caps us at ~700 hosts
per Shadow sim (we're memory-bound). To run `bootstrap_eclipse` with thousands
of attacker nodes, and `long_running` at scale, we need more RAM. Target
machine is a Threadripper 3970X with 256 GB RAM — should enable 5000-7000
host sims.

## Bootstrap on the new machine

```bash
# Clone the repo
cd ~
git clone https://github.com/Fountain5405/transpeer.git
cd transpeer

# Python deps (use --break-system-packages on Ubuntu/Debian)
pip install --break-system-packages aiohttp aiosqlite pyyaml

# Build EquiX C library
python3 equix/build.py
# If the submodule fetch fails, try:
#   cd equix/equix-src && git submodule update --init --recursive

# Build Shadow 3.2.0 from source
# Shadow docs: https://shadow.github.io/docs/guide/install_shadow.html
# Quick version:
sudo apt install -y cmake findutils libclang-dev libc-dbg libglib2.0-dev \
    make netbase python3 python3-networkx xz-utils util-linux gcc g++
# Install Rust if not already: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
# Then:
cd ~
git clone https://github.com/shadow/shadow.git
cd shadow
./setup build --clean --release
./setup install  # installs to ~/.local/bin

# Verify
~/.local/bin/shadow --version

# Update the shadow binary path in test runners
# Edit these files to use ~/.local/bin/shadow instead of the old path:
#   sim/tests/attacker_ratio/run_experiment.sh
#   sim/tests/handshake_pow/run_experiment.sh
# Search for "SHADOW_BIN=" and point it at the new install

# Verify everything works
cd ~/transpeer
python3 tests/test_two_nodes.py
# Should see: Results: 24/24 passed, 0 failed
```

## Key files to know

- `PROTOCOL.md` — the transpeer/1 wire protocol spec
- `transpeer/` — the Python implementation
  - `node.py` — main orchestrator, the event loops
  - `server.py` — HTTP server + LoadTracker for adaptive PoW
  - `client.py` — HTTP client with transparent handshake PoW
  - `peerstore.py` — in-memory store + SQLite persistence, all defense
    mechanisms live here
  - `pow.py` — EquiX ctypes wrapper (real + simulated + handshake variants)
  - `scanner.py` — async IPv4 scanner
  - `networks/` — per-network plugins (monero, wownero, aeon, generic)
- `sim/` — Shadow simulation infrastructure
  - `gen_scale_test.py` — parameterized config generator
  - `attacker.py` — peer-injection attacker
  - `flooder.py` — request-flood attacker
  - `tests/README.md` — test matrix
  - `tests/*/` — individual test experiments
- `tests/test_two_nodes.py` — fast unit/integration tests (24 checks, no
  Shadow needed)

## Conventions we've been following

- Run all tests via their `run_experiment.sh`. They save configs to `configs/`
  (committed) and data to `data/` (gitignored).
- Results go in `results.txt` as CSV — commit that.
- For large/long sims, use the Monitor tool to stream memory + progress.
- Commit each logical chunk with Co-Authored-By.
- Avoid committing `sim/shadow.data/` or per-test `data/` dirs — those are
  gigabytes of per-host stderr logs.

## Open design questions parked for later

1. **Bash/socat fake daemon** (`TODO/bash_daemon_for_scale.md`) — for
   full-verification testing at scale. Python daemon is too heavy per-host.
2. **Adaptive entry-PoW difficulty** — scale EquiX difficulty per source
   based on their verification rate. Not yet implemented; discussed but
   decided not urgent given existing defenses.
3. **Handshake PoW bucket size tuning** — currently 1 hour. Shorter = more
   attacker re-solves but also more honest-client re-solves. Decided to leave
   at 1 hour since honest UX matters more.

## What to tell Claude first

Paste the whole contents of this file (`HANDOFF.md`) into the first prompt on
the new machine, then ask to pick up where we left off. Suggested first
actions:

1. Run `tests/test_two_nodes.py` to confirm environment works.
2. Pick up with implementing `bootstrap_eclipse` per `sim/tests/README.md`.
3. Once that's running, move to `sybil_subnet` and the rest of the matrix.
