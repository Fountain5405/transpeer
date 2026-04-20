# Bash-based fake daemon for large-scale Shadow simulation

## Problem
Each Python fake_daemon process is ~40MB. At 200+ hosts with multi-network
configurations, we hit OOM. Current workaround is `--static-peers` which
hardcodes peers at transpeer startup — no churn, no dynamic behavior.

## Idea
Replace `fake_daemon.py` with a lightweight bash+netcat/socat implementation.
Memory footprint could drop from ~40MB to ~1-5MB per daemon.

## Requirements
- Serve JSON-RPC on a port (mimic Monero's `get_peer_list` and `get_connections`)
- Accept TCP connections on the P2P port and respond with magic handshake bytes
- Ideally support dynamic peer list updates (read from a file that another
  lightweight process can rewrite periodically)

## Sketch
```bash
# Serve static JSON via socat
socat TCP-LISTEN:10001,fork,reuseaddr \
  SYSTEM:"cat /tmp/daemon_peers.json; sleep 0.1"
```
Combined with a background process that periodically updates
`/tmp/daemon_peers.json` to simulate peer churn.

## Value
Would enable simulations at 1000+ hosts with realistic per-node peer
behavior. Particularly useful for testing:
- How transpeer handles a daemon whose peer list evolves
- Long-running simulations where peer churn matters
- Attack scenarios that depend on timing of peer list updates

## Priority
Low — `--static-peers` + `--no-verify` is sufficient for large-scale
testing of discovery, gossip, and scan behaviors. Tried a bash+nc
implementation but OpenBSD nc's single-shot listen pattern would mean
process churn that Shadow doesn't handle well. Real fix needs socat or
a small compiled binary.

Revisit if we need to simulate:
- Peer churn (daemons' peer lists changing over time)
- Full verification pipeline at scale (currently tested at smaller scale
  with Python fake_daemon.py)
