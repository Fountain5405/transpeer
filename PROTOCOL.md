# Transpeer Protocol Specification v1

## Overview

Transpeer is a cross-network P2P peer discovery overlay protocol. It allows nodes on different P2P networks (Monero, Wownero, BitTorrent, etc.) to share peer lists, so a new node can bootstrap by finding any transpeer via IPv4 scanning, then discover peers for any network through the overlay.

## Transport

- **Port**: 7337 (TCP)
- **Protocol**: HTTP/1.1 with JSON payloads
- **Address space**: IPv4 only (IPv4 scarcity provides natural Sybil resistance)

## Proof-of-Work

Every peer entry published to the transpeer network must carry an EquiX proof-of-work. This makes it computationally expensive to flood the network with fake peer entries.

### Challenge Construction

```
timestamp_bucket = unix_time // 21600
challenge = blake2b(network || ":" || addr || ":" || port || ":" || timestamp_bucket, digest_size=32)
```

### Solving

1. Generate a 16-byte nonce (8-byte counter + 8 random bytes)
2. Compute `full_challenge = challenge || nonce`
3. Call `equix_solve(full_challenge)` to get candidate solutions
4. For each solution, check: `blake2b(challenge || nonce || solution, digest_size=4)` interpreted as little-endian uint32, multiplied by `effort`, must be `<= 0xFFFFFFFF`
5. If no solution passes, increment counter and retry

### Verification

1. Check `timestamp_bucket` is current or previous 6-hour window
2. Reconstruct `challenge` from peer entry fields
3. Call `equix_verify(challenge || nonce, solution)` — must return OK
4. Check difficulty: `blake2b(challenge || nonce || solution) * effort <= 0xFFFFFFFF`

Verification takes ~50 microseconds. Solving takes significantly longer, scaling with effort.

### Timestamp Buckets

Proofs are valid for the current 6-hour window and the previous one (12-hour total validity). This prevents indefinite proof reuse while giving honest nodes ample time between re-solves and allowing proofs to propagate across the network.

## Endpoints

### `GET /transpeer`

Discovery and handshake endpoint. This is what scanners probe.

**Response:**
```json
{
  "protocol": "transpeer/1",
  "node_id": "a3f8c912",
  "networks": ["monero", "wownero"],
  "peer_counts": {"monero": 4821, "wownero": 312},
  "uptime": 84600,
  "difficulty": 100
}
```

- `protocol`: Must be `"transpeer/1"` for this version
- `node_id`: Random hex string identifying this node instance
- `networks`: Networks this transpeer participates in
- `peer_counts`: Number of verified peers per network
- `uptime`: Seconds since node start
- `difficulty`: EquiX effort required to publish peer entries

### `GET /peers/{network}`

Retrieve the peer list for a specific network.

**Response:**
```json
{
  "network": "monero",
  "peers": [
    {
      "addr": "203.0.113.42",
      "port": 18080,
      "last_seen": 1713500000,
      "sources": 3,
      "proof": {
        "nonce": "<base64>",
        "effort": 100,
        "solution": "<base64>",
        "timestamp_bucket": 475972
      }
    }
  ]
}
```

- `addr`: IPv4 address of the peer
- `port`: Port the peer's daemon listens on
- `last_seen`: Unix timestamp of last successful verification
- `sources`: Number of independent transpeers that reported this peer
- `proof`: EquiX proof-of-work for this entry

Only verified peers (locally probed and confirmed alive) are served.

### `GET /transpeers`

Retrieve the list of known transpeers.

**Response:**
```json
{
  "transpeers": [
    {
      "addr": "198.51.100.7",
      "port": 7337,
      "networks": ["monero", "bittorrent"],
      "last_seen": 1713500000
    }
  ]
}
```

## Discovery

### IPv4 Scanning

A new transpeer with no known peers generates random non-reserved IPv4 addresses and probes port 7337. If the port is open and responds to `GET /transpeer` with a valid protocol response, it's a transpeer.

Reserved ranges (RFC 1918, loopback, multicast, etc.) are skipped.

### Implicit Self-Announcement

When a node queries any endpoint on a transpeer, the server records the requester's IP address as a "candidate transpeer." The server periodically probes candidates on port 7337. If they respond with a valid `/transpeer` handshake, they're added to the transpeer list.

This means connecting to a transpeer automatically makes you discoverable — no explicit registration needed.

### Transitive Discovery

After finding one transpeer, query its `/transpeers` endpoint to discover more. Each of those can be queried in turn. The network grows organically from a single connection.

## Peer Lifecycle

1. **Received** — Peer entry arrives from another transpeer with PoW proof
2. **Proof verified** — EquiX proof is checked (~50us)
3. **Probed** — TCP connection attempt to peer's daemon port
4. **Verified** — If probe succeeds, peer is marked verified and shared with others
5. **Re-probed** — Periodic re-verification to confirm peer is still alive
6. **Pruned** — Peers with `sources=0` and stale `last_seen` are removed

Only verified peers are served via `/peers/{network}`.

## Network Identifiers

Standardized lowercase strings:

| Network | Identifier | Default P2P Port | Default RPC Port |
|---------|-----------|-------------------|------------------|
| Monero | `monero` | 18080 | 18081 |
| Wownero | `wownero` | 34567 | 34568 |
| Aeon | `aeon` | 11180 | 11181 |

New networks can be added by implementing the network plugin interface.

## Rate Limiting

Transpeer nodes should rate-limit requests per source IP (default: 60 requests per 60 seconds) to prevent abuse as an amplification vector.

## Security Considerations

- **Sybil resistance**: IPv4 address scarcity makes it expensive to run many fake transpeers
- **Spam resistance**: EquiX proof-of-work makes it computationally costly to publish fake peer entries
- **Verification**: Peers are only shared after local TCP probe confirms they're alive
- **No trust required**: All data is verified independently by each transpeer node
- **Pruning**: Stale and unresponsive entries are automatically removed
