# transpeer

Oh, whattaya know?!?! MORE BASH! 

This time I actually think there's a reason besides my inability to learn C++... 
this makes it relatively easy to run with a bunch of other daemons as an overlay thing maybe. 
Cross compatability, because all you gotta do is write a bash script to dump a daemons p2p list to a file. 

[A narrative was provided here](https://old.reddit.com/r/Monero/comments/f6y8xn/ccs_idea_maybe_someone_can_write_it_up/)

But basically, we create a common protocol for p2p networks to share their IP lists with each other,
such that a brute force of IP space is more likely to yield a connection that can provide IP lists of potential peers. 

The Sybil and eclipse defenses (bucketing, vouchers, tried table, hand-off
reserve, native vouchers) are explained with an analogy in
[docs/defenses-explained.md](docs/defenses-explained.md); the measured
record is [docs/manuscript.md](docs/manuscript.md). A proposed extension
that anchors published transpeer lists to P2Pool's proof-of-work, with
no change to Monero or P2Pool, is specified in
[docs/spec-chain-anchored-publication.md](docs/spec-chain-anchored-publication.md)
and argued in the manuscript's §12.


## Scanning etiquette and blocklist risk

A node that knows nobody finds the network by probing random IPv4
addresses on port 7337. Blind scanning is exactly what intrusion sensors,
abuse databases and hosting providers' acceptable-use policies react to,
so the scanner is built to be a bootstrap mechanism, not a steady state:

- **Cold only.** Blind scanning runs at `--scan-rate` probes per second
  (default 4, paced with jitter rather than in bursts) until
  `--scan-target-known` transpeers (default 3) have answered a query, then
  stops (`--scan-idle-rate`, default 0). Discovery continues through
  gossip, through nodes that contact this one, and through the local
  daemon's own peers, which are probed on the transpeer port because they
  are already in a P2P relationship with us. If the live count drops back
  below the target, scanning resumes on its own.
- **Exclusions.** Reserved ranges and the US DoD `/8`s are never
  blind-scanned. `--scan-exclude FILE` adds your own list; see
  `docs/scan-exclude.example`. An explicit `--scan-range` is not filtered.
- **Identification.** Every HTTP request carries a User-Agent naming the
  protocol, the project URL and, if `--contact` is set, an opt-out
  address. `GET /` on port 7337 explains what the probe was and how to opt
  out, for anyone who looks up the address that touched them.
- **No-scan mode.** `--no-scan` never blind-scans. Use it on residential
  lines and on hosts whose provider forbids scanning; the node then needs
  at least one reachable transpeer from gossip, a candidate, or its
  daemon's peers.
- **Legacy profile.** `--scan-legacy` restores bursts of 500 probes every
  10 s with no backoff. Simulations use it so results stay comparable; do
  not run it on the public internet.

Expect some reports anyway. A single TCP connect to a monitored host is
enough for an automated complaint, and no rate is low enough for every
sensor. Set `--contact`, answer complaints, and keep the exclude list.

## Publishing through P2Pool

With `--anchor-publish` (default off; nothing changes without it) the
node runs a small JSON-RPC server that P2Pool treats as a merge-mined
chain. The node's curated transpeer list (a blob of at most 64
addresses) is hashed, and the hash rides as an aux leaf in every share
the P2Pool node builds and in every Monero block it finds. Start
P2Pool with `--merge-mine 127.0.0.1:7338 <WALLET>`.

- **Aux RPC.** `--aux-rpc-bind` sets the interface the aux server
  listens on and `--aux-rpc-port` (default 7338) the port; `--aux-diff`
  is the difficulty reported to P2Pool, which decides when to call
  `submit_solution` — the sidecar does not verify share difficulty
  itself. The aux-chain RPC trusts whatever calls it, so leave
  `--aux-rpc-bind` on its loopback default or firewall it to your own
  P2Pool node.
- **Anchor policy.** `--anchor-chain` selects the target chain (default
  `monero`); `--anchor-min-age` (default 14 days) and `--anchor-max-new`
  (default 0.25) bound how much of a published list can be recently
  added.
- **Blob endpoints.** The blob is served at `/blob/{hash}` and indexed
  at `/blobs/index`. See "Reading the anchor" below for the newcomer
  path that consumes these commitments.

## Reading the anchor

With `--anchor-read` (default off) the node runs the newcomer path: it
verifies the Monero chain from a shipped checkpoint, resolves the
merge-mining tags in that chain to P2Pool shares and the transpeer-list
blobs they commit to, weights transpeers by the difficulty of the
shares that vouch for them, and seeds its store with the result,
marking those entries `published`. It then challenges other transpeers
for the blobs and shares it has not yet verified, gossiping fetched
commitments the same way `/transpeers` results are gossiped. Under
this flag, blind scanning stops on coverage (resolved shares over
tagged anchor-chain blocks) reaching 0.5, not on the live transpeer
count.

| Flag | Default | Meaning |
| --- | --- | --- |
| `--anchor-read` | off | Run the reader. Requires `--anchor-checkpoint`. |
| `--anchor-checkpoint HEIGHT:HASH` | none | Trusted anchor-chain block shipped with a release. Required by `--anchor-read`. |
| `--anchor-sim-pow` | off | Simulation only: SHA-256 in place of RandomX for anchor-chain and share proof-of-work. |
| `--anchor-venues` | empty (main, mini, nano) | Comma-separated venue names or 64-hex consensus ids to read shares from. |
| `--anchor-window-days` | 7 | Coverage window: the anchor chain's last N days (spec §8). |
| `--anchor-monerod URL` | empty | monerod JSON-RPC URL to fill the anchor store from directly. Requires `--anchor-read`. |
| `--anchor-observe HOST:PORT,...` | empty | P2Pool nodes to fill share stores from through the observer client (also accepts `name@host:port`). Requires `--anchor-read`. |

The checkpoint is `HEIGHT:HASH`: a block height and its hex block
hash on the Monero chain. A source whose tip is below the checkpoint,
or more than 400000 blocks past it (about a year and a half of blocks),
is ignored, so ship a fresh checkpoint with each release: one older than
that bound stops the reader from following any chain.
`--anchor-sim-pow` is simulation-only; without
it the reader requires a RandomX binding at start-up and refuses to run
otherwise. `--anchor-monerod` and `--anchor-observe` are built to
monerod's documented RPC and to P2Pool v4.18's source, but are
unverified against real daemons.

The node also answers `GET /venues` with the consensus ids of the
venues it holds shares for, so a reader can resolve a merge-mining tag
for a venue it was not configured with, and serve that venue onward.

Under `--anchor-read` the node writes `anchor_chain.json` (the verified
header chain) and `anchor_blobs.json` (transpeer-list blobs, shared with
the publisher) directly under `data_dir`, and per-venue raw shares
under `data_dir/venues/<hex>/`.

**Tests.** `python tests/test_anchor_read.py` (171 passed),
`python tests/test_anchor.py` (106 passed),
`python tests/test_anchor_publish.py` (118 passed),
`python tests/test_bucketed.py` (47 passed),
`python tests/test_two_nodes.py` (24 passed),
`python tests/test_scanner.py` (19 passed).

See
[docs/spec-chain-anchored-publication.md](docs/spec-chain-anchored-publication.md)
for the protocol.
