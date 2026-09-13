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
record is [docs/manuscript.md](docs/manuscript.md).


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
