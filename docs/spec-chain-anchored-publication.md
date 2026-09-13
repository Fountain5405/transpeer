# Chain-anchored publication of transpeer lists

Specification, draft 0.1, 2026-09-13. Companion to `manuscript.md` §12,
which gives the motivation and the security argument, and to
`defenses-explained.md`, which tells the same story in plain language.

This document describes an extension to the transpeer protocol in which
the lists of transpeers a newcomer bootstraps from are committed to
proof-of-work the newcomer can verify alone, stored by every transpeer,
and served by any of them. Two routes carry the commitment. **Route A**
(§4.2) uses P2Pool's existing merge-mining interface and changes nothing
in Monero, P2Pool or mining software; everything it adds lives in the
transpeer sidecar. **Route B** (§4.4) changes P2Pool's share format so
that every share carries the field, which puts the whole venue's
hashrate behind the published set rather than the participants' share
of it. §4.5 compares them. Everything from §5 on applies to both unless
stated.

Requirement words (MUST, SHOULD, MAY) are used in the RFC 2119 sense.
Facts about P2Pool's interfaces are stated from memory of its source and
documentation and are listed in §15 for verification before
implementation.

## 1. Scope

**Goals.**

- A newcomer with nothing but the software and a release checkpoint can
  obtain a set of transpeer addresses whose weight it can verify against
  proof-of-work, without trusting the node that served them.
- A newcomer that has been shown only an attacker's world can tell, from
  data the attacker cannot forge, that it is in a corner.
- Publishing is open to anyone who mines on P2Pool, at any scale.
- Withholding is detectable per node.
- No address is ever written to a blockchain.

**Non-goals.**

- Replacing the clearnet defenses of `manuscript.md` §6. Those remain the
  default for every network; this extension is an additional anchor for
  networks whose miners carry it.
- Defending against an adversary with a majority of P2Pool's hashrate.
  Such an adversary can publish with the weight its work earns; the
  mining-policy layer (§10) makes that expensive but not impossible.
- Committing daemon peer lists. Only transpeer addresses, which are
  public servers by construction, are ever listed.

## 2. Terminology

| term | meaning |
|---|---|
| anchor chain | the blockchain whose proof-of-work backs commitments; Monero in this document |
| venue | a P2Pool sidechain, identified by its consensus id: main, mini, nano, or any other |
| share | a P2Pool sidechain block; carries the miner's wallet, sidechain links, and a full Monero block template |
| tag | the merge-mining tag in a coinbase transaction's `tx_extra`; a Merkle root over aux hashes |
| aux leaf | one entry of that Merkle tree; one is the venue's share id, one is a transpeer list hash |
| list blob | the canonical byte encoding of a curated list of transpeer addresses (§3.1) |
| commitment | the appearance of a list blob's hash as an aux leaf in a share or an anchor-chain block |
| publisher | the wallet that mined the share or block carrying a commitment |
| window | the span of recent shares or blocks considered for weight and coverage |
| newcomer | a node with no prior knowledge of the network |
| observer | a client that speaks a venue's P2P protocol to read shares without mining |

## 3. Data model

### 3.1 List blob

A list blob is a byte string with this layout. Multi-byte integers are
little-endian.

| offset | size | field |
|---|---|---|
| 0 | 4 | magic `TPL1` |
| 4 | 1 | version, `0x01` |
| 5 | 1 | `n`, length of the anchor-chain name |
| 6 | n | anchor-chain name, UTF-8, e.g. `monero` |
| 6+n | 8 | `created_at`, Unix seconds |
| 14+n | 2 | `count`, number of entries, 1 to 64 |
| 16+n | 6 × count | entries: IPv4 address (4 bytes, network order) then port (2 bytes) |

Canonical form, which a blob MUST satisfy to be valid:

- entries sorted ascending by (address, port) and unique;
- no entry in a reserved range (RFC 1918, loopback, link-local, CGNAT,
  multicast, documentation, benchmarking, `0/8`, `240/4`);
- `count` between 1 and 64 inclusive;
- total length at most 1024 bytes;
- no trailing bytes.

The blob hash is SHA-256 over the blob bytes. Any 32-byte value serves
as an aux leaf, so the choice of hash is the sidecar's; SHA-256 is fixed
here so that every implementation names the same blob by the same hash.
Version 2 will add IPv6 entries; a reader that sees an unknown version
MUST ignore the blob and MUST NOT count its commitment as unavailable.

### 3.2 Commitment record

For each commitment a sidecar has verified it keeps:

| field | content |
|---|---|
| `hash` | the list blob hash |
| `kind` | `share` or `block` |
| `venue` | the sidechain consensus id (for `share`, and for `block` when the block's tag also carries a venue leaf) |
| `ref` | the share id, or the anchor-chain block height and hash |
| `publisher` | the wallet address in the share, or in the block's coinbase |
| `difficulty` | the share difficulty, or the block difficulty |
| `timestamp` | the share or block timestamp |
| `proof` | what is needed to recompute the tag's Merkle root from the leaf: leaf index, sibling hashes, aux-chain count and nonce |

### 3.3 Blob database

Every transpeer keeps a table keyed by blob hash: the blob bytes and the
set of commitment records that reference it. Rows are content-addressed
and self-checking. A row MUST NOT be stored unless at least one
commitment referencing it has been verified (§6); uncommitted blobs are
discarded on arrival. Retention: all rows within the coverage window
(§8) MUST be kept; older rows SHOULD be kept, since they are small and
serve the fallback in §6.7.

## 4. Publishing

### 4.1 Curation

A publisher's list MUST contain only transpeers the publisher's own
sidecar has observed. It SHOULD apply, in order:

1. **History.** The transpeer has answered the publisher's queries over
   at least 14 days (the tried table with an age requirement).
2. **Quality.** The peers it served verified reachable at a rate of at
   least 80 percent (the per-source trust the verifier keeps).
3. **Native.** Its host answered the daemon-port probe for at least one
   network it claims to serve.
4. **Diversity.** At most one entry per `/16`.
5. **Continuity.** Mostly transpeers that appeared in earlier committed
   blobs (§6.7 makes that verifiable), with at most a quarter of the
   entries reserved for transpeers with a clean but short history.
6. **Faithfulness.** No transpeer that has failed availability
   challenges (§9) in the last 7 days.

A list SHOULD change rarely. A publisher SHOULD NOT emit more than one
new blob per day unless an entry has become unreachable.

### 4.2 The aux-chain interface

The sidecar publishes by posing as a merge-mined chain to the
operator's P2Pool node. P2Pool's merge-mining support calls the aux
chain's JSON-RPC interface; the sidecar serves that interface on a local
port and the operator points P2Pool at it. The sidecar:

- answers the chain-id request with the constant
  `SHA-256("transpeer/anchor/v1")`;
- answers the aux-block request with its current list blob hash as the
  aux hash, the blob bytes as the aux blob, and an aux difficulty large
  enough that P2Pool never treats a share as a solution for it;
- accepts and ignores any solution submission.

P2Pool then carries the hash as an aux leaf in every share template the
node builds, and in every Monero block the node finds. The share's
proof-of-work binds the leaf at mining time, so a commitment cannot be
produced after the fact and a publisher cannot equivocate between
readers. Whether P2Pool includes aux leaves whose difficulty is never
met is item 1 in §15.

### 4.3 Availability duty

A publisher MUST serve its own blob from the moment its first share
carrying the commitment is broadcast, and MUST keep serving every blob
it has ever committed. A commitment whose blob cannot be obtained from
the publisher or from any transpeer 10 minutes after the share's
timestamp is *unavailable*; §9 and §10 say what follows.

### 4.4 Route B: a share-format change

Route A has a weakness in early adoption. Weight (§7) is summed only
over shares that carry a transpeer leaf, so the honest weight behind the
published set is the hashrate of miners who run a sidecar. An attacker
does not have to beat the venue; it has to beat the participants, and
while participants are a few percent of the venue that is cheap. Route
B removes the gap by putting the field into every share.

**Field.** A new field in the sidechain section of the share, present
in every share from activation onward:

- `transpeer_list`: a list blob in the canonical form of §3.1, or empty.
  Inline rather than a hash: at most 1024 bytes against shares that
  already carry a full block template, and inline content is stored by
  every P2Pool node for as long as it keeps the share, which solves
  availability for the window without the blob database.

The field is part of the sidechain data hashed into the share id, so it
is bound by the share's proof-of-work exactly as an aux leaf is, and the
sidechain leaf in every Monero block P2Pool finds commits to it
transitively.

**Consensus rules.** Format only: canonical form, size cap, count cap,
empty allowed. Reachability is not a consensus rule because it is not
deterministic; content stays the publisher's assertion and is judged by
§7, §9 and §10 as before.

**Default content.** What makes Route B universal is not the field but
what a node puts in it when no sidecar is present. Two options, and the
first is recommended:

1. **Built-in discovery.** The P2Pool node probes the transpeer port of
   its own P2Pool peers, hosts it is already connected to and that run
   monerod by construction, and lists those that answered over the last
   24 hours, at most one per `/16`. This is the daemon-peer path of
   `manuscript.md` §3, executed by P2Pool itself, and it involves no
   blind scanning. Every miner then publishes a truthful, if small, list
   with no configuration.
2. **Empty unless configured.** The field is empty for nodes without a
   sidecar. Universal format, participant-only content; this is Route A
   with a hard fork, and buys little.

With a sidecar, the node takes the curated list (§4.1) from it through
a local file or RPC, exactly as Route A's aux-chain interface does.

**Weighting under Route B.** Every share contributes its difficulty to
the blobs in its field; empty fields contribute nothing. With built-in
discovery, the honest weight is close to the venue's whole hashrate,
and the threshold in §12 becomes a majority of the venue rather than of
the participants from the first day.

**Activation.** A share-version bump activated at a scheduled timestamp
on every venue, coordinated through a P2Pool release, as the v2 share
format was. Nodes that do not upgrade fork off; that is the normal
P2Pool upgrade path and it needs the maintainer.

**Permanence under Route B.** Inline lists are committed to Monero
blocks only transitively, through the sidechain leaf, so a reader that
wants a commitment provable from a Monero block alone needs the share
and the share-chain segment linking it to the block's sidechain leaf.
Transpeers SHOULD keep those segments for blocks whose lists they
serve, or publishers MAY additionally run Route A's aux leaf for a
direct, share-free proof. §6.7's fallback uses whichever is available.

### 4.5 Comparison

| | Route A: aux leaf | Route B: share field |
|---|---|---|
| change to P2Pool | none; configuration only | share format, validation, template, P2P messages; a sidechain fork |
| who publishes | sidecar operators | every node, by built-in discovery; curated lists where a sidecar exists |
| honest weight | participants' hashrate | the venue's hashrate |
| early-adoption threshold | majority of participants | majority of the venue |
| availability in the window | blob database, gossip, §9 challenges | the sidechain itself; §9 still applies to older blobs |
| permanence in Monero blocks | direct leaf in blocks the publisher finds | transitive through the sidechain leaf; share segments needed for proof |
| privacy | hashes on chain, addresses in blobs | addresses in shares, kept for the window by every P2Pool node, hashes on chain |
| dependency | facts in §15 items 1 to 3 | the maintainer, a release, an activation date |
| time to deploy | as soon as the sidecar exists | one P2Pool release cycle after agreement |

The routes compose. Route A can ship first and serve as the proposal's
proof of concept; Route B is what to ask the maintainer for, with the
built-in discovery default as the argument, since it gives every miner
something truthful to publish at no cost and makes the honest weight
the venue's from day one.

## 5. Transport

Endpoints on the transpeer HTTP port, all free of handshake proof-of-work
since they serve content-addressed data:

- `GET /blob/{hash}` → the blob bytes, or 404.
- `GET /blobs/index?since={unix}` → hashes of blobs first seen after
  `since`, with their commitment records, paged.
- `GET /anchor/{chain}/headers?from={height}` → anchor-chain block
  headers from `from` to the tip, for newcomers (§6.2).
- `GET /anchor/{chain}/coinbase/{height}` → the coinbase transaction
  and its Merkle path for one block (§6.3).
- `GET /venue/{id}/shares?from={share_id}&count={n}` → a segment of the
  venue's canonical share chain as the serving node holds it (§6.5).

Gossip: on each query cycle a transpeer asks each queried transpeer for
`/blobs/index` since its last sync and fetches rows it lacks, verifying
each blob against its hash and each commitment record against §6
before storing it. Anchor-chain data and share segments are served
from the operator's own monerod and P2Pool node; a transpeer without
either MAY relay what it fetched from others, since all of it verifies.

## 6. Verification by a newcomer

### 6.1 Inputs shipped with the software

For each anchor chain: a checkpoint (height, block hash) from the
release, and the chain's proof-of-work and difficulty-adjustment rules.
For each known venue: its consensus id. New venues are discovered from
tags (§6.4) and need no prior knowledge.

### 6.2 Anchor-chain headers

Fetch headers from the checkpoint to the tip from several transpeers.
For every candidate chain: verify that headers link, that each meets
its difficulty, and that difficulty follows the adjustment rule. Keep the
candidate with the greatest cumulative work. A tip whose timestamp is
more than 30 minutes behind local time is stale and MUST NOT be accepted
as the current chain; the newcomer keeps asking.

Proof-of-work MAY be verified on a uniform random sample of at least 5
percent of headers plus every header in the most recent 720, with
linkage and difficulty rules checked on all. An attacker who fakes the
work of enough headers to change the cumulative-work comparison is
caught by the sample with overwhelming probability; faking a few
changes nothing.

### 6.3 Coinbases and tags

For every block in the coverage window (§8), fetch the coinbase and its
Merkle path; verify the path against the header's transaction root.
Parse `tx_extra` for the merge-mining tag. A block with no tag is
*untagged*. A tagged block's tag is a Merkle root; the tag's leaves are
not known until a share or a commitment record supplies them.

### 6.4 Aux leaves and venues

For a tagged block, a leaf is proven by a commitment record's `proof`
(§3.2): recompute the Merkle root from the leaf, the sibling hashes,
the aux-chain count and nonce, and compare with the tag. A venue leaf is
a share id; resolving it means obtaining that share (§6.5). A transpeer
leaf is a blob hash; resolving it means obtaining the blob (§5).

### 6.5 Shares and the canonical fork

For each venue whose share ids appear in resolved tags, fetch the share
chain back through the weight window (§7) from any observer or
transpeer. Verify each share: its proof-of-work meets its sidechain
difficulty, its parent link is consistent, and its transpeer leaf, if
present, is proven as in §6.4. The **canonical fork** of a venue is the
chain containing the share id referenced by the most recent resolved
tagged block for that venue; shares that are not ancestors of that share
carry no weight. This is what stops a private fork of a real venue from
passing as the real one.

### 6.6 Freshness

Weight (§7) is computed only over shares and blocks within their
windows, and the current-chain rule of §6.2 already rejects stale
worlds. A newcomer MUST NOT bootstrap from blobs alone without a
current anchor chain.

### 6.7 Fallback to permanent commitments

If the newcomer cannot resolve the venues needed to meet the coverage
rule (§8), it MAY use blobs committed in anchor-chain blocks older than
the window, newest first, weighted by block count, as a starting set,
while continuing to seek current data. Entries in old blobs are expected
to be partly dead; the newcomer verifies reachability before use.

## 7. Weighting

Let `W` be the weight window: 24 hours of a venue's canonical shares.

- **Share weight** `w(s)` is the share's verified difficulty.
- **Blob weight** `w(b)` is the sum of `w(s)` over canonical shares in
  `W` whose transpeer leaf is `hash(b)`.
- **Publisher weight** is the sum of `w(b)` over the publisher's blobs;
  it is reported for diagnostics and is not used for ranking, since a
  publisher may split work across wallets without changing the sum.
- **Transpeer weight** `w(t)` is the sum of `w(b)` over blobs listing
  `t`. A blob vouches fully for each of its entries, as a reporter
  vouches for each peer in `manuscript.md` §6.

Venues are additive: a transpeer's weight is summed across every venue
resolved. There MUST NOT be any per-venue quota or normalisation. A
venue an attacker creates and mines alone is worth exactly the
attacker's work, which is what it would have been worth on a public
venue. Anchor-chain block commitments are not added to `w(t)`; they are
permanence and fallback (§6.7), and the yardstick (§8).

The newcomer's transpeer store is seeded with the highest-weight
transpeers, tagged *published*. Transpeers learned by scanning, gossip
or self-announcement are tagged *unpublished*; under this extension the
hand-off ranking (`manuscript.md` §6) counts vouchers from published
reporters first, unpublished second, and the reserve pass ranks
published clusters first.

## 8. The yardstick and the coverage rule

Let the coverage window be the anchor chain's last 7 days. Let `T` be
its tagged blocks and `R ⊆ T` the tagged blocks whose venue leaf the
newcomer resolved to a share on a venue whose canonical fork and blobs
it obtained. Coverage is `|R| / |T|`.

- If coverage is at least 0.5, the newcomer is **bootstrapped**: it has
  seen venues accounting for at least half of the real mining that
  publishes.
- Otherwise it is **in a corner**: whatever it has been shown accounts
  for less than half of the work on the anchor chain, and it MUST keep
  discovering (scanning, asking every known transpeer for the missing
  venues' data) until coverage is met. It MAY use what it has as a
  provisional set in the meantime, marked provisional to the daemon
  hand-off.

Unresolved tags are counted in `T` and not in `R`; an attacker cannot
raise coverage without finding anchor-chain blocks, and cannot lower an
honest newcomer's coverage except by withholding, which §9 attributes.

**Scan-stop.** Where an anchor chain is configured, the scanner's stop
condition (`--scan-target-known`) is replaced by *coverage met*. On
networks without an anchor the live-count rule stays.

## 9. Faithfulness challenges

Every transpeer is expected to serve every committed blob in the
coverage window. Any node MAY challenge any transpeer:

- Sample up to 8 hashes per transpeer per hour, uniformly from
  commitments the challenger has verified, older than 10 minutes.
- A challenge fails if the transpeer returns 404 or bytes that do not
  hash to the requested value.
- Three failures in 24 hours mark the transpeer **unfaithful**: it is
  ranked last in the hand-off and evicted first when the store is full.
  Twenty-four hours without a failure clears the mark.
- A hash that every challenged transpeer fails is treated as **lost**,
  not as evidence against any of them; the challenger stops using it.
- A transpeer whose `/transpeer` uptime is under 10 minutes is not
  challenged; it is syncing.

## 10. Mining-policy layer (optional)

A P2Pool node whose operator runs a transpeer sidecar MAY apply a
stricter validity rule to shares, so that publishing garbage forfeits
the publisher's reward. This is a miner policy, not a consensus rule:
nodes that do not apply it still accept the chain the policy produces.

- **No commitment, no judgement.** A share without a transpeer leaf is
  never penalised.
- **Verdict on a blob**, computed by the sidecar in the background:
  *bad* if fewer than half the entries are known-good in the sidecar's
  own store (seen answering within 7 days) or, for unknown entries,
  fail a probe with three attempts over 10 minutes; *bad* if the blob is
  unavailable 10 minutes after the share's timestamp; *bad* if the
  publisher has committed more than 6 distinct blobs in 24 hours.
  Verdicts are cached by blob hash for 6 hours. Live probing of
  known-good entries is forbidden, so that thousands of miners do not
  probe every listed transpeer every ten seconds.
- **Optimistic acceptance.** A share whose blob has no verdict yet is
  built on. A miner must choose a tip within seconds and a verdict takes
  minutes.
- **Penalty.** Once a publisher has a bad verdict, the node does not
  build on that wallet's shares, and does not reference them as uncles,
  for 24 hours. With an aware majority of a venue's hashrate, those
  shares are orphaned and the wallet loses its PPLNS reward.

The layer only bites once aware miners hold a majority of a venue's
hashrate. Below that it is a filter; §7 and §8 carry the newcomer
regardless.

## 11. Privacy

The anchor chain holds hashes only. Blobs hold transpeer addresses,
which are public servers already, and never daemon peer addresses.
Blobs live in transpeer databases and may be dropped after the window;
the permanence is of the commitment, not of any address. A publisher's
wallet address is already public in every share it mines; this
extension adds nothing to that exposure.

## 12. Security considerations

| adversary | what happens |
|---|---|
| Sybil with many addresses, no mining | cannot publish; its addresses reach a newcomer only as unpublished entries, ranked second |
| Many prefixes, no mining | same; prefixes buy nothing here |
| Private venue mined with the attacker's own hashrate | its blobs carry exactly the attacker's work; the yardstick shows the newcomer that the venue accounts for a sliver of tagged blocks |
| A world of attacker nodes serving only the attacker's venue | coverage fails; the newcomer knows it is in a corner and keeps discovering |
| Withholding public blobs or shares while showing the real chain | unresolved tags keep coverage low; challenges mark the withholders unfaithful |
| Stale tip | rejected by the freshness rule |
| Private fork of a real venue | not canonical; no weight |
| Publishing garbage from an honest-sized wallet | weight equals the wallet's work; under §10, the wallet loses its reward |
| Majority of a venue's hashrate | can dominate that venue's commitments; must also dominate the anchor chain's tagged blocks to pass coverage alone, which is a majority of all P2Pool hashrate |
| Majority of the anchor chain's hashrate | out of scope; can corral the chain itself |

Residual risks: liveness (an attacker who is the newcomer's whole view
can delay it, not mislead it); the header-verification sample (§6.2)
trades a small probability of missing a large forgery for bootstrap
time; and the policy layer's verdicts are heuristics that can misfire on
a genuinely flaky honest list, which the tolerances are set to make
rare.

## 13. Sizes and performance

| item | size or cost |
|---|---|
| list blob | ≤ 1024 bytes, typically ~140 for 20 entries |
| blob database, one week | a few megabytes |
| anchor headers, one year old checkpoint | ~26 MB, ~260k headers; proof-of-work sample per §6.2 |
| coinbases, one week | ~10 MB, dominated by P2Pool payout transactions |
| share chain, 24 hours per venue | ~8600 shares; parsing and one RandomX verification each |
| challenge traffic | ≤ 8 small requests per transpeer per hour |

## 14. Compatibility and versioning

Route A: no change to Monero consensus, monerod, P2Pool, or mining
software. Route B: a P2Pool sidechain fork (§4.4); still no change to
Monero or to mining software. Under both, transpeer changes are: the
aux-chain RPC server (§4.2) or the list file for Route B, the blob database
and endpoints (§5), an observer client for each venue (§6.5), anchor
header and coinbase verification (§6.2, §6.3), weighting and coverage
(§7, §8), challenges (§9), and optionally the policy hook (§10). Every
piece is behind a flag that defaults off, in keeping with
`manuscript.md`'s rule that existing behaviour is unchanged unless
asked for.

Blob version is the byte at offset 4. Readers ignore unknown versions.
The chain id constant changes only with an incompatible blob format.

## 15. Items to verify against P2Pool before implementation

1. Whether P2Pool includes an aux leaf in the tag when the aux chain's
   difficulty is never met, or only tracks solutions for it.
2. The exact names and parameters of the merge-mining RPC methods and
   the aux-block response fields.
3. The maximum number of aux chains per node, and how the leaf index
   and nonce are derived and exposed, which determines what `proof`
   (§3.2) must contain.
4. The observer protocol: handshake and its anti-abuse proof-of-work,
   peer-list request, share broadcast and request messages, and share
   serialisation, for each of main, mini and nano.
5. Share retention on P2Pool nodes, which bounds how far back §6.5 can
   fetch without transpeer relays.
6. P2Pool's current share of Monero's hashrate, which sets the price in
   §12.
7. The encoding of the merge-mining tag in `tx_extra` and whether any
   non-P2Pool software emits it on Monero today.
8. For Route B: how the share format is versioned and activated, the
   size limits on sidechain data, and whether P2Pool nodes would accept
   a built-in probe of their peers' transpeer port as default behaviour.

## 16. Test plan

- Property tests for §3.1 canonicalisation and hashing, §6.4 Merkle
  recomputation, and §7 weighting on synthetic shares.
- A Shadow experiment with a **venue oracle** process standing in for
  P2Pool: it emits shares with commitments at rates proportional to
  configured hashrates, simulated proof-of-work, and an attacker share
  `q`; the fresh node runs the newcomer path and the metrics are the
  published-store composition, coverage, and daemon hand-off share
  against `q`, at the honest and attacker prefix counts of the existing
  grid. The expected result is a crossover in `q` near one half and
  independence from prefix count.
- An integration test against a real P2Pool node on a private testnet
  venue, exercising §4.2 and §6.5 end to end, once §15 is settled.
