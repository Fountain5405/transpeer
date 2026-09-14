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
| 6+n | 8 | `period`, the 25-minute period index `floor(unix_seconds / 1500)` at which this blob was issued |
| 14+n | 2 | `count`, number of entries, 1 to 64 |
| 16+n | 6 × count | entries: IPv4 address (4 bytes, network order) then port (2 bytes) |

The `period` field exists because of a verified P2Pool behaviour (§4.2):
the merge-mining client drops a chain whose aux hash has not changed
for 1800 seconds. A publisher therefore reissues its blob every period
with only `period` changed, so the hash rotates while the list does
not. The *list body* is the blob with `period` zeroed; two blobs with
the same list body publish the same list. Storage, churn rules and
challenges are defined over list bodies where that matters (§3.3, §9,
§10).

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
| `proof` | for `block`: the sibling hashes from the tag's Merkle tree; the slot, aux-chain count and nonce are recomputed from the chain id and the tag (§6.4). For `share`: empty, because the share's own sidechain data carries the aux hash explicitly (§6.5) |

A fourth kind, `template`, is recorded only by a publisher, from
P2Pool's `merge_mining_submit_solution`: the proof is against the tag
in the Monero block template P2Pool was mining, before the share or
block that carries it has been observed. Template records carry no
weight (§7) and are upgraded to `share` or `block` when the reader
resolves the corresponding share or block.

### 3.3 Blob database

Every transpeer keeps a table keyed by blob hash: the blob bytes and the
set of commitment records that reference it. Rows are content-addressed
and self-checking. A row MUST NOT be stored unless at least one
commitment referencing it has been verified (§6); uncommitted blobs are
discarded on arrival. Because a publisher reissues its blob every
period (§3.1), implementations MUST store each distinct list body once
and reconstruct a period's blob from the body and the period on demand,
so that a publisher costs about one body plus eight bytes per period
rather than a full blob per period. Retention: all rows within the
coverage window (§8) MUST be kept; older rows SHOULD be kept, since
they are small and serve the fallback in §6.7.

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
new list body per day unless an entry has become unreachable; the
period-driven reissue of the same body (§3.1) does not count.

### 4.2 The aux-chain interface

The sidecar publishes by posing as a merge-mined chain to the
operator's P2Pool node, through the interface P2Pool documents in
`docs/MERGE_MINING.MD` and implements in
`merge_mining_client_json_rpc.cpp` (verified against v4.18). P2Pool is
pointed at the sidecar with `--merge-mine IP:port WALLET_ADDRESS`
(HTTPS with certificate pinning optional), and there is no limit on the
number of merge-mined chains beyond the fifteen or so that the Merkle
slot assignment can hold. P2Pool polls the aux-block method every 500
milliseconds. The interface is JSON-RPC over HTTP POST, three methods:

- `merge_mining_get_chain_id`: the sidecar answers with `chain_id`, the
  constant `SHA-256("transpeer/anchor/v1")` in hex, and MAY add
  `ticker` `"TPL"`.
- `merge_mining_get_aux_block`, sent with `address`, the current
  `aux_hash`, the Monero `height` and `prev_id`: the sidecar answers with
  `aux_hash` (the list blob hash), `aux_blob` (the blob bytes, opaque to
  P2Pool), and `aux_diff`. An empty result, or the same `aux_hash` as in
  the request, means "unchanged", which makes polling cheap. P2Pool
  records the time of the last *change* of `aux_hash` and drops a chain
  whose hash has not changed for 1800 seconds, or whose difficulty is
  zero (verified: `last_updated` is set only in the changed branch of
  `parse_merge_mining_get_aux_block`, and `get_params` compares it with
  `EXPIRE_TIME`). The sidecar therefore MUST set a nonzero difficulty
  and MUST change `aux_hash` at least every 1800 seconds; the `period`
  field of §3.1 does that every 1500 seconds without changing the list.
- `merge_mining_submit_solution`, sent by P2Pool with `aux_blob`,
  `aux_hash`, the Monero block template `blob`, the `merkle_proof`
  (sibling hashes), the `path` bitmap and the RandomX `seed_hash`
  whenever a share's proof-of-work meets `aux_diff`: the sidecar answers
  `{"status":"accepted"}` and stores the proof.

**Difficulty strategy.** Set `aux_diff` to the venue's minimum share
difficulty, so that every share the node finds is reported to the
sidecar with its Merkle proof. That is how the sidecar learns the
`proof` field of §3.2 for the Monero blocks it finds, since a found
block is one of those shares, and it costs nothing: the "solution" is
the miner's own share. A high difficulty would keep the leaf in every
template (the leaf is included whenever the chain's parameters are
fresh, whether or not any share meets its difficulty) but would leave
the sidecar without proofs.

P2Pool then carries the hash as an aux leaf in every share template the
node builds, and in every Monero block the node finds; each share's
sidechain data also lists the chain id, the aux hash and the difficulty
explicitly (§6.5). The share's proof-of-work binds the hash at mining
time, so a commitment cannot be produced after the fact and a publisher
cannot equivocate between readers.

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

### 4.6 Route C: a donated aux job (exists, maintainer-controlled)

P2Pool v4.18 contains, behind the compile-time flag
`WITH_MERGE_MINING_DONATION` and TLS, an `AUX_JOB_DONATION` P2P message:
a set of aux jobs (chain id, aux hash, difficulty) signed with the
P2Pool author's key, verified by every receiving node against that key,
rebroadcast, and added to the receiving node's own templates for 1800
seconds after the last refresh (`p2pool::update_aux_data`,
`set_aux_job_donation`). The donor's node then treats every share on
the venue as a candidate solution for its chain (`on_external_block`).
This is how the author can have the whole venue merge-mine one job.

For this proposal it is a third route with a different shape: one aux
job, hence one list, carried by every share in the venue, with the
venue's whole hashrate behind it and no fork, but only the holder of
the donation key can publish it. That is a maintainer-curated anchor
list, distributed with proof-of-work and verifiable by a newcomer, and
it is a legitimate design where a project is willing to have the P2Pool
maintainer, or a build with a different key, curate its seed list. It
is not the many-publishers design of Routes A and B, and the two can
coexist: the donated job as the floor everyone carries, per-miner lists
on top.

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
Parse `tx_extra` for the merge-mining tag, whose layout (P2Pool
`docs/MERGE_MINING.MD`, verified against v4.18) is: one byte `0x03`;
one byte length; a varint of *Merkle tree parameters* packing
`n_aux_chains` and a 32-bit `aux_nonce` (bits 0–2 give the width of the
count field, the count follows, then the nonce, the rest reserved); and
the 32-byte Merkle root. `n_aux_chains` counts the P2Pool sidechain
itself plus every merge-mined chain. A block with no tag is *untagged*.
A tagged block's leaves are not known until a share or a commitment
record supplies them.

### 6.4 Aux leaves and venues

For a tagged block, a leaf is proven by a commitment record's `proof`
(§3.2). The leaf's slot is `SHA-256(chain_id | aux_nonce | 'm') mod
n_aux_chains`, with the transpeer chain id fixed by §4.2 and the venue's
chain id being its consensus id; `aux_nonce` and `n_aux_chains` come
from the tag. The tree is built over the leaves in slot order with
Keccak-256 over the concatenation of each pair, after a first step
that, when the leaf count is not a power of two, pairs leaves from the
end of the list until it is. The proof is verified by recomputing the
root from the leaf, the sibling hashes and the slot and comparing with
the tag (P2Pool `merkle.cpp`, `verify_merkle_proof`). A venue leaf is a
share id; resolving it means obtaining that share (§6.5). A transpeer
leaf is a blob hash; resolving it means obtaining the blob (§5).

### 6.5 Shares and the canonical fork

For each venue whose share ids appear in resolved tags, fetch the share
chain back through the weight window (§7) from any observer or
transpeer. A share's sidechain data (P2Pool `PoolBlock`, verified
against v4.18) carries the miner's wallet keys, the parent and uncle
ids, the sidechain height, difficulty and cumulative difficulty, the
Merkle tree parameters and root, and a map from each merge-mined chain
id to that chain's aux hash and difficulty. The share id is the hash of
this data, so a transpeer commitment is read directly from the map and
is bound by the share's proof-of-work with no Merkle proof. Verify each
share: its proof-of-work over its hashing blob meets its sidechain
difficulty, its parent link is consistent, and its map entry for the
transpeer chain id, if present, names a blob. The **canonical fork** of
a venue is the chain containing the share id referenced by the most
recent resolved tagged block for that venue; shares that are not
ancestors of that share carry no weight. This is what stops a private
fork of a real venue from passing as the real one.

**The observer protocol**, verified against v4.18: default P2P ports
37889 (main), 37888 (mini) and 37890 (nano); a connecting peer must
answer a handshake challenge with a Keccak preimage over the challenge,
the consensus id and a salt whose last word times 10000 does not
overflow 64 bits, about ten thousand hashes; message ids include
`PEER_LIST_REQUEST` and `PEER_LIST_RESPONSE` (at most 16 peers per
reply, rate-limited per peer, private and loopback addresses filtered),
`BLOCK_REQUEST`, `BLOCK_RESPONSE`, `BLOCK_BROADCAST`,
`BLOCK_BROADCAST_COMPACT` and `BLOCK_NOTIFY`. Share serialisation is in
`pool_block_parser.inl`. Walking a venue's overlay is therefore many
small peer-list requests over time rather than one bulk fetch.

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

Let `W` be the weight window: the venue's PPLNS window, up to 2160
canonical shares, about six hours on main and mini at ten seconds per
share and about eighteen on nano at thirty. P2Pool nodes keep shares
for roughly twice the window before pruning, about twelve hours on
main (verified against v4.18: prune distance twice the window plus the
uncle depth, or four windows by age, whichever comes first), so a
transpeer that wants a longer window archives shares itself.

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
  publisher has committed more than 6 distinct list bodies (§3.1) in 24
  hours; period reissues of one body do not count.
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
| Majority of the anchor chain's hashrate | out of scope; can corral the chain itself. Not hypothetical: in August 2025 the Qubic project claimed a majority of Monero's hashrate and produced reorganisations reported at 6 and 18 blocks deep. During such an episode the tip is contested and the set of tagged blocks is shaped by whoever mines; the newcomer's freshness and cumulative-work rules still pick the chain the majority extends, which is the best any chain-anchored design can do. The clearnet defenses of `manuscript.md` §6 do not depend on the chain and keep working throughout |

Residual risks: liveness (an attacker who is the newcomer's whole view
can delay it, not mislead it); the header-verification sample (§6.2)
trades a small probability of missing a large forgery for bootstrap
time; and the policy layer's verdicts are heuristics that can misfire on
a genuinely flaky honest list, which the tolerances are set to make
rare.

**The price in hashrate, measured 2026-09-13** from the three observers'
`pool_info` (sidechain difficulty over block time against Monero
difficulty over 120 s): main 393 MH/s, 6.65 % of a 5.9 GH/s network;
mini 25 MH/s, 0.42 %; nano 4.2 MH/s, 0.07 %; about 7.1 % together, down
from a reported peak above 18 % in May 2025. Wallets in the windows:
about 11,000 on main, 33,000 on mini, 5,500 on nano. Holding half of
P2Pool's work is therefore about 210 MH/s, on the order of ten to twenty
thousand current CPUs running continuously, and the corral collapses
when they stop. The figure moves with adoption and should be re-read
from the observers when quoted.

The aux-chain RPC (§4.2) is a trusted-caller interface: the sidecar
verifies that a submitted template's tag commits to its aux hash but
cannot verify the block's proof-of-work without RandomX and chain
state, which the reader path (§6) supplies; implementations bound the
records a caller can create and SHOULD bind the RPC to loopback.

## 13. Sizes and performance

| item | size or cost |
|---|---|
| list blob | ≤ 1024 bytes, typically ~140 for 20 entries |
| blob database, one week | one body per publisher per list version plus 8 bytes per 25-minute period: about 4 KB per publisher-week, so 40 MB if every one of P2Pool main's ~11,000 wallets published |
| anchor headers, one year old checkpoint | ~26 MB, ~260k headers; proof-of-work sample per §6.2 |
| coinbases, one week | ~10 MB, dominated by P2Pool payout transactions |
| share chain, one PPLNS window per venue | up to 2160 shares; parsing and one RandomX verification each |
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

## 15. Verification status

Checked on 2026-09-13 against the P2Pool source at v4.18 (commit
`9bac5bd`) and the three observers' `pool_info`. Draft 0.1 listed these
as assumptions; the text above was corrected where they were wrong.

1. **Aux leaf inclusion: verified, with a wrinkle.** A chain is included
   in every template whenever `get_params` succeeds, which requires a
   nonzero difficulty and parameters younger than `EXPIRE_TIME` = 1800 s
   (`merge_mining_client.h`, `merge_mining_client_json_rpc.cpp`,
   `block_template.cpp`); meeting the difficulty only governs
   `merge_mining_submit_solution`. The wrinkle: `last_updated` is set
   only when `aux_hash` changes, so an unchanged job expires after 30
   minutes. Hence the `period` field (§3.1) and the rotation rule
   (§4.2). Re-check `get_params` before relying on the exact expiry.
2. **RPC names and fields: verified** against `docs/MERGE_MINING.MD` and
   the client: `merge_mining_get_chain_id`, `merge_mining_get_aux_block`
   (`address`, `aux_hash`, `height`, `prev_id` → `aux_blob`, `aux_diff`,
   `aux_hash`, optional `aux_height`/`aux_reward`/`aux_fees`; empty or
   same-hash result means unchanged), `merge_mining_submit_solution`
   (`aux_blob`, `aux_hash`, `blob`, `merkle_proof`, `path`, `seed_hash`
   → `status`). Polling every 500 ms. Option `--merge-mine`.
3. **Aux chains and proofs: verified.** No configured limit; the slot
   assignment `SHA-256(id | nonce | 'm') mod n` with a brute-forced
   nonce holds about 15 to 16 chains (`merkle.cpp`, `get_aux_slot`,
   `find_aux_nonce`). `n_aux_chains` and `aux_nonce` are in the tag's
   Merkle tree parameters, so a block-only verifier has them (§6.3);
   the sibling hashes come to the sidecar in `submit_solution`, which is
   why §4.2 sets a low difficulty. Shares also carry each chain's aux
   hash explicitly in `m_mergeMiningExtra` (`pool_block.h`), so
   share-level commitments need no proof (§6.5).
4. **Observer protocol: verified** (`p2p_server.h`, `p2p_server.cpp`):
   ports 37889/37888/37890; handshake challenge with Keccak and
   `CHALLENGE_DIFFICULTY` = 10000 for the connecting side; `MessageId`
   enum with `PEER_LIST_REQUEST`/`RESPONSE` (16 peers per reply,
   rate-limited, filtered), `BLOCK_REQUEST`/`RESPONSE`/`BROADCAST`/
   `BROADCAST_COMPACT`/`NOTIFY`; serialisation in `pool_block_parser.inl`.
5. **Retention: verified.** Pruned beyond `2 × (window − 1) + 2 ×
   UNCLE_BLOCK_DEPTH(3) + 120 / block_time + 1` shares, about 4337 on
   main (≈ 12 h), or beyond four windows by age (`side_chain.cpp`,
   `prune_old_blocks`). Window up to 2160 shares, `MAX_PPLNS_WINDOW_HOURS`
   = 30. §7's window was reduced to the PPLNS window accordingly.
6. **Hashrate: measured** (§12): main 6.65 %, mini 0.42 %, nano 0.07 %
   of 5.9 GH/s; ~11,000 / 33,000 / 5,500 wallets in the windows.
7. **Tag encoding: verified** (§6.3). Whether non-P2Pool software emits
   the tag on Monero today is still unknown; the coverage rule treats
   every tag as a venue, so a foreign tag counts as an unresolvable
   venue and lowers coverage slightly rather than breaking anything.
8. **Route B activation: partly verified.** Share versions are activated
   by timestamp in the consensus parameters (v2 at 1679173200, v3 at
   1728763200 on main); the sidechain data already has a 16-byte
   `m_sidechainExtraBuf` (used by convention for software id and
   version) and the per-chain `m_mergeMiningExtra` map with a fixed
   entry format, so a Route B field would be a new entry in the
   serialiser. Whether nodes would accept a built-in peer probe as
   default behaviour is a question for the maintainer, not the code.
9. **New: the donation route (§4.6) exists** behind
   `WITH_MERGE_MINING_DONATION`, signed with the author's key,
   undocumented in `COMMAND_LINE.MD`, enabled on the sending side with
   `--adkf`.

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
  venue, exercising §4.2 and §6.5 end to end: the sidecar as a
  `--merge-mine` target, the 500 ms poll, the 30-minute expiry and the
  period rotation, a low `aux_diff` producing `submit_solution` calls
  with proofs, and the observer handshake and peer-list walk.

## 17. Implementation notes

Decided on 2026-09-13 when the build started. These are engineering
choices about how the specification is realised and tested; the
protocol above is unchanged by them.

**Build order.** Four slices, each behind flags that default off, each
mergeable on its own:

1. `transpeer/anchor/`: the list blob (§3.1), the P2Pool Merkle tree
   and proof check (§6.4), commitment records and the blob database
   (§3.2, §3.3), weighting (§7) and coverage (§8). Pure code, property
   tests, no I/O.
2. The publisher: the aux-chain JSON-RPC server (§4.2), curation from
   the peer store (§4.1), period rotation, and `/blob/{hash}` and
   `/blobs/index` on the transpeer port (§5).
3. The reader: the newcomer path (§6), blob gossip (§5), the observer
   client (§6.5), challenges (§9), and the published/unpublished tags
   in the hand-off ranking (§7).
4. The Shadow experiment of §16 with a venue oracle.

**What Shadow can and cannot test.** Shadow runs the sidecar unchanged
against a Python *venue oracle* in place of a P2Pool node. The oracle
speaks P2Pool's client side of §4.2 to the sidecar (the 500 ms poll,
the 1800 s expiry, `submit_solution` with a Merkle proof), mints shares
that carry the committed hashes at rates proportional to configured
hashrates, and mints anchor-chain blocks with merge-mining tags. It
serves the §5 anchor and venue endpoints as a transpeer with a monerod
and a P2Pool node would. P2Pool itself and monerod do not run in
Shadow: both need RandomX with a 2 GB dataset per host, and P2Pool
needs a monerod for templates and ZMQ notifications.

**Simulated proof-of-work.** Under a sim-only flag the RandomX check of
§6.2 and §6.5 is replaced by SHA-256 over the same hashing blob against
the same difficulty rule. The verifier code path is the production one
with the hash function swapped; the oracle mines by the same rule at a
difficulty that a Python process meets in milliseconds. Nothing else in
verification is stubbed: Merkle proofs, tag parsing, linkage, the
canonical-fork rule and weighting all run as written.

**What only a real P2Pool node can test**, on Monero testnet after
slice 2: P2Pool's actual poll cadence and expiry against the sidecar,
the exact serialisation of `merge_mining_submit_solution`, the
observer handshake and peer-list walk, and share parsing from
`pool_block_parser.inl`. Whether P2Pool accepts monerod's `--regtest`
mode, which would make this test take minutes rather than a testnet
sync, is unverified.

**Byte-level fixtures.** Slice 1 pins the aux-slot and tree-parameter
vectors from P2Pool's `tests/src/merkle_tests.cpp` at v4.18 and the
Merkle algorithm transcribed from `src/merkle.cpp`; P2Pool's own
Python merge-mining stub, `tests/src/mm_server.py`, fixed the JSON
shapes. A live tagged Monero block is the remaining cross-check and
belongs to slice 3, where the coinbase fetch exists.

### 17.1 Slice 3 decisions

Decided on 2026-09-14 when the reader build started, after reading
P2Pool v4.18 `pool_block_parser.inl`, `pool_block.cpp`,
`side_chain.cpp`, `p2p_server.cpp`, `merkle.cpp` and Monero v0.18.4.1
`difficulty.cpp`, `tree-hash.c`, `cryptonote_format_utils.cpp`. As
above, these are engineering choices; where one narrows the protocol
text it says so.

**Anchor data on the wire.** `/anchor/{chain}/headers?from=H&count=N`
returns, per block, the *hashing blob* (header, transaction tree root,
transaction count: what the proof-of-work is computed over and what the
block id is the hash of) and the difficulty the serving node's monerod
reports. `/anchor/{chain}/coinbase/{height}` returns the block blob as
monerod serves it: header, miner transaction and the list of
transaction hashes. This *is* the "coinbase and its Merkle path" of §5:
the verifier hashes the miner transaction (Monero's three-part hash,
with the second part the Keccak of a single zero byte and the third
part zero), builds the transaction tree hash over the coinbase hash
followed by the listed hashes (Monero `tree_hash`, which P2Pool's
`merkle_hash` reproduces) and compares with the root in the hashing
blob. `count` is capped at 720 per request. All three §5 anchor and
venue endpoints stay free of handshake proof-of-work and under the
rate limit.

**Checkpoint and difficulty.** A checkpoint is `height:hash`. Headers
are fetched from `checkpoint - 735` (Monero's difficulty window plus
lag) so that every block after the checkpoint has a full window.
Blocks at or before the checkpoint are authenticated by linkage to the
checkpoint hash and their difficulties are taken as served; blocks
after it get their difficulty recomputed by Monero's `next_difficulty`
(window 720, lag 15, cut 60, target 120 s) and checked against the
served value. A server lying about pre-checkpoint difficulties can only
lower the post-checkpoint difficulty it then has to mine at, and its
chain loses the cumulative-work comparison to any honest source; the
newcomer is only fooled when every source it reaches lies, which is
the eclipse the anchor cannot address. Ship a fresh checkpoint with
each release. The 30-minute stale-tip rule and the sampling rule of
§6.2 are implemented as written; the sample is drawn with the
process's own randomness.

**Proof-of-work backend.** Verification takes a hasher
`pow_hash(blob, height, seed_hash) -> 32 bytes`. The production
backend looks for a RandomX binding at start-up and refuses to run the
reader without one; the simulation backend (`--anchor-sim-pow`) is
SHA-256 of the blob. Difficulty is checked as Monero does: the hash
read as a little-endian 256-bit integer times the difficulty must not
overflow 256 bits.

**Shares.** The reader parses P2Pool's full (non-compact, non-pruned)
share serialisation from `pool_block_parser.inl` and checks, in
order: syntax; the share id, which is Keccak over the main-chain data
with the nonce, extra nonce and Merkle root zeroed, the side-chain
data, and the venue's consensus id; the proof-of-work over the
main-chain hashing blob against the share's own `m_difficulty`; the
share's Merkle proof of its id at its aux slot against the Merkle root
in its coinbase tag; and, for a share that names the transpeer chain
id in its merge-mining extra map, that the entry decodes as a 32-byte
aux hash followed by two varints of difficulty. Not checked: the
miner's transaction keys and payouts, and the sidechain difficulty
rule. These are the venue's consensus, which the canonical-fork rule of
§6.5 delegates to the venue: a share only carries weight when it is an
ancestor of a share P2Pool itself put into a Monero block, and P2Pool
does not build on shares that fail its rules. Compact and pruned share
encodings are rejected; serving nodes MUST serve full shares.

**Venue endpoints.** `{id}` is the venue's consensus id, hex. Three
lookups: `/venue/{id}/share/{share_id}` for one share, `/venue/{id}/
shares?from={share_id}&count={n}` walking parents from `from` (`n`
capped at 64 per request), and `/venue/{id}/share_by_root/{root}` for
the share whose coinbase Merkle root equals a tag's root, which is how
a tagged anchor block's venue leaf is resolved (P2Pool's own
`find_block_by_merkle_root`). The share store keeps raw bytes on disk
under `data_dir/venues/{id}/` and an in-memory index of the parsed
header fields, pruned at four windows of age, like P2Pool.

**Built-in venues.** The consensus ids of P2Pool main, mini and nano
are copied from `side_chain.cpp`; `--anchor-venues` adds or replaces
them. A venue discovered from a tag but not configured is resolved
only if some transpeer serves its shares.

**Gossip.** Each query cycle, after `/transpeers`, the node asks the
queried transpeer for `/blobs/index` since the cursor it holds for
that transpeer, fetches blobs it lacks, and verifies each commitment
before storing: `share` records by fetching and verifying the share
from the same transpeer, `block` records by the coinbase of the named
height and the proof; `template` records are dropped, they carry no
weight and are the publisher's own. The `/blobs/index` cursor is made
inclusive with a `(first_seen, hash)` pair so that rows sharing a
timestamp across a page boundary are not skipped; the response carries
`next_since` and `next_hash`.

**Store tags and ranking.** `TranspeerEntry` gains `published` (set
when the reader seeds or re-seeds the store from weights) and
`unfaithful` (§9). Under `--anchor-read`, the hand-off ranking key
counts vouchers from published reporters before other vouchers, the
reserve pass takes published clusters first, and unfaithful transpeers
sort last for queries and gossip and are the first eviction
candidates. With the flag off the keys are unchanged.

**Scan-stop.** Under `--anchor-read` the scanner's idle condition is
the reader's `bootstrapped` state (§8); without the flag it is the live
count, as before.

**Observer client.** A minimal P2Pool P2P client transcribed from
`p2p_server.cpp`: challenge, solution with the 10000-difficulty rule,
listen port, then `PEER_LIST_REQUEST` and `BLOCK_REQUEST` by share id
(the zero id asks for the tip). It exists so that a transpeer with no
P2Pool node of its own can still fill its share store from the venue's
overlay; it is tested against a Python double that speaks the same
bytes and, like the merge-mining poller, is unverified against a real
P2Pool until the testnet check.

**Serving from the operator's daemons.** `--anchor-monerod URL` makes
the node fill its anchor store from monerod's JSON-RPC
(`get_block_headers_range`, `get_block`); `--anchor-observe
HOST:PORT,...` makes it fill share stores through the observer client.
Both are unverified against real daemons until the testnet check. A
node with neither relays what it verified from other transpeers.

**Flags.** `--anchor-read` (default off; needs a checkpoint and a
proof-of-work backend), `--anchor-checkpoint HEIGHT:HASH`,
`--anchor-sim-pow`, `--anchor-venues ID,...`, `--anchor-monerod URL`,
`--anchor-observe HOST:PORT,...`, `--anchor-window-days` (default 7).
The reader runs as one more node loop, syncing every 60 s.

**Faithfulness challenges** are implemented as §9 states, in their own
node loop, with the sample drawn from commitments the reader itself
verified; a transpeer's `uptime` from `/transpeer` gates the
10-minute exemption.
