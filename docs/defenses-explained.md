# The defenses, explained with a traveller

The formal record is `manuscript.md`. This is the same material told as a
story, for readers who want the shape of the mechanisms before the
numbers. The mapping between the story and the protocol:

| in the story | in the protocol |
|---|---|
| the traveller | a fresh node joining a network |
| the marketplace | the network's real peers, and the real chain behind them |
| knocking on random doors | the blind scan of IPv4 space on port 7337 |
| an informant | a transpeer, a node that hands out peer addresses |
| an informant's list | a `/peers/{network}` response |
| a street | a diversity bucket, a `/16` prefix in production |
| the con artist | a coordinated attacker with many addresses |
| the fake market | a corralled network: fake peers, or real daemons on a fork |
| the walking list | the top twenty peers handed to the daemon |

## The setting

A traveller arrives in a foreign city and needs to find the real
marketplace. They know nobody, so they knock on random doors and ask,
"do you know where the market is?" Anyone who answers with a list of
addresses is an informant. The traveller collects informants, collects
their lists, and eventually chooses twenty addresses to walk to.

The con artist wants every newcomer to end up at a fake market they
control. They rent thousands of mailboxes across town, put someone at
each one, and have them all hand out the same list, every address
pointing to the fake market. With no defenses the traveller's notebook
fills up with the con artist's people, because there are so many of
them, and their addresses crowd out the real ones. That is the eclipse
attack, and the first experiments measured exactly that outcome.

## Three informants per street

Bucketing is a rule the traveller applies to the notebook: at most three
informants from any one street. Renting a thousand mailboxes on one
street now buys the con artist three entries and no more. To get more
entries they must rent on many different streets, and streets are real
estate rather than printing. When the notebook is full, the traveller
crosses out a name from the most crowded street rather than the oldest
name, so a flood from one street can only ever push out its own kind.

The measured result is a closed form: the con artist's share of the
notebook is `min(A, 3S) / (min(A, 3S) + H)`, where `A` is their mailbox
count, `S` their street count and `H` the honest informants. Past three
per street, the mailboxes stop mattering.

## Count the streets that agree

Vouchers decide which addresses the traveller trusts. An address is
ranked by how many different streets' informants independently mentioned
it. The real market is mentioned by informants from all over town. The
fake market is mentioned only by the con artist's people, who live on
however many streets the con artist rented.

So the fake ranks below the real one until the con artist has rented more
streets than the number of streets that independently vouch for the real
market. That threshold is the crossover in the results: four streets
against a town of fifty honest informants, sixteen to twenty-four against
two hundred. A bigger honest town is harder to fool, and a traveller who
has been in town longer has heard from more streets, which is why the
crossover also rises with uptime.

## Old friends keep their page

The tried table protects informants who have actually answered the
traveller's questions twice. They are never crossed out to make room for
a newcomer. It matters for a resident who has lived in the city a while
and is hit by a sudden flood of new mailboxes: without it the resident
lost about ten of fifty old contacts to the flood, with it one. Under
bucketing it changes nothing, because the crowded-street rule already
never evicts a lone honest name.

## Proportional representation, not winner-takes-all

The hand-off reserve changes how the walking list is chosen. Instead of
taking the top twenty by vote, the traveller takes the top fifteen and
then asks which informants got nothing of theirs onto that list. If a
whole group of informants from different streets is unrepresented, that
is a signal: either they are all wrong, or the top fifteen is a bloc.
The last five slots go to that group's best picks.

Under a corral the con artist's informants all point at the fake market,
so every honest informant is unrepresented and a few real addresses land
on the walking list. And once the traveller walks to one real market
they can tell it is real, because the daemon follows the heaviest chain
and a fake market cannot fake the weight of the real one. One honest
visit breaks the corral. Without the reserve, at twenty-five streets and
above, no seed put a single real address on the list; with it, every seed
did up to a hundred streets, and four of five at two hundred.

Two rules keep the reserve honest. A recommendation needs two independent
streets behind it before it can take a reserve slot, so a con artist
cannot turn every stray mailbox into a seat. And the traveller can only
hear from informants they have actually asked. That is the limit the
results showed at two hundred streets: in fifteen minutes the traveller
had asked so few honest informants that in one seed of five there was
nobody left to represent. The reserve also has a price below the
crossover: a small con artist group that would have got nothing by vote
is handed one seat, five percent of the list, for being unrepresented.

## Knock on the informant's own door

Native vouchers weigh informants by whether they demonstrably trade at
the market themselves. Anyone can say "I know the market." But the
traveller can walk to the informant's own house and check whether there
is a stall there, meaning the informant's host answers on the network's
daemon port. Informants who run a stall outrank those who only talk.

The con artist's cheap informants are mailboxes with someone reading a
script and no stall behind the door, so their recommendations sink to the
bottom. Against that attacker the daemon list went from mostly fake to
entirely real in every cell. To beat it the con artist must build a real
stall at every mailbox, which is the full price of running the fake
market everywhere rather than the price of hiring script readers. Against
an attacker willing to pay that, the numbers matched the undefended
baseline. That is the honest statement of what this defense does: it
removes the cheap version of the attack and prices the expensive one. The
simulated check is a knock on the door, a TCP connect; a deployment should
look inside, using the network plugin's protocol handshake.

## The knocking itself

Knocking on random doors is what gets the traveller reported to the
police. So the traveller knocks only until three informants have
answered, then stops, and relies on the people they have met and on the
merchants their own shop already trades with to introduce them to more.
They skip the government buildings, wear a name badge with a contact
address, and can be told never to knock at all. In protocol terms: scan
only while cold, the daemon-peer discovery path, the sensitive-range
exclusions, the User-Agent and `GET /` page, and `--no-scan`.

## Why not more proof-of-work?

EquiX proof-of-work is already in the protocol in two places: every peer
entry a transpeer publishes carries a proof bound to the address and a
six-hour window, and the HTTP handshake demands a proof whose difficulty
rises with load. Both meter a *rate*: how fast fake entries can be
minted, how fast one requester can hit a server.

The corral is not a rate problem. Its scarce resource is streets, and
work cannot stand in for streets. Suppose every voucher had to carry a
proof binding the reporting informant to the address it reports. An
honest informant publishes a few dozen addresses per six hours. A con
artist on `S` streets vouching for twenty fakes needs `20 S` proofs per
six hours: at twenty-five streets, five hundred, about ten to thirty
times an honest node's work. That is a few CPU cores, which costs less
than one rented `/16`, let alone twenty-five. Raising the difficulty
until the attacker's bill mattered would first make honest publishing
impractical on small machines. The same arithmetic applies to charging
for self-announcements on the candidate path: it slows a flood, it does
not shrink its reach. So EquiX stays where it is, on the rates, and the
defenses against breadth stay on the streets.

## The limit

None of this beats a con artist who has rented more streets than the
honest town covers. At that point they are, for the traveller's purposes,
the town. The defenses raise the price from mailboxes to streets,
guarantee that a few real addresses survive on the walking list, and
leave the final judgement to the walk.
