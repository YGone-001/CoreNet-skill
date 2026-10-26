# Session Identity Bridge

Contract for the bounded EPC S11<->S5/S8 session-identity capability
(`analyze_epc_session_identity.py`). Normative sections are cited in
`rules/epc-session-identity-model.json`; the reviewed section numbering follows
the repository's accepted normative references and no version-specific behaviour
beyond those sections is relied upon.

## Three strictly separated relationships

1. **HOP_LOCAL_SESSION_CONTEXT** — transactions of one GTPv2-C hop (S11 or
   S5/S8) that share one receiver-scoped control-plane context. This is never a
   cross-interface claim.
2. **CROSS_INTERFACE_ENDPOINT_CORRESPONDENCE** — an explicitly advertised
   bearer-scope user-plane F-TEID that appears on both hops with agreeing
   address, TEID, interface type and item-scoped bearer identity. Correspondence
   is classified `SUPPORTED` at most and is never displayed as session identity.
3. **CROSS_INTERFACE_SESSION_IDENTITY** — proof that two hop-local contexts
   belong to one EPC session instance. The reviewed bridge in this capability is
   the relayed control-plane F-TEID: the S11 Create Session Response relays the
   PGW S5/S8 GTP-C F-TEID (interface type 7) that the S5/S8 Create Session
   Response assigned for the same session. It establishes session identity only
   when it is unique on both hops, both contexts are independently established,
   the capture context is shared and no competing context claims the same
   F-TEID.

## Receiver-side TEID interpretation

A GTPv2-C header TEID is interpreted in the scope of its receiving control-plane
endpoint. TS 29.274 scopes a GTP-C tunnel by TEID, address and path peer, so a
transaction joins a hop-local context only when:

- its request header TEID is non-zero and equals the TEID of one **hop-local**
  control-plane F-TEID published inside the context (interface type in the hop's
  set: S11 = {10, 11}, S5/S8 = {6, 7});
- its request destination address equals that F-TEID's address;
- its request source address equals a hop-local F-TEID address of the same
  context (the GTP-C path peer);
- exactly one context satisfies all of the above in the same capture.

Equal numeric TEID values never join anything by themselves. Real captures can
reuse one header TEID (for example TEID 1) across every session, and one SGW can
reuse the same control TEID value on S11 and S5/S8; only the full
(receiver, interface type, TEID, address, path peer) relation separates those
tunnels. A relayed F-TEID of a foreign interface type and an F-TEID with TEID 0
(an address hint) are never join keys.

Competing candidates are published as `AMBIGUOUS` with their competitor
references. Ties are never broken by first-seen order, lowest frame, lowest
TEID, earliest Create Session transaction or correlation strength alone.

## Bridge gates

Before a cross-interface session identity is published:

1. both hop contexts are independently established (proved MATCHED allocation
   transactions with joinable hop-local F-TEIDs);
2. both are in the same authorized capture context;
3. the interface roles are reviewed (interface type names the owner);
4. at least one valid independent identity bridge connects the two;
5. the bridge is bound to the exact source messages;
6. the candidate contexts have compatible lifecycle windows;
7. the bridge cannot belong to competing sessions (unique on both hops);
8. no observed identifier conflict exists;
9. no source collection is materially incomplete or truncated (unbound and
   omitted evidence is published, never hidden);
10. the published evidence names the exact source frames.

If only endpoint equality exists, the document publishes
`CROSS_INTERFACE_ENDPOINT_CORRESPONDENCE` and keeps
`CROSS_INTERFACE_SESSION_IDENTITY = NOT_ESTABLISHED`. If no valid bridge exists,
the two hop subjects stay separate and the missing proof is named. A truthful
unresolved relationship is acceptable; a bridge is never invented because one is
desired.

## Allocation acceptance and bearer scope

Transaction correlation, control-plane context identification, endpoint
advertisement, allocation acceptance and bearer association are separate
classification layers; none substitutes for another. A hop-local context is
`ESTABLISHED` only when the allocation transaction is a proved `MATCHED` pair,
publishes a joinable path-corroborated hop-local control-plane F-TEID **and** its
correlated response carries an accepted message-scope Cause. A rejected or
unresolved allocation keeps the context as a diagnostic candidate that establishes
nothing downstream; the observations are retained, never discarded.

Every S1-U endpoint keeps one item record per grouped bearer-context
advertisement. A bearer-scope Cause decides its own item's outcome and is never
overridden by the message-level Cause; an item without a grouped Cause falls back
only to its own transaction's correlated response message Cause; flat unbound IE
values are never assigned to any item by position. The outcome of **every**
grouped item of the endpoint is evaluated, so a rejected or unresolved item —
including one that carries no readable identity — blocks that endpoint's bearer
association and is never outweighed by a sibling item. One endpoint advertising
more than one distinct assigned item-scoped bearer identity stays `AMBIGUOUS` —
both source records are preserved and no single bearer generation is isolated.

## EPS Bearer Identity value validity

Bearer identity is an affirmative requirement, and it is a requirement on an
**assigned** identity, not merely on a readable number. The field is a four-bit
identity: 3GPP TS 24.007 sec 11.2.3.1.5, 3GPP TS 24.301 sec 9.3.2 and
3GPP TS 29.274 sec 8.8 code zero as "no EPS bearer identity assigned", and
1..15 as bearer identity values. Values 1..4 additionally depend on the
participating nodes supporting fifteen EPS bearer contexts, which an observed
message never proves either way, so this capability applies no unconditional
5..15 rule and treats every value in 1..15 as potentially assigned.

One observed grouped value is classified internally as one of:

```text
ITEM_IDENTITY_ASSIGNED     readable, inside 1..15   -> may isolate a bearer
ITEM_IDENTITY_UNASSIGNED   readable, exactly 0      -> never isolates a bearer
ITEM_IDENTITY_INVALID      outside the encoded domain, or not an integer
ITEM_IDENTITY_UNRESOLVED   absent or unreadable
ITEM_IDENTITY_READABLE     the union of ASSIGNED and UNASSIGNED
```

Only `ITEM_IDENTITY_ASSIGNED` satisfies the identity requirement. At least one
grouped item must carry an assigned item-scoped EBI before anything is
established; an endpoint whose grouped items carry only zero or an out-of-domain
value fails closed on `grouped_bearer_item_identity_unassigned_or_invalid`, and
an endpoint advertised only at message scope, or whose grouped items carry no
readable EBI at all, fails closed on `grouped_bearer_item_identity_missing`.

Two further consequences follow, and both are enforced rather than assumed:

- **A mixed endpoint fails closed.** When one endpoint is advertised both by an
  item with an assigned identity and by an item whose identity is zero or
  out-of-domain, the assigned item's ownership of that endpoint is not
  independently unique. The link fails closed on
  `grouped_bearer_item_identity_unassigned_or_invalid`; the conflicting evidence
  is never silently discarded to raise the established count.
- **Reading is not proving.** An accepted message-scope Cause 16 decides only the
  item's outcome. It never manufactures an assigned identity, and it never
  rescues an item whose EBI is zero or out-of-domain.

Observed values stay published. An unassigned or out-of-domain identity remains
visible in `bearer_endpoint.eps_bearer_identities` and in the reviewed
identifiers as diagnostic evidence; only its proof status is refused. The
message-scope advertisement likewise remains observable diagnostic evidence that
neither establishes nor blocks the association, and a duplicated message-scope
record never disqualifies an otherwise independently proved grouped
relationship.

## Hop classification

Every classifying F-TEID must be corroborated by the publishing message's own
path: its address must be one of that message's two endpoints. A relayed
foreign-interface F-TEID alone therefore yields `INSUFFICIENT_HOP_EVIDENCE` and
seeds no context, while a response may still supply missing hop evidence when its
own direction corroborates the F-TEID it publishes.

## Forbidden assumptions

Never establish a link solely from equal header TEID, equal EBI, equal E-RAB ID,
equal GTPv2-C sequence number, equal Cause, equal S1-U TEID, equal IP address,
a common SGW IP address, event proximity, the same PCAP, one apparent UE or the
same procedure name. A shared numeric TEID is not an end-to-end EPC session
identity. APN names and subscriber identity are neither read nor used.
