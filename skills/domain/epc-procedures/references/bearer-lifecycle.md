# Bounded EPC bearer lifecycle-generation evidence

This capability reports **what the accepted control-plane evidence proves about the
life of one S1-U receiving endpoint**, not the state of a bearer, a session or a
subscriber.

## Inputs

| Input | Required | Used for |
| --- | --- | --- |
| GTPv2-C detailed events | yes | S1-U F-TEID advertisements, Causes, procedure families |
| GTPv2-C transaction correlation | yes | binding an advertisement to an accepted request/response pair |
| EPC session-control analysis | optional | release context, recorded as provenance only |
| EPS default-bearer analysis | optional | cross-reference to the accepted bearer subjects |
| EPC S1-U observation | optional | aggregate stream counts to attribute |
| GTP-U detailed events | optional | frame-level packet attribution |

The model never decodes a capture, never parses protocol bytes, never rebuilds
request/response matching from timestamps and never publishes subscriber identity.

## Three separate questions

```text
Do repeated advertisements describe one allocation or several?   -> advertisement family
Does an accepted boundary prove a new generation of the endpoint? -> generation boundary
Which observed G-PDUs belong to a proved generation?              -> packet attribution
```

The answers are never collapsed into one verdict. A proved family removes
duplicate-message ambiguity; it does not prove a complete lifecycle, an S11 to
S5/S8 identity, PDN connectivity, UE delivery or user-plane forwarding.

## Generation identity

```text
capture identity
receiving endpoint role (sgw_s1u | enodeb_s1u)
endpoint address
endpoint TEID
reviewed interface type (0 | 1)
first accepted advertisement frame
```

The label is `epc-bearer-generation-<sha256[:10]>` over exactly those values. A
GTP-U TEID alone is never a generation identity, and neither an EBI nor an E-RAB
identifier is treated as globally unique.

## Opening a generation

A Create Session advertisement opens an allocation candidate; a Modify Bearer
advertisement opens an endpoint-update candidate. An accepted network Cause is an
observed control-plane outcome. It is not user-plane delivery confirmation.

A repeated advertisement of an endpoint that is still open updates the same
generation. Repeated Modify Bearer evidence never fabricates a new generation.

## Closing a generation

A generation closes only when **all** of the following hold:

1. the release is an explicit GTPv2-C release transaction in the **same capture**;
2. the transaction is `MATCHED` with a correlation strength in the proof set;
3. exactly one correlated response establishes the outcome;
4. that response carries a **message-scope** accepted Cause;
5. the request names the released endpoint (address, TEID, interface type);
6. the release names the **same control-plane context** as the allocation;
7. the bearer identity is compatible when both sides publish one;
8. exactly one bound release candidate exists.

Endpoint equality alone never closes a generation. A release from another capture,
from another control-plane context, with a rejected response, with an uncorrelated
response or with an unproved Cause leaves `RELEASE_STATUS_UNRESOLVED`.

In the accepted real capture every Delete Session request carries no S1-U F-TEID,
so no release can be bound and every generation stays `OPEN_AT_CAPTURE_END`; an
open generation does not prove the bearer is still active.

An accepted Delete Session that carries no endpoint still closes the session
control-plane context as the session-control capability already reports. It does
not close an independently linked S1-U generation.

## Release initiation and confirmation

```text
release_request_frame        300   initiation evidence
release_confirmation_frame   306   the correlated accepted response
release_effective_frame_proven  false
```

A boundary anchors on the confirmation frame, never on the request. The request
frame stays visible as initiation evidence, and the document never claims the
exact instant user-plane forwarding stopped.

Packets observed between the request and the confirmation belong to **neither**
generation: they are published as `GENERATION_UNRESOLVED` with basis
`release_in_progress_interval`. The closed generation owns frames up to and
including its release request; a later generation owns frames from its own proved
allocation. No packet is moved across that interval by proximity.

## Message Cause

The release outcome is read from the accepted GTPv2-C event contract:

```text
message_cause:
  cause_code
  cause_name
  scope: message | bearer
```

Only a `scope: message` Cause on the **correlated response** establishes the
outcome. A bearer-scope Cause belongs to one item-scoped bearer context and is
never substituted for the message outcome, a request-side Cause is never an
outcome, and a Cause carried by any other transaction is never consulted. When the
response publishes no message-scope Cause the outcome stays `UNRESOLVED`; there is
no fallback to a missing or invented field.

## Capture-scoped evidence identity

A frame number is unique only inside one capture and one message occurrence, so
evidence is identified by:

```text
capture identity + frame number + message occurrence
```

Transaction references in the accepted contract carry no per-transaction capture,
so a transaction is bound to observed messages as follows:

| Document | Rule |
| --- | --- |
| exactly one capture | bind only to events of that capture; an event from another capture is rejected |
| several captures | bind only when the observed messages resolve to exactly one candidate |
| several captures, colliding frames | `INSUFFICIENT_CAPTURE_PROVENANCE`; no family, no boundary, no generation split |

A collision never overwrites an index entry, never transfers a Cause, never
transfers a control-plane context, and never depends on input order. A release
that cannot be bound publishes `release_transaction_<reason>` as its basis.

## Correlation strength

```text
STRONG      eligible when every other gate passes
SUPPORTED   eligible when every other gate passes; published so the weaker
            corroboration stays visible
NONE        never sufficient, for a family or for a release
missing or unreviewed   never sufficient
```

A `MATCHED` pair without corroboration is not independent proof. The reviewed
vocabulary comes from the accepted GTPv2-C transaction contract; an unknown value
is rejected rather than silently accepted.

## Reuse

```text
same value, same generation       -> one generation, no reuse observation
same value, proved boundary       -> SEPARATE_GENERATIONS_ESTABLISHED + reuse observation
same value, no proved boundary    -> INSUFFICIENT_GENERATION_EVIDENCE, no generation split
```

Chronological order alone never decides a generation. A numerically identical
TEID observed later is not automatically a new generation.

## Packet attribution

A directed GTP-U stream is not a bearer generation. Attribution uses exact frame
events:

```text
aggregate observed G-PDU count
  = sum(generation-attributed G-PDU counts) + unresolved G-PDU count
aggregate observed payload octets
  = sum(generation-attributed octets) + unresolved octets
```

Packets are never divided proportionally, never assigned by stream proximity and
never assigned to the earliest generation of a reused endpoint. Frames outside a
proved window, or inside an interval covered by more than one generation, stay
`GENERATION_UNRESOLVED` and keep their counts. An unresolved attribution is not
packet loss and not a tunnel failure.

## Session-context release path (input contract)

`analyze_epc_bearer_lifecycle.py` accepts one optional additional input:

```bash
--session-identity epc-session-identity-analysis.json
```

The file must be an accepted EPC session-identity analysis
(`schemas/epc-session-identity-analysis.schema.json`). Through this documented
input contract the lifecycle capability may close a generation through the
**reviewed session-context release path** when all of the following hold:

1. the analysis publishes an `ESTABLISHED` `RELEASE_TO_SESSION_CONTEXT` binding
   for the release transaction, in the same capture;
2. it publishes an `ESTABLISHED` `SESSION_CONTEXT_TO_BEARER_GENERATION` link
   whose bearer endpoint matches the generation's receiving role, address, TEID
   and interface type;
3. it publishes an `ESTABLISHED` generation-closure candidate for that
   context/release/endpoint triple;
4. the lifecycle's own capture-scoped transaction binding independently resolves
   the same release transaction to one accepted request/response pair with exact
   frames;
5. exactly one candidate release remains; an ambiguous direct path never falls
   back to the session-context path, and an ambiguous identity chain closes
   nothing;
6. the identity analysis is complete as an affirmative proof: for every
   closure-critical collection the declared count must be present, a nonnegative
   integer, equal to the published record array, and the published omitted count
   must be present, valid and zero. Positive truncation publishes
   `SOURCE_CANDIDATES_TRUNCATED`; every other missing, invalid, underdeclared or
   nonzero-omitted metadata publishes `SOURCE_CANDIDATES_METADATA_INVALID` — both
   refuse session-context closure for the whole analysis, with no input-order
   fallback.

The lifecycle also never closes a generation whose owning session context lacks an
accepted allocation outcome, or whose endpoint carries a rejected or unresolved
grouped bearer item, or which shares its endpoint value with a second assigned
item-scoped bearer identity.

It additionally re-verifies the identity of a candidate's bearer endpoint instead
of trusting the published candidate status. A candidate whose endpoint carries no
valid assigned EBI is never indexed for closure, because zero is the explicit
"no EPS bearer identity assigned" code and a value outside the four-bit encoded
domain is no identity at all. An analysis produced by an older or doctored
implementation therefore cannot close a generation through an unassigned value,
and the generation simply stays open.

Such a boundary publishes the basis
`accepted_release_response_bound_by_reviewed_session_context` and keeps
`release_effective_frame_proven = false`. The direct endpoint-bound path is
unchanged and remains authoritative; without the optional input the lifecycle
output is identical to its previous contract.
