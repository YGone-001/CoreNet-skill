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
