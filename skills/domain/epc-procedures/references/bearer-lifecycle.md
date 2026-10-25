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

A generation closes only when an accepted release transaction **names the S1-U
endpoint it releases**. In the accepted real capture every Delete Session request
carries no S1-U F-TEID, so every generation stays `OPEN_AT_CAPTURE_END` with
`RELEASE_STATUS_UNRESOLVED`; an open generation does not prove the bearer is still
active.

An accepted Delete Session that carries no endpoint still closes the session
control-plane context as the session-control capability already reports. It does
not close an independently linked S1-U generation.

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
