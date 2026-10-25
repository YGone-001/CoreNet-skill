# Bounded S1-U GTP-U observation

This capability reports **what was observed on the S1-U tunnel**, not whether the
subscriber's traffic was delivered.

## Inputs

| Input | Required | Used for |
| --- | --- | --- |
| GTP-U detailed events | yes | message types, frames, directed outer endpoints, header TEID |
| GTP-U directed stream summary | yes | bounded G-PDU and payload-octet counts, Echo/Error Indication/End Marker frames |
| EPS default-bearer analysis | optional | the eNB S1-U receiving endpoint from item-scoped E-RAB evidence |
| GTPv2-C events | optional | the SGW-U S1-U receiving endpoint from bearer F-TEIDs with interface type 1 |

Without the optional inputs the streams stay observable and unbound.

## Matching rule

A GTP-U TEID is meaningful only in the context of the **receiving endpoint**, so a
stream is related to a bearer only when:

```text
outer destination address  ==  advertised S1-U F-TEID address
GTP-U header TEID          ==  advertised S1-U F-TEID TEID
same capture, reviewed S1-U receiving role, one candidate on both sides
```

These are never sufficient alone:

- an outer **source** address,
- a UDP port,
- a TEID value,
- an inner UE address.

A stream whose receiving endpoint matches an eNB endpoint is the **downlink**
direction of the tunnel; a match on an SGW-U endpoint is the **uplink** direction.
Direction is derived from the advertised endpoint role only.

## Association statuses

```text
SUPPORTED        one evidence-safe compatible candidate on both sides
AMBIGUOUS        several endpoint candidates, or one endpoint claimed by several bearers
NOT_ESTABLISHED  no advertised receiving endpoint matches this stream
```

A `SUPPORTED` association means the receiving-endpoint evidence supports the
tunnel relationship. It does **not** elevate the bearer to service delivery, and a
reused endpoint value is never treated as a new lifecycle generation: when several
bearer subjects claim one endpoint the stream is `AMBIGUOUS` and a
`LIFECYCLE_ASSOCIATION_AMBIGUOUS` deviation is published.

## Published evidence

Per directed stream: capture identity, outer source and destination, UDP ports,
header TEID, first and last frame, observed G-PDU count, bounded payload-octet
count with its documented definition, observed message types, Echo presence,
End Marker and Error Indication frames, the interface classification, the
association verdict, the matched endpoint role and frames, competing subjects,
outcomes, evidence references and limitations.

## Forbidden claims

```text
USER_RECEIVED_PACKET
BEARER_DELIVERY_CONFIRMED
PDN_CONNECTIVITY_SUCCESS_CONFIRMED
S1U_FORWARDING_HEALTHY
APPLICATION_REACHABLE
```

An observed G-PDU proves packet visibility at the capture point only. An Echo
Response is not evidence that a bearer is delivering data, an End Marker is not
evidence that a PDN session ended, and no packet loss is inferred from frame gaps,
sequence values or a missing reverse direction.

## Privacy

Inner packet content is never republished: no inner source or destination
address, no inner ports, no application payload. Outer transport endpoints and the
TEID are published because they are required for tunnel engineering analysis.
Output caps apply to streams, evidence references, End Marker and Error Indication
frames, with explicit omission counts.
