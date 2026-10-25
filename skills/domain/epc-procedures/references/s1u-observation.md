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

A stream whose receiving endpoint is the eNodeB endpoint is the **downlink**
direction of the tunnel; a match on the SGW-U endpoint is the **uplink** direction.
Direction is derived from the advertised receiving-endpoint role only, never from
the packet's source address and never from the direction the advertising signaling
message travelled:

| Advertised by | Receiving role | Direction |
| --- | --- | --- |
| S1AP Initial Context Setup Request E-RAB item | `sgw_s1u` | UPLINK |
| S1AP Initial Context Setup Response E-RAB item | `enodeb_s1u` | DOWNLINK |
| GTPv2-C F-TEID interface type 1 | `sgw_s1u` | UPLINK |
| GTPv2-C F-TEID interface type 0 | `enodeb_s1u` | DOWNLINK |

If endpoints of different roles match the same directed stream, the direction is
`UNKNOWN` and the association is `AMBIGUOUS`; the first candidate is never chosen.

## Endpoint match versus bearer ownership

Two independent fields are published:

```text
receiving_endpoint_match_status  MATCHED | NOT_MATCHED
bearer_association_status        SUPPORTED | AMBIGUOUS | NOT_ESTABLISHED
```

A matched receiving endpoint whose advertisement no default-bearer subject owns is
published as `receiving_endpoint_match_status: MATCHED` together with
`bearer_association_status: NOT_ESTABLISHED` (basis
`receiving_endpoint_matched_without_bearer_owner`). Endpoint evidence is preserved;
bearer identity is not asserted. `SUPPORTED` requires one unique endpoint candidate
and one owning subject.

## Evidence provenance

Every matched endpoint keeps the protocol and message that actually advertised it,
and the evidence references use those identities: an S1AP E-RAB item references
`S1AP` with `InitialContextSetupRequest` or `InitialContextSetupResponse`, and a
GTPv2-C F-TEID references `GTPv2-C` with its own message type. A frame is never
relabelled to the other protocol merely because it was used for the association.

A stream publishes what the matching advertisements actually contained:

| Field | Meaning |
| --- | --- |
| `matched_endpoint_role_basis` | the rule that fixed the role, `null` when the matching advertisements disagree |
| `matched_endpoint_source_protocols` | every protocol that advertised a matching endpoint |
| `matched_endpoint_interface_types` | the advertised GTPv2-C interface types, empty for an S1AP-only match |
| `matched_endpoint_interface_type_names` | the reviewed names of those interface types |

Every published `GTP-U` reference names the message that the frame-anchored GTP-U
event reports for that frame. A stream's first and last frames are not necessarily
G-PDUs, so identity is never inferred from stream membership, the G-PDU count, the
UDP port, the header TEID or the first element of a sorted message-type list. When
no event exists for a frame, the reference keeps the frame and publishes
`message_type: null`; `"G-PDU"` is never used as a fallback.

An S1AP E-RAB item carries a transport address and a TEID but **no** GTPv2-C
interface type, so an S1AP-only match publishes an empty interface-type list and
the workflow publishes `interface_type: null` with the basis
`s1ap_erab_item_advertises_no_gtpv2_interface_type`. An interface type is never
synthesised from the role, and a role is never synthesised from an interface
type: TS 29.274 clause 8.22 names interface type 1 "S1-U SGW GTP-U interface" and
interface type 0 "S1-U eNodeB GTP-U interface", so only a record that carries one
may be published with one.

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
