# GTP-U Message Map

Reviewed GTP-U message types from 3GPP TS 29.281 version 19.2.0 Release 19,
table 6.1-1. Message names are reproduced as the specification spells them.
Support status is a Skill-local classification: recognition never implies
semantic support.

## Supported bounded subset

| Code | Reviewed message | Class | TEID expectation | Protocol-local interpretation |
| --- | --- | --- | --- | --- |
| 1 | Echo Request | path-management | all zeroes | a peer asks whether the other peer is alive; Recovery Time Stamp is optional |
| 2 | Echo Response | path-management | all zeroes | sent as a response to a received Echo Request; Recovery is mandatory |
| 26 | Error Indication | path-management | all zeroes | reports that a peer has no tunnel context; the affected tunnel TEID is carried inside the message |
| 31 | Supported Extension Headers Notification | path-management | all zeroes | advertises extension header types the sender supports |
| 254 | End Marker | tunnel-management | tunnel TEID | marks the end of traffic on one directed forwarding tunnel |
| 255 | G-PDU | user-plane | tunnel TEID | carries the encapsulated T-PDU |

TEID expectation is derived from TS 29.281 clause 5.1: the Echo
Request/Response, the Supported Extension Headers Notification and the Error
Indication messages set the header TEID to all zeroes; a G-PDU and an End
Marker carry the tunnel TEID. A G-PDU with an all-zeroes TEID is only valid
in the reviewed backward-compatibility case where a peer's control-plane
TEID was itself all zeroes, so this Skill records a limitation when it
observes one.

## Recognized but unsupported

| Code | Reviewed message | Class |
| --- | --- | --- |
| 253 | Tunnel Status | path-management |

Tunnel Status is recognized by reviewed name and reported `UNSUPPORTED`
with no semantics beyond the bounded header fields.

## Unknown values

Codes outside the reviewed table are `UNKNOWN` with the numeric code
preserved and no invented name, class, or role. This covers the reviewed
reserved ranges 3-25, 27-30 and 32-252.

## Optional header fields

The Sequence Number, N-PDU Number and Next Extension Header Type are
present only when the corresponding S, PN and E flags are set. A G-PDU
commonly carries neither a sequence number nor an extension header, so a
missing sequence number is normal and is never replaced by an invented
zero.

## Message-role labels

`result` is a local normalized label derived from the reviewed message
identity, and only the Echo pair has a reviewed request/response
relationship:

- Echo Request → `REQUEST`
- Echo Response → `RESPONSE`
- every other supported message → null

It is a message-role label only. It never means a tunnel or user-plane path
works.

## Reading a GTP-U capture

- A G-PDU proves that an encapsulated packet was observed at the capture
  point, nothing more.
- An End Marker observed for a directed TEID context is signalling
  evidence for that context; it is not proof that a teardown completed end
  to end.
- An Error Indication states that a peer has no tunnel context; the
  affected tunnel TEID is a separate observation from the header TEID and
  is never converted into automatic blame.
- An Echo Response observed at the capture point does not prove that all
  GTP-U tunnels are functioning, and an Echo Request without a visible
  response in a partial capture does not prove the peer is unavailable.
