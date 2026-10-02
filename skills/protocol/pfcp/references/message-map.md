# PFCP Message Map

Reviewed message types from 3GPP TS 29.244 version 19.6.0 Release 19,
table 7.3-1. Message names are reproduced as the specification spells them.
Support status is a Skill-local classification: recognition never implies
semantic support.

## Supported bounded subset

| Code | Reviewed message | Kind | Procedure family | Transaction role | Logical direction |
| --- | --- | --- | --- | --- | --- |
| 1 | PFCP Heartbeat Request | node | Heartbeat | request | either node (null) |
| 2 | PFCP Heartbeat Response | node | Heartbeat | response | either node (null) |
| 5 | PFCP Association Setup Request | node | AssociationSetup | request | control-plane-to-user-plane |
| 6 | PFCP Association Setup Response | node | AssociationSetup | response | user-plane-to-control-plane |
| 50 | PFCP Session Establishment Request | session | SessionEstablishment | request | control-plane-to-user-plane |
| 51 | PFCP Session Establishment Response | session | SessionEstablishment | response | user-plane-to-control-plane |
| 52 | PFCP Session Modification Request | session | SessionModification | request | control-plane-to-user-plane |
| 53 | PFCP Session Modification Response | session | SessionModification | response | user-plane-to-control-plane |
| 54 | PFCP Session Deletion Request | session | SessionDeletion | request | control-plane-to-user-plane |
| 55 | PFCP Session Deletion Response | session | SessionDeletion | response | user-plane-to-control-plane |

Logical direction is derived from the reviewed procedure definition, never
from IP addresses or UDP ports. Heartbeat may be initiated by either node,
so its direction stays null.

## Recognized but unsupported

Recognized by reviewed name and reported `UNSUPPORTED` with no semantics
beyond the bounded header fields:

| Code | Reviewed message | Kind |
| --- | --- | --- |
| 3 | PFCP PFD Management Request | node |
| 4 | PFCP PFD Management Response | node |
| 7 | PFCP Association Update Request | node |
| 8 | PFCP Association Update Response | node |
| 9 | PFCP Association Release Request | node |
| 10 | PFCP Association Release Response | node |
| 11 | PFCP Version Not Supported Response | node |
| 12 | PFCP Node Report Request | node |
| 13 | PFCP Node Report Response | node |
| 14 | PFCP Session Set Deletion Request | node |
| 15 | PFCP Session Set Deletion Response | node |
| 16 | PFCP Session Set Modification Request | node |
| 17 | PFCP Session Set Modification Response | node |
| 56 | PFCP Session Report Request | session |
| 57 | PFCP Session Report Response | session |

Session Report is deliberately left at recognition level: downlink-data and
usage-report semantics are out of scope for this version.

## Unknown values

Codes outside the reviewed table are `UNKNOWN` with the numeric code
preserved and no invented name, family, direction, or result label. This
covers code 0 (Reserved), 18-49 and 58-99 ("For future use" ranges in the
reviewed table), and 100-255 ("Other messages", for future use).

## S flag expectation

The S flag indicates whether the SEID field is present. Reviewed behaviour:

- Node related messages (codes 1-17) carry no SEID field.
- Session related messages (codes 50-57) carry the SEID field.
- A PFCP Session Establishment Request (code 50) sets the SEID field to 0
  because the peer SEID is not yet available (clause 7.2.2.4.2). The event
  records this expectation in `header.seid_expected_zero`.

## Message-level result labels

`result` is a local normalized label derived from the reviewed transaction
role: REQUEST for a request message, RESPONSE for a response message, and
null when the message has no reviewed request/response role or the code is
UNKNOWN. It is a message-level label only. It never means that the PFCP
session or the user plane succeeded; the PFCP Cause carries the
protocol-defined outcome.
