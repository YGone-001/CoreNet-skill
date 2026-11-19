# Evidence Model

## Association identity

The only accepted SIP-to-SDP identity is:

```text
SDP message source_reference == SIP Event source_reference
```

The reference is capture-scoped, for example
`sip-event:synthetic-call.pcapng:12.1`. The Domain additionally requires equal
`capture_file`, `frame_number` and `message_occurrence`, exactly one SIP Event
per reference, exactly one SDP message per reference, and the SDP evidence
status `OBSERVED`.

A frame number alone, a timestamp, a stream index, an IP address, an SDP session
name, an SSRC or a filename is never a join key. If exact identity cannot be
proven, the observation is published as unbound, incomplete or ambiguous rather
than dropped.

## Evidence classes

| Field | Value | Meaning |
|---|---|---|
| `exchanges[].evidence_class` | `DERIVED` | The association is derived from accepted artifacts |
| individual SIP observation | owned by `sip` | `OBSERVED` at the Protocol layer |
| individual SDP observation | owned by `sdp-rtp` | `OBSERVED`/`INCOMPLETE`/`UNSUPPORTED`/`INVALID` at the Protocol layer |
| `negotiation_compatibility` | `NOT_EVALUATED` | No offer/answer compatibility conclusion |

## Association statuses

| Status | Meaning |
|---|---|
| `ESTABLISHED` | The required exact references and signaling positions were observed |
| `NOT_ESTABLISHED` | The attempt exists but no supported offer association was observed |
| `INSUFFICIENT_EVIDENCE` | A position was expected but the accepted artifact is missing, incomplete or unresolved |
| `AMBIGUOUS` | More than one candidate competes and no deterministic choice exists |
| `OUT_OF_SCOPE` | The observation is preserved but intentionally not interpreted in this phase |

## Exchange types

| Type | Meaning |
|---|---|
| `INITIAL_INVITE_SDP_OFFER` | Accepted initial INVITE carries an accepted SDP offer; no answer exchange was published |
| `INITIAL_INVITE_OFFER_ANSWER` | Accepted initial INVITE offer plus an accepted branch-scoped final 2xx SDP answer |
| `INITIAL_INVITE_WITHOUT_SDP` | Accepted initial INVITE has no body or no SDP body; this is not a failure |
| `LATE_OFFER_ANSWER` | Accepted 2xx SDP offer plus the same branch's accepted SDP ACK answer |

## Observation types

| Type | Meaning |
|---|---|
| `PROVISIONAL_SDP_UNINTERPRETED` | 18x SDP preserved without reliable provisional response interpretation |
| `UNSUPPORTED_SDP_OBSERVATION` | In-dialog, non-2xx or otherwise unsupported SDP position |
| `UNBOUND_SIP_SDP_EVENT` | SDP-bearing SIP Event without a resolvable accepted branch owner |
| `UNMATCHED_SDP_MESSAGE` | SDP message whose exact source reference resolves to no SIP Event |

## Reason codes

Deterministic, machine-readable reason codes include:

- `SIP_EVENT_NOT_FOUND`
- `SDP_SOURCE_REFERENCE_MISMATCH`
- `CAPTURE_IDENTITY_MISMATCH`
- `FRAME_REFERENCE_MISMATCH`
- `MESSAGE_OCCURRENCE_MISMATCH`
- `SIP_BODY_NOT_PRESENT`
- `SIP_CONTENT_TYPE_NOT_SDP`
- `SIP_MESSAGE_INCOMPLETE`
- `SDP_MESSAGE_NOT_OBSERVED`
- `SDP_MESSAGE_INCOMPLETE`
- `SDP_MESSAGE_UNSUPPORTED`
- `INITIAL_INVITE_NOT_FOUND`
- `PROVISIONAL_SDP_RELIABILITY_NOT_PROVEN`
- `COMPETING_SDP_CANDIDATES`
- `LATE_OFFER_ACK_NOT_OBSERVED`
- `IN_DIALOG_SDP_OUT_OF_SCOPE`
- `NON_2XX_FINAL_SDP_OUT_OF_SCOPE`
- `SDP_ANSWER_NOT_OBSERVED`
- `BRANCH_ASSOCIATION_AMBIGUOUS`

## Conservation

`completeness` accounts for all supplied inputs:

```text
supplied_sdp_message_count
  = matched_sip_event_count + unmatched_sdp_message_count

established + not_established + incomplete + ambiguous
  = published exchange count

omitted_observation_count
  = bounded-out exchanges + bounded-out observations
```

`observed_offer_count` and `observed_answer_count` count published exchanges
that carry those roles. Counts are never derived from narrative text.

## Fail-closed rules

An association is never promoted to `ESTABLISHED` when any of the following is
true:

- the SIP Event or SDP message is missing or duplicated;
- capture, frame or message occurrence disagrees;
- the SIP Event has no body or does not declare `application/sdp`;
- the SIP message is incomplete or its extraction status is not accepted;
- the SDP message is not `OBSERVED`;
- the branch association is missing or ambiguous;
- more than one SDP answer or ACK candidate competes.