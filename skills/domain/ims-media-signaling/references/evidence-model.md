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

## Initial SDP states

Every exchange publishes the classified state of the initial INVITE SDP evidence:

| State | Meaning |
|---|---|
| `ABSENT` | No body, zero content length, complete extraction and no contradictory SDP message |
| `OBSERVED_VALID` | An eligible SDP message is present and structurally accepted |
| `OBSERVED_INCOMPLETE` | SDP presence is established but the SIP or SDP evidence is incomplete |
| `OBSERVED_INVALID` | SDP presence is established but structural validation failed |
| `UNRESOLVED` | Presence or identity association cannot be established reliably |
| `OUT_OF_SCOPE` | Body present but not supported `application/sdp` |

Only `ABSENT` enables late-offer evaluation. Any other non-valid state publishes
`INITIAL_INVITE_SDP_EVIDENCE_UNUSABLE`; a later 2xx SDP cannot overwrite the
initial deficiency.

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
- `SDP_ANSWER_NOT_UNIQUE`
- `BRANCH_ASSOCIATION_AMBIGUOUS`
- `DIALOG_IDENTITY_NOT_ESTABLISHED`
- `BRANCH_REFERENCE_MISSING`
- `BRANCH_IDENTITY_NOT_ESTABLISHED`
- `BRANCH_RESPONSE_OWNERSHIP_UNPROVEN`
- `COMPETING_BRANCH_OWNERSHIP`
- `PROVISIONAL_FINAL_SDP_ROLE_UNRESOLVED`
- `RESPONSE_MESSAGE_TYPE_INVALID`
- `RESPONSE_STATUS_INVALID`
- `RESPONSE_CSEQ_METHOD_NOT_INVITE`
- `SIP_BODY_LENGTH_NOT_PROVEN`
- `INITIAL_INVITE_INVALID`
- `INITIAL_SDP_EVIDENCE_UNUSABLE`
- `SDP_MESSAGE_INVALID`

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

## Branch identity gate

An exchange is `ESTABLISHED` only when all of the following hold:

- an accepted IMS Session attempt owns the exchange;
- an accepted branch of that attempt owns the response;
- `branch_reference` is a non-null string;
- `dialog_reference` is a non-null string and the branch Dialog state is
  `CONFIRMED`;
- the accepted branch `identity_status` is `ESTABLISHED`;
- the response event reference belongs to that branch's accepted responses;
- no other accepted branch owns the same response reference.

Missing or insufficient identity is `INSUFFICIENT_EVIDENCE`. Conflicting
identity or competing ownership is `AMBIGUOUS`. No Dialog reference is created
or inferred from frame proximity, timestamps, ports, transport streams, SDP
identity or a matching status code.

## Provisional SDP role

When a branch has both provisional SDP and a final 2xx SDP, both observations
are preserved with exact references. The final response is not treated as a
uniquely established answer: the pair stays unestablished with
`PROVISIONAL_FINAL_SDP_ROLE_UNRESOLVED` and no offer/answer role claim. The
Domain does not implement 100rel, RSeq, RAck or PRACK association.

## Provenance integrity

Accepted SDP analysis must be internally consistent:

- root `capture_files` has exactly one capture and root `capture_sha256` is a
  lowercase 64-character hexadecimal SHA-256;
- every message `capture_file` equals the root capture, and every message
  `capture_sha256` equals the root SHA-256;
- every source reference capture, frame and occurrence equals the message
  `capture_file`, `frame_number` and `message_occurrence`;
- a `frame_reference` of the form `frame-<n>` agrees with `frame_number`; the
  contract does not define a canonical format for other values, so they are
  validated for presence only;
- root and provenance message counts equal the published message count;
- references are unique and accepted analysis and event schema versions match.

The SIP Event file SHA-256 is not the capture SHA-256. Only the IMS Session
`event_sha256` is compared with the supplied SIP Event file hash.

## Fail-closed rules

An association is never promoted to `ESTABLISHED` when any of the following is
true:

- the SIP Event or SDP message is missing or duplicated;
- capture, frame, message occurrence or SDP provenance disagrees;
- the SIP Event has no body or does not declare `application/sdp`;
- the SIP message is incomplete or its extraction status is not accepted;
- the SDP message is not `OBSERVED`;
- the initial SDP state is not `OBSERVED_VALID` for an initial pair, or not
  `ABSENT` for a late pair;
- the branch Dialog or branch identity is not established;
- a final response is not a `RESPONSE` with valid 2xx status and INVITE CSeq;
- provisional SDP leaves the final answer role unresolved;
- more than one SDP answer or ACK candidate competes.