# Failure Cases

All failures are deterministic. Contract failures return a non-zero exit and
publish no analysis. Evidence-level gaps remain in the analysis with an explicit
status and reason code.

## Input contract failures (exit `2`)

| Case | Behavior |
|---|---|
| SIP Event schema version unsupported | Rejected |
| Duplicate SIP Event source references | Rejected |
| SIP Events mix capture identity | Rejected |
| Duplicate SDP source references | Rejected |
| SDP `analysis_name`, `analysis_version` or `event_schema_version` unsupported | Rejected |
| IMS Session analysis name, version or structural contract invalid | Rejected through the accepted IMS Session validator |
| IMS Session `event_sha256` differs from the supplied SIP Event file | Rejected |
| IMS Session capture identity differs from the SIP Event capture | Rejected |
| IMS Session references a missing SIP Event | Rejected |
| SDP capture identity differs from the SIP Event capture | Rejected |
| SDP message capture identity is inconsistent with its source reference | Rejected |
| Output destination collides with an input artifact | Rejected |
| Output exists without `--force` | Rejected |

## Evidence-level gaps (exit `0`, explicit status)

| Case | Required behavior |
|---|---|
| SIP Event declares SDP but no SDP message was supplied | `SDP_MESSAGE_NOT_OBSERVED` |
| SDP message exists but the SIP Event has no body | `SIP_BODY_NOT_PRESENT` |
| SIP Event body is not `application/sdp` | `SIP_CONTENT_TYPE_NOT_SDP` |
| SIP message is incomplete or truncated | `INSUFFICIENT_EVIDENCE` with `SIP_MESSAGE_INCOMPLETE` |
| SDP message is incomplete | `SDP_MESSAGE_INCOMPLETE` |
| SDP message is invalid or ambiguous | `SDP_MESSAGE_NOT_OBSERVED` |
| SDP message is unsupported | `OUT_OF_SCOPE` with `SDP_MESSAGE_UNSUPPORTED` |
| Initial INVITE has no SDP | `INITIAL_INVITE_WITHOUT_SDP`, not a failure |
| Initial INVITE offer has no final SDP answer | `INSUFFICIENT_EVIDENCE`, `SDP_ANSWER_NOT_OBSERVED` |
| Two 2xx responses on one branch carry SDP | `AMBIGUOUS`, `COMPETING_SDP_CANDIDATES` |
| Late offer has no SDP-bearing 2xx ACK | `INSUFFICIENT_EVIDENCE`, `LATE_OFFER_ACK_NOT_OBSERVED` |
| Two SDP-bearing ACKs compete | `AMBIGUOUS`, `COMPETING_SDP_CANDIDATES` |
| SDP in 18x response | `PROVISIONAL_SDP_UNINTERPRETED`, `OUT_OF_SCOPE` |
| SDP in PRACK, re-INVITE, UPDATE or INFO | `OUT_OF_SCOPE`, `IN_DIALOG_SDP_OUT_OF_SCOPE` |
| SDP in a non-2xx final response | `OUT_OF_SCOPE`, `NON_2XX_FINAL_SDP_OUT_OF_SCOPE` |
| SDP message with no matching SIP Event | `UNMATCHED_SDP_MESSAGE`, `SIP_EVENT_NOT_FOUND` |
| SDP-bearing SIP Event without an accepted branch owner | `UNBOUND_SIP_SDP_EVENT` |

## Initial SDP state separation

| Case | Required behavior |
|---|---|
| INVITE with no body, zero content length and complete extraction | `ABSENT` and `INITIAL_INVITE_WITHOUT_SDP` |
| INVITE with an accepted SDP message | `OBSERVED_VALID` |
| INVITE with SDP evidence marked incomplete | `OBSERVED_INCOMPLETE` and `INITIAL_INVITE_SDP_EVIDENCE_UNUSABLE` |
| INVITE with SDP evidence marked invalid | `OBSERVED_INVALID` and `INITIAL_INVITE_SDP_EVIDENCE_UNUSABLE` |
| INVITE declares SDP but the SDP analysis lacks the message | `UNRESOLVED`, never `ABSENT` |
| INVITE body exists but Content-Type is not `application/sdp` | `OUT_OF_SCOPE`, never a late offer |
| Invalid initial SDP followed by a 2xx SDP | No established late offer |
| Unsupported initial Content-Type followed by a 2xx SDP | No established late offer |

## Branch identity failures

| Case | Required behavior |
|---|---|
| Missing Confirmed Dialog reference | `INSUFFICIENT_EVIDENCE`, `DIALOG_IDENTITY_NOT_ESTABLISHED` |
| Missing branch reference | `INSUFFICIENT_EVIDENCE`, `BRANCH_REFERENCE_MISSING` |
| Identity marked insufficient or not established | `INSUFFICIENT_EVIDENCE`, `BRANCH_IDENTITY_NOT_ESTABLISHED` |
| Identity marked ambiguous | `AMBIGUOUS`, `COMPETING_BRANCH_OWNERSHIP` |
| Response not owned by the accepted branch | `INSUFFICIENT_EVIDENCE`, `BRANCH_RESPONSE_OWNERSHIP_UNPROVEN` |
| One response claimed by two accepted branches | `AMBIGUOUS`, `COMPETING_BRANCH_OWNERSHIP` |

## Response role failures

| Case | Required behavior |
|---|---|
| 2xx status on a non-`RESPONSE` message | Not an answer; `RESPONSE_MESSAGE_TYPE_INVALID` |
| 2xx status with `status_code_valid = false` | Not an answer; `RESPONSE_STATUS_INVALID` |
| 2xx response with a non-INVITE CSeq method | Not an answer; `RESPONSE_CSEQ_METHOD_NOT_INVITE` |
| Incomplete response extraction | Not an answer; `SIP_MESSAGE_INCOMPLETE` |
| Provisional SDP plus final 2xx SDP in one branch | `AMBIGUOUS`, `PROVISIONAL_FINAL_SDP_ROLE_UNRESOLVED` |

## Provenance failures

| Case | Required behavior |
|---|---|
| SDP root and message capture SHA-256 differ | Rejected, exit `2` |
| SDP source reference frame differs from `frame_number` | Rejected, exit `2` |
| SDP `frame-<n>` reference differs from `frame_number` | Rejected, exit `2` |
| SDP message occurrence differs from its source reference | Rejected, exit `2` |
| SDP message `capture_file` differs from the root | Rejected, exit `2` |
| Duplicate SDP source references | Rejected, exit `2` |
| SIP Event file hash differs from the IMS Session declaration | Rejected, exit `2` |

No analysis output is written after a provenance failure.

## Branch failures

| Case | Required behavior |
|---|---|
| Missing Confirmed Dialog identity | The exchange remains attributable through the accepted response reference; `dialog_reference` is `null` |
| Missing branch identity | The exchange remains attributable through the accepted attempt; `branch_reference` is `null` |
| One accepted and one rejected fork | The accepted branch keeps its own answer; the rejected SDP is out of scope |
| Two initial INVITEs share a Call-ID | Each accepted attempt is processed independently |
| ACK belongs to another branch | The affected branch remains `INSUFFICIENT_EVIDENCE`; no cross-branch assignment |

## Missing evidence versus network outcome

A missing 2xx answer, missing ACK, provisional-only SDP or out-of-scope SDP body
is capture or scope incompleteness. It is never a SIP timeout, call failure,
media delivery failure or IMS service verdict.

## Bounded output

If more than 64 exchanges or observations are produced, the published arrays are
bounded and the overflow is recorded in `omitted_observation_count`. No evidence
is silently dropped without a count.