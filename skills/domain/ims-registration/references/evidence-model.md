# Registration evidence model

## Separate dimensions

The analysis does not collapse registration evidence into one success/failure field.
The following dimensions are independent:

| Dimension | Values |
| --- | --- |
| registration type | `INITIAL_REGISTRATION_CANDIDATE`, `INITIAL_REGISTRATION_SUPPORTED`, `RE_REGISTRATION_CANDIDATE`, `REFRESH_OBSERVED`, `DEREGISTRATION_REQUESTED`, `UNDETERMINED` |
| authentication evidence | `NOT_OBSERVED`, `CHALLENGE_OBSERVED`, `RETRY_OBSERVED`, `CHALLENGE_RETRY_ASSOCIATED`, `CHALLENGE_WITHOUT_OBSERVED_RETRY`, `RETRY_WITHOUT_OBSERVED_CHALLENGE`, `AUTHENTICATION_OUTCOME_UNPROVED` |
| SIP outcome | `SUCCESS_RESPONSE_OBSERVED`, `NEGATIVE_RESPONSE_OBSERVED`, `OPEN_IN_CAPTURE`, `AMBIGUOUS`, `INCOMPLETE_EVIDENCE` |
| Diameter status | `OBSERVED`, `NOT_OBSERVED_IN_SUPPLIED_ARTIFACT`, `NOT_SUPPLIED`, `AMBIGUOUS`, `CONFLICTING` |
| cross-protocol association | `ESTABLISHED`, `SUPPORTED`, `AMBIGUOUS`, `NOT_ESTABLISHED`, `INSUFFICIENT_EVIDENCE` |

A SIP 200 OK remains distinct from authentication, Diameter application results and
network-side registration persistence.

## Top-level structure

```text
analysis_name
analysis_version
domain
capability
input_provenance
sip_registration_inventory
registration_attempts
diameter_ims_inventory
cross_protocol_associations
timeline
completeness
limitations
not_confirmed
```

## Registration attempt fields

- `attempt_reference`
- `capture_identity`
- `registration_type` and `registration_type_evidence`
- `authentication_evidence_status` and
  `authentication_cryptographically_verified`
- `sip_outcome`
- `transaction_references`
- `request_event_references`
- `response_event_references`
- `challenge_event_references`
- `retry_event_references`
- `final_response_event_references`
- `source_frame_references`
- `deregistration`
- `min_expires_evidence`
- `multi_hop_candidate`
- `cseq_observations`
- bounded omission counts
- `missing_evidence`
- `conflict_findings`
- `limitations` and `not_confirmed`

## Integrity rules

- Every reference resolves to an accepted SIP event or transaction.
- One transaction is assigned to at most one registration attempt.
- Attempt references are unique and deterministic.
- Published arrays are bounded; omission counts are explicit.
- `row_count` equals the published timeline rows plus omitted rows.
- `ESTABLISHED` cross-protocol association is rejected by semantic validation.
- `TERMINATED`, call success, RTP delivery and registration persistence are not
  modeled states and are never emitted.

## Timeline

Rows distinguish:

- SIP REGISTER request;
- SIP provisional response;
- SIP authentication challenge;
- SIP REGISTER retry;
- SIP final response;
- unassociated Diameter application observation.

For one capture, rows are ordered by frame. For independently generated or
different-capture inputs, rows are ordered per source capture and
`global_order_proven` is `false` with `SOURCE_LOCAL_ONLY`. No synchronized clock or
causal relationship is inferred from timestamps.

Diameter rows always carry `attempt_reference: null` because no identity bridge exists
in this phase. No Diameter message is presented as a stage of a particular SIP
attempt.

## Completeness

`completeness` reports observed SIP events and transactions, REGISTER transactions,
attempts, Diameter observations, associations and timeline rows, with explicit
omission accounting. Counts are derived from the actual published producer output.