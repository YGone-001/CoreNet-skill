# Registration evidence model

## Separate dimensions

The analysis does not collapse registration evidence into one success/failure field.
The following dimensions are independent:

| Dimension | Values |
| --- | --- |
| registration type | `INITIAL_REGISTRATION_CANDIDATE`, `INITIAL_REGISTRATION_SUPPORTED`, `RE_REGISTRATION_CANDIDATE`, `REFRESH_OBSERVED`, `DEREGISTRATION_REQUESTED`, `UNDETERMINED` |
| authentication evidence | `NOT_OBSERVED`, `CHALLENGE_OBSERVED`, `RETRY_OBSERVED`, `CHALLENGE_RETRY_ASSOCIATED`, `CHALLENGE_WITHOUT_OBSERVED_RETRY`, `RETRY_WITHOUT_OBSERVED_CHALLENGE`, `RETRY_NOT_ESTABLISHED`, `AUTHENTICATION_OUTCOME_UNPROVED` |
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
- `deregistration`, containing the attempt-level summary plus
  `transaction_observations`; each observation binds one REGISTER transaction's
  removal request, scope, request validity, Contact boundary status, wildcard-boundary
  classification, matching final response reference, response code and
  unproved-or-supported outcome
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
- For inventory entries, attempts, Diameter observations, associations and timeline
  rows, `total_observed = published_count + omitted_count`. Source totals are
  computed before publication caps are applied.
- Each attempt exposes omission counts for transaction, request, response, challenge,
  retry, final-response and source-frame reference collections.
- Published associations and timeline rows never point to an omitted attempt.
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

`ordering_scope` distinguishes `SIP_ONLY_SINGLE_CAPTURE`,
`SIP_ONLY_MULTI_CAPTURE`, `DIAMETER_ONLY_SINGLE_CAPTURE`,
`DIAMETER_ONLY_MULTI_CAPTURE`, `CROSS_SOURCE_UNVERIFIED` and
`VERIFIED_COMMON_CAPTURE`. A SIP and Diameter row set is `CROSS_SOURCE_UNVERIFIED`
and `global_order_proven` stays `false` unless common capture provenance is
independently verified. Matching filenames, frame numbers, timestamps or application
success are not such verification.

Diameter rows always carry `attempt_reference: null` because no identity bridge exists
in this phase. No Diameter message is presented as a stage of a particular SIP
attempt.

## Completeness

`completeness` reports observed SIP events and transactions, REGISTER transactions,
attempts, Diameter observations, associations and timeline rows, with explicit
omission accounting. Counts are derived from the actual published producer output.