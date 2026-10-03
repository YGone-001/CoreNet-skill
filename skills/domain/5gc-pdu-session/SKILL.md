# 5GC PDU Session

## Purpose

Analyze bounded 5GC PDU Session Establishment, Modification, and Release procedures and
immediate post-establishment / post-modification / post-release N3 user-plane observation evidence
at the procedure level: which stages of the reviewed 3GPP TS 23.502 PDU Session
Establishment, Modification, and Release procedures were directly observed, which expected
counterpart evidence is missing, which protocol-defined reject or negative outcome
was observed, which field finding supports each procedure-local deviation, which
evidence planes can be safely associated, which evidence remains ambiguous or unbound,
and what cannot be proven from the available capture. The Skill consumes already-extracted
structured evidence from nas-5gs, ngap, pfcp, gtpu, and sbi-http2, plus optional
cross-protocol-evidence correlation groups; it answers procedure questions, never
implementation questions.

## Scope

- Form evidence-safe procedure instances from NGAP UE context (capture_file,
  SCTP association context, ran_ue_ngap_id, amf_ue_ngap_id) and pdu_session_id,
  with frame-provenance NAS joins.
- Evaluate the 7 bounded establishment stages:
  1. `session_request` (N1 NAS-5GS)
  2. `sm_context_control` (N11 3GPP-SBI)
  3. `user_plane_control` (N4 PFCP)
  4. `access_resource_control` (N2 NGAP)
  5. `n1_n2_delivery` (N11 3GPP-SBI)
  6. `session_decision` (N1 NAS-5GS)
  7. `user_plane_observation` (N3 GTP-U)
- Repeated modification attempt modeling (0..N attempts per established session)
  with UE-requested and network-requested triggers. Attempts are formed only from
  N1 NAS anchors; cross-plane events are associated through an explicit
  candidate model with per-attempt control and observation windows. Frame
  position, timestamp, or nearest-attempt proximity never selects one attempt
  from several compatible candidates: ambiguous events remain attempt-unbound
  with explicit `unbound_evidence` records and `CORRELATION_AMBIGUITY`
  deviations, and every attempt-owned event is tracked by the deterministic
  reference `(protocol, capture_file, frame_number)` under `event_ownership`
  (one event never belongs to two attempts).
- Evaluate the 7 bounded modification stages per attempt:
  1. `modification_initiation` (N1 NAS-5GS)
  2. `sm_context_update` (N11 3GPP-SBI)
  3. `user_plane_control_update` (N4 PFCP)
  4. `access_resource_update` (N2 NGAP)
  5. `n1_n2_delivery` (N11 3GPP-SBI)
  6. `modification_completion` (N1 NAS-5GS)
  7. `post_modification_observation` (N3 GTP-U)
- Repeated release attempt modeling (0..N release attempts per lifecycle generation)
  with UE-requested, network-requested, and unknown triggers.
- Evaluate the 7 bounded release stages per attempt:
  1. `release_initiation` (N1 NAS-5GS)
  2. `sm_context_release_control` (N11 3GPP-SBI)
  3. `user_plane_teardown_control` (N4 PFCP)
  4. `access_resource_release` (N2 NGAP)
  5. `n1_n2_delivery` (N11 3GPP-SBI)
  6. `release_terminal` (N1 NAS-5GS)
  7. `post_release_observation` (N3 GTP-U)
- Lifecycle generation split: the same UE context re-using the same numeric PDU
  Session ID after an evidence-supported release boundary (PduSessionReleaseComplete
  observed) forms a distinct lifecycle instance; reuse without a proven boundary
  stays in one instance with a `LIFECYCLE_AMBIGUITY` deviation instead of an unsafe
  merge or split.
- Multi-plane evidence association across N1, N2, N3, N4, and N11 with explicit
  association strengths (`STRONG`, `SUPPORTED`, `AMBIGUOUS`, `UNBOUND`).
- Multi-UE isolation: procedure instances are anchored by NGAP UE context and
  PDU Session ID. PDU Session ID alone is never a global key; timestamp proximity
  alone never merges instances.
- Scoped transaction PTI: NAS PTI is scoped strictly per UE context and PDU Session.
  Concurrent modifications on different UEs with identical PTI remain strictly isolated.
- Ambiguous N11 preservation: sanitized subscriber identities across concurrent UEs
  with identical PDU Session IDs remain unbound in `unbound_evidence` with `CORRELATION_AMBIGUITY`.
- F-TEID directed tunnel binding: N3 GTP-U binds to N4 PFCP only when both the
  outer endpoint IP and header TEID match the provisioned F-TEID. Post-modification
  GTP-U additionally requires the attempt's bounded observation window plus a
  tunnel identity match (TEID + endpoint) against the attempt's signaled or
  established tunnel context, so concurrent and sequential attempts stay isolated.
  N2 transport-layer GTP-TEID evidence is kept distinct from N4 PFCP F-TEID
  provisioning and the two are never compared as a conflict.
- Item-scoped NGAP resource outcomes: evaluate NGAP resource lists per PDU Session
  ID item, preserving mixed success and failed outcomes without message-level collapse.
- Recognize protocol-defined rejections and negative causes across planes: 5GSM
  Cause on N1 Reject / Command Reject, ProblemDetails on N11 HTTP error, negative PFCP
  Cause on N4, failed resource items on N2, and delivery failure notification on N11.
- Detect cross-plane field conflicts (`FIELD_CONFLICT`) for UE IP address, QFI,
  and DNN/Network Instance, recording `CORRELATION_CONFLICT` deviations.
- Conditional post-modification N3 observation: absence of GTP-U within the
  attempt observation window is reported as `NOT_OBSERVED` with explicit
  limitations, never as a missing required counterpart or user-plane failure.
- QFI findings use evidence-bounded neutral wording unless PFCP explicitly
  supplies a QER create/update/remove operation binding the QFI.
- Emit generic procedure-evidence stage JSONL and a deterministic analysis
  summary JSON, plus a per-instance PDU session timeline.

## Non-Goals

- No raw PCAP parsing and no NAS, NGAP, PFCP, GTP-U, or HTTP/2 byte-level decoding.
- No subscriber identity exposure: IMSI, SUPI, and PEI are redacted or absent.
- No success, failure, or root-cause verdicts: Accept is terminal protocol signaling,
  never application-plane success; negative cause is protocol evidence, never network
  function blame; missing GTP-U traffic is never reported as `USER_PLANE_FAILED`.
- Handover, path switch, UPF relocation, multi-access, and EPS interworking remain deferred.
- UE deregistration as a complete Domain procedure and implicit global UE-context teardown remain deferred.
- No Open5GS, free5GC, or vendor source-code mappings.

## Inputs

- `--nas`: NAS-5GS detailed event JSONL (repeatable).
- `--ngap`: NGAP detailed event JSONL (repeatable).
- `--pfcp`: PFCP detailed event JSONL (repeatable).
- `--gtpu`: GTP-U detailed event JSONL (repeatable).
- `--sbi`: SBI-HTTP2 detailed event JSONL (repeatable).
- `--correlation`: cross-protocol-evidence correlation-event JSONL (optional).
- `--input-dir`: directory containing protocol event JSONL files.

## Outputs

- `scripts/analyze_pdu_session.py [INPUTS] --output analysis.json [--stages-output stages.jsonl]`
- `scripts/pdu_session_timeline.py analysis.json [--format text|json]`
- The analysis summary conforms to `schemas/5gc-pdu-session-analysis.schema.json`;
  stage JSONL conforms to the generic procedure-evidence schema (byte-identical
  package-local copy under `schemas/`).

## Dependencies

Required: `[]` (standalone package).
Optional: `procedure-evidence >=0.1.0`, `cross-protocol-evidence >=0.1.0`,
`nas-5gs >=0.2.0`, `ngap >=0.2.0`, `pfcp >=0.1.0`, `gtpu >=0.1.0`, `sbi-http2 >=0.2.0`.

## Workflow

1. Obtain structured event JSONL files from lower-layer Protocol Skills.
2. Run `analyze_pdu_session.py` to evaluate procedure instances, stage progression,
   repeated modification attempts, deviations, and field findings.
3. Check observation-window limitations: capture start and end bound every
   missing-evidence statement.
4. Render `pdu_session_timeline.py` for chronological per-instance tracking.
5. Hand multi-procedure composition to Analysis Orchestration.

## Evidence Rules

- OBSERVED: directly visible protocol events, causes, status codes, and items.
- DERIVED: instance formation, frame joins, F-TEID bindings, stage assignment,
  conflict detection, duplicate detection, and earliest observed deviation.
- INFERRED: procedure interpretation strongly supported but not directly determined.
- HYPOTHESIS: candidate explanations requiring further evidence.
- CONFIRMED: never used as shorthand for implementation root cause.

## Failure Handling

Malformed input records, missing required provenance fields, forbidden verdict wording,
and unsafe output replacement fail loudly with non-zero exit codes. Ambiguous or
unresolvable records remain UNBOUND in `unbound_evidence`.

## Validation

Run `python -m unittest tests/test_5gc_pdu_session.py` from this package.
Repository checkouts also run `scripts/validate-5gc-pdu-session.py`.

## References

- `references/procedure-model.md`: TS 23.502 procedure model and partial ordering.
- `references/stage-model.md`: 7 establishment stages, 7 modification stages, and 7 release stages.
- `references/association-model.md`: multi-plane binding rules, PTI scoping, and isolation.
- `references/deviation-model.md`: procedure deviations and earliest deviation.
- `references/field-findings.md`: field findings and conflict handling.
- `references/failure-cases.md`: catalog of failure boundaries.
