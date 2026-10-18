# Golden Capture Adjudication Reconciliation Against the Current Runtime

Record type: sanitized, documentation-only reconciliation report.

Applies to: the six Golden Capture cases whose committed adjudications remain unresolved.

Nothing is changed by this report. The per-case adjudication files under `cases/`
remain the historical record; frozen benchmark artifacts, Skills, schemas, scoring
logic, and denominators are untouched. Each confirmed defect identified here
requires separate authorization before any correction is implemented.

## 1. Purpose and Scope

The committed per-case adjudications were produced against runtime
`603075bcb550225acd10bc5df5dacf33ce0e4589`. Since then the repository accepted the
corrections referenced by those adjudications (corr-01, corr-02, corr-03, corr-04
and the cause-21 recovered-outcome reclassification) and refreshed the benchmark
artifacts. This report reconciles every historical adjudication finding for the
following six cases against the current runtime:

- public-5gc-auth-negative
- public-5gc-auth-recovery
- public-5gc-baseline-lifecycle
- public-5gc-baseline-user-plane
- public-5gc-dnn-recovery
- public-5gc-registration-resync

The seventh adjudicated case file (public-5gc-dnn-negative) is outside this
reconciliation's scope.

## 2. Runtime Provenance

### 2.1 Historical adjudication records

| Case | Adjudication revision | Historical runtime | Baseline status | Historical comparison status | Historical first differing layer | Items |
| --- | --- | --- | --- | --- | --- | --- |
| public-5gc-auth-negative | 1 | 603075bc | BOUNDARY_OBSERVED | NEEDS_ADJUDICATION | DOMAIN_INSTANCE_FORMATION | 8 |
| public-5gc-auth-recovery | 1 | 603075bc | NO_SUPPORTED_ABNORMAL_BOUNDARY_OBSERVED | NEEDS_ADJUDICATION | DOMAIN_DEVIATION_EMISSION | 15 |
| public-5gc-baseline-lifecycle | 1 | 603075bc | NO_SUPPORTED_ABNORMAL_BOUNDARY_OBSERVED | NEEDS_ADJUDICATION | DOMAIN_DEVIATION_EMISSION | 15 |
| public-5gc-baseline-user-plane | 1 | 603075bc | NO_SUPPORTED_ABNORMAL_BOUNDARY_OBSERVED | NEEDS_ADJUDICATION | DOMAIN_DEVIATION_EMISSION | 15 |
| public-5gc-dnn-recovery | 1 | 603075bc | NO_SUPPORTED_ABNORMAL_BOUNDARY_OBSERVED | NEEDS_ADJUDICATION | DOMAIN_DEVIATION_EMISSION | 15 |
| public-5gc-registration-resync | 1 | 603075bc | NO_SUPPORTED_ABNORMAL_BOUNDARY_OBSERVED | NEEDS_ADJUDICATION | DOMAIN_DEVIATION_EMISSION | 17 |

All six historical records cite the same pinned external capture source commit,
`82934c2cc231540fa425e48177d4bed33210bfc1`, which is also frozen in every per-case
record and in the benchmark summary.

### 2.2 Accepted corrections between the two runtimes

- corr-01: the Domain layer stopped republishing lower-layer UNKNOWN support
  status as UNKNOWN_OR_RESERVED_PROTOCOL_VALUE deviations when the capture
  contains no message-type value at all (a protected envelope without a decodable
  inner octet is handled separately).
- corr-02: PDU-session reconstruction stopped emitting PARTIAL_CAPTURE deviations
  from fallback associations that carry no observable session identity and no
  window anchor.
- corr-03: stage-less absence candidates were removed, and window-bounded
  MISSING_EXPECTED_COUNTERPART deviations were converted into stage-level
  evidence limitations attached to the stage records that own the position.
- corr-04, together with the accepted cause-21 runtime change: an authentication
  failure with decoded synchronization-failure cause 21 that is followed by
  same-cycle recovery evidence is emitted as
  RECOVERED_INTERMEDIATE_OUTCOME_OBSERVED and is classified as a non-candidate
  intermediate outcome.

### 2.3 Current runtime and reproduction evidence

Current runtime: `f067db7a2fe2daf4893cfc721fa3d9486c71a81a`, which adds test-only
coverage over `d271f02` and is runtime-equivalent to it; the refreshed benchmark
artifacts record provenance `d271f02`.

Reproduction method: the full public-corpus pipeline was rerun for all 13 public
cases from the pinned external capture collection at source commit
`82934c2cc231540fa425e48177d4bed33210bfc1` (repository
`abdelrahman-fawaz18/5g-sa-core-protocol-lab`, as already recorded in every frozen
per-case record), using TShark 4.7.1, in an external work directory outside the
repository. The regenerated sanitized per-case artifacts were compared
byte-for-byte with the committed benchmark artifacts: 52 identical (four files
for each of the 13 cases: the frozen case record, the sanitized human-baseline
record, the sanitized skill-result summary, and the sanitized differential
record), 0 different, 0 missing. The aggregate benchmark summary differs only in
its recorded runtime commit and generation timestamp, which are provenance
metadata refreshed by design. The current-runtime evidence examined below is
therefore exactly the committed benchmark evidence.

## 3. Classification Vocabulary

Each reconciled finding is classified as exactly one of:

- ALREADY_CORRECTED_DEFECT: a historical finding whose defective record is no
  longer emitted, or has been reclassified into its corrected form, by a
  previously accepted correction.
- LEGITIMATE_EVIDENCE_LIMITATION_STILL_EMITTED: a still-emitted record that
  correctly reports a capture limitation and invents nothing.
- NON_BOUNDARY_SUPPORTING_ANOMALY: a still-emitted record that documents
  procedure-relevant behavior without being, or producing, a boundary candidate.
- REMAINING_UNSUPPORTED_DEVIATION: a still-emitted record that the packet
  evidence does not support.
- DOMAIN_RECONSTRUCTION_DEFECT: a confirmed defect in Domain evidence
  reconstruction.
- ORCHESTRATION_CLASSIFICATION_DEFECT: a confirmed defect in Orchestration
  classification or selection.
- MISSING_SEMANTIC_INFO_IN_SUMMARIES: the sanitized summaries lack semantics
  needed to resolve a comparison without adjudication.
- UNRESOLVABLE_WITH_CURRENT_EVIDENCE: the question cannot be answered from the
  available packet evidence and frozen records without inventing detail or
  editing a frozen record.

## 4. Six-Case Comparison Matrix

| Case | Independent baseline | Current comparison status | Layer attribution | Current relevant-domain deviations | Orchestration treatment | Reconciliation outcome |
| --- | --- | --- | --- | --- | --- | --- |
| public-5gc-auth-negative | BOUNDARY_OBSERVED, frame 11, stage label "security" | NEEDS_ADJUDICATION | UNKNOWN | registration: 2; PDU-session: none reconstructed | 2 candidates; frame-11 candidate selected, HIGH confidence | Boundary anchor agrees; stage dimension unresolved (Domain emission gap plus baseline label without direct packet support) |
| public-5gc-auth-recovery | NO_SUPPORTED_ABNORMAL_BOUNDARY_OBSERVED | NEEDS_ADJUDICATION | DOMAIN | registration: 5; PDU-session: 1 | no candidates; NO_ABNORMAL_BOUNDARY_OBSERVED | All deviations are legitimate non-candidate evidence limitations; summaries lack the semantics to show this |
| public-5gc-baseline-lifecycle | NO_SUPPORTED_ABNORMAL_BOUNDARY_OBSERVED | NEEDS_ADJUDICATION | DOMAIN | registration: 5; PDU-session: 1 | no candidates; NO_ABNORMAL_BOUNDARY_OBSERVED | Same pattern as auth-recovery |
| public-5gc-baseline-user-plane | NO_SUPPORTED_ABNORMAL_BOUNDARY_OBSERVED | NEEDS_ADJUDICATION | DOMAIN | registration: 5; PDU-session: 1 | no candidates; NO_ABNORMAL_BOUNDARY_OBSERVED | Same pattern as auth-recovery |
| public-5gc-dnn-recovery | NO_SUPPORTED_ABNORMAL_BOUNDARY_OBSERVED | NEEDS_ADJUDICATION | DOMAIN | registration: 5; PDU-session: 1 | no candidates; NO_ABNORMAL_BOUNDARY_OBSERVED | Same pattern as auth-recovery |
| public-5gc-registration-resync | NO_SUPPORTED_ABNORMAL_BOUNDARY_OBSERVED | NEEDS_ADJUDICATION | DOMAIN | registration: 6 (including the recovered-outcome record); PDU-session: 1 (not relevant to the baseline's observed families) | no candidates; NO_ABNORMAL_BOUNDARY_OBSERVED | Recovered outcome correctly reclassified and non-candidate; remaining deviations are legitimate limitations; summaries lack the semantics to show this |

The current differential note for the five healthy-spectrum cases reads "6
deviation(s)". The count is the sum of deviation counts over the Domains the
baseline makes relevant: registration plus PDU-session where the baseline
observed a PDU-session procedure (5 + 1), and registration alone for
public-5gc-registration-resync because its baseline observes only
registration-family procedures and its registration instance carries six
deviations.

## 5. Case Reconciliation Detail

### 5.1 public-5gc-auth-negative

Capture: `captures/fault-injection/authentication-key-mismatch/fault.pcap`
(16 frames; capture digest frozen in the per-case record). Registration instance
`5gc-reg:fault.pcap:sctp-assoc-65535:r1`, observation window frames 9-15.
PDU-session instances: none reconstructed (the capture exposes no observable
PDU-session identity; see the corr-02 mapping below).

Stage records at instance level: registration-initiation (confidence MEDIUM,
evidence OBSERVED, with a recorded evidence limitation because no accept or
reject is observable), authentication (confidence HIGH, evidence OBSERVED;
request frame 10, failure frame 11, reject frame 12), context-release
(confidence HIGH, evidence OBSERVED; command frame 13, complete frame 15).

Current deviations: UNSUCCESSFUL_OUTCOME_OBSERVED at frame 11 (NAS-5GS
Authentication failure with decoded 5GMM cause 20) and PROTOCOL_REJECT_OBSERVED
at frame 12 (NAS-5GS Authentication reject). Both carry a null stage identity and
EVENT evidence references at OBSERVED level.

Historical-to-current mapping (8 items):

| Historical item | Finding | Historical status | Current state | Classification |
| --- | --- | --- | --- | --- |
| adj-01 | UNSUCCESSFUL_OUTCOME_OBSERVED, frame 11 | SUPPORTED_BY_PACKET_EVIDENCE | still emitted; selected boundary | LEGITIMATE_EVIDENCE_LIMITATION_STILL_EMITTED is not applicable; this is a supported observation, still correct (no defect) |
| adj-02 | PROTOCOL_REJECT_OBSERVED, frame 12 | SUPPORTED_BY_PACKET_EVIDENCE | still emitted; candidate not selected | supported observation, still correct (no defect) |
| adj-03 | MISSING_EXPECTED_COUNTERPART (window-bounded) | VALID_CAPTURE_LIMITATION | no longer emitted; the registration-initiation stage record carries the evidence limitation | ALREADY_CORRECTED_DEFECT (corr-03) |
| adj-04 | PARTIAL_CAPTURE, PDU-session, no evidence references | UNSUPPORTED_BY_PACKET_EVIDENCE (corr-02) | no PDU-session instance reconstructed | ALREADY_CORRECTED_DEFECT (corr-02) |
| adj-05 | PARTIAL_CAPTURE, PDU-session, fallback identity | UNSUPPORTED_BY_PACKET_EVIDENCE (corr-02) | no PDU-session instance reconstructed | ALREADY_CORRECTED_DEFECT (corr-02) |
| adj-06 | MISSING_EXPECTED_COUNTERPART candidate (1-cand-1), stage-less | POTENTIALLY_SPURIOUS (corr-03) | candidate no longer generated | ALREADY_CORRECTED_DEFECT (corr-03) |
| adj-07 | PROTOCOL_REJECT_OBSERVED candidate, frame 12 | SUPPORTED_BY_PACKET_EVIDENCE | candidate present (renumbered), not selected | supported observation, still correct (no defect) |
| adj-08 | UNSUCCESSFUL_OUTCOME_OBSERVED candidate, frame 11 | SUPPORTED_BY_PACKET_EVIDENCE | candidate present (renumbered), SELECTED | supported observation, still correct (no defect) |

#### 5.1.1 Stage-identifier availability (reconciliation question set)

Question: does the current Domain output contain a usable stage identifier for
the selected boundary?

Answer: yes at instance level, no at deviation level. The registration
instance's stage records contain an authentication stage with HIGH confidence
whose observed evidence spans frames 10, 11 and 12 - exactly the frames of both
current deviations. However, both deviation records carry a null stage identity.
This is systemic, not case-specific: in the current Domain emitter, event-derived
deviation records (unsuccessful outcome, protocol reject, recovered intermediate
outcome, protected-envelope, unknown-value) are constructed with a literal null
stage identity, while absence-shaped deviations (missing counterpart, partial
capture) do carry their stage identity.

Question: does Orchestration preserve a usable stage identifier?

Answer: Orchestration consumes the deviation record. It maps the candidate
procedure stage from the deviation's stage identity and does not use the
instance-level stage records for candidate semantics, so the null passes through
unchanged and nothing is invented. No Orchestration defect is observed in this
case: selection picked the frame-11 candidate, consistent with the independent
baseline's frame-11 boundary anchor, and the frame-12 reject remained a
non-selected candidate.

Question: does the sanitized Skill summary discard a valid stage?

Answer: no. The summary reports the null it receives from Orchestration. The
information loss occurs at Domain deviation emission, not at summary
sanitization.

Question: is the baseline stage label "security" directly supported by the
packet evidence and the procedure semantics modeled here?

Answer: no. The capture exposes the authentication procedure: challenge at
frame 10, Authentication failure with decoded 5GMM cause 20 at frame 11,
Authentication reject at frame 12, followed by NGAP context release at frames
13-15. No security-mode exchange is present in the capture; the registration
procedure's security-mode stage never started. Under the procedure model, the
directly packet-supported stage identity for frames 10-12 is the authentication
stage. The baseline label "security" is therefore not directly supported by the
packet evidence, and equating it with any pipeline stage would require inventing
stage semantics. Classification: UNRESOLVABLE_WITH_CURRENT_EVIDENCE for the
label-equivalence question itself, plus a confirmed DOMAIN_RECONSTRUCTION_DEFECT
for the missing stage identity on event-derived deviations (independent of the
baseline label).

Consequence: the current comparison status NEEDS_ADJUDICATION with layer
attribution UNKNOWN remains the correct outcome. The comparator cannot establish
exact boundary equivalence because the summary side reports no stage and the
baseline side reports a label the packets do not directly support; assuming a
match would require inventing detail on one of the two sides.

### 5.2 Healthy-spectrum common pattern

public-5gc-auth-recovery, public-5gc-baseline-lifecycle,
public-5gc-baseline-user-plane and public-5gc-dnn-recovery share one evidence
pattern, and public-5gc-registration-resync shares it with one addition covered
in section 5.4.

Per-case registration instance deviations:

- Five PROTECTED_INNER_MESSAGE_UNAVAILABLE records, each OBSERVED with an EVENT
  evidence reference to one protected NAS-5GS envelope frame, null stage
  identity, and a description stating that a protected NAS envelope at that
  frame carried no decodable inner message. These are legitimate capture
  limitations: the inner message identity is genuinely undecodable in these
  captures, and the records invent no message type, cause, or outcome.

- One PARTIAL_CAPTURE record on the PDU-session instance: DERIVED, with an
  OBSERVATION_WINDOW evidence reference, stage identity `session_request`, and a
  description stating that the observation window begins after the procedure's
  initiation evidence. The historical adj-13 in each case confirmed this as a
  valid capture limitation: the session identity is observable on the NGAP
  PDU-session resource messages, while the N1 session-management request sits
  inside a protected envelope.

Stage-level evidence limitations (not deviations): the registration-initiation
record documents that no Registration accept or reject is observable and that
this absence is an evidence limitation rather than an asserted missing
counterpart; the security-mode record documents that the expected NAS
counterpart may be inside the protected envelopes, so its absence is likewise
recorded as an evidence limitation.

Orchestration: no deviation became a candidate; status
NO_ABNORMAL_BOUNDARY_OBSERVED; one diagnostic group per case.

Historical mapping (15 items per case; public-5gc-registration-resync has 17,
covered in section 5.4):

| Historical items | Finding | Historical status | Current state | Classification |
| --- | --- | --- | --- | --- |
| adj-01 | MISSING_EXPECTED_COUNTERPART, security-mode completion | VALID_CAPTURE_LIMITATION | no longer emitted; stage-level evidence limitation on the security-mode stage record | ALREADY_CORRECTED_DEFECT (corr-03) |
| adj-02, 04, 06, 08, 10 | UNKNOWN_OR_RESERVED_PROTOCOL_VALUE, five protected-envelope frames | UNSUPPORTED_BY_PACKET_EVIDENCE (corr-01) | no longer emitted | ALREADY_CORRECTED_DEFECT (corr-01) |
| adj-03, 05, 07, 09, 11 | PROTECTED_INNER_MESSAGE_UNAVAILABLE, same five frames | VALID_CAPTURE_LIMITATION | still emitted at the same frames | LEGITIMATE_EVIDENCE_LIMITATION_STILL_EMITTED; for Orchestration, NON_BOUNDARY_SUPPORTING_ANOMALY |
| adj-12 | MISSING_EXPECTED_COUNTERPART, registration decision | VALID_CAPTURE_LIMITATION | no longer emitted; stage-level evidence limitation on the registration-decision stage record | ALREADY_CORRECTED_DEFECT (corr-03) |
| adj-13 | PARTIAL_CAPTURE, PDU-session | VALID_CAPTURE_LIMITATION | still emitted, window-anchored, stage `session_request` | LEGITIMATE_EVIDENCE_LIMITATION_STILL_EMITTED; NON_BOUNDARY_SUPPORTING_ANOMALY |
| adj-14, 15 | MISSING_EXPECTED_COUNTERPART candidates, stage-less | POTENTIALLY_SPURIOUS (corr-03) | candidates no longer generated | ALREADY_CORRECTED_DEFECT (corr-03) |

### 5.3 Per-case evidence anchors

| Case | Protected-envelope frames | Registration window | Security-mode command frame | PDU-session window |
| --- | --- | --- | --- | --- |
| public-5gc-auth-recovery | 13, 14, 17, 18, 19 | 9-25 | 12 | 19-23 |
| public-5gc-baseline-lifecycle | 13, 14, 17, 18, 21 | 9-60 | 12 | 19-58 |
| public-5gc-baseline-user-plane | 7, 8, 11, 12, 15 | 1-17 | 6 | 2-49 |
| public-5gc-dnn-recovery | 13, 14, 17, 18, 21 | 9-31 | 12 | 19-29 |
| public-5gc-registration-resync | 45, 46, 49, 50, 51 | 39-53 | 44 | 51-53 |

### 5.4 public-5gc-registration-resync specifics

The independent baseline records two observations: an authentication
resynchronization procedure with outcome RESYNCHRONIZED over frames 40-43, and a
registration procedure with outcome COMPLETE over frames 39-49, with supporting
evidence at frame 40 (Authentication request) and frame 41 (Authentication
failure with synchronization-failure cause).

Current registration deviations: the five protected-envelope records of section
5.2 plus one RECOVERED_INTERMEDIATE_OUTCOME_OBSERVED record: OBSERVED, with
EVENT references to frame 41 (Authentication failure, decoded 5GMM cause 21),
frame 42 (Authentication request, same-cycle re-challenge) and frame 43
(Authentication response), describing the intermediate outcome as recovered. The
record is non-candidate by construction.

Historical mapping of the two resync-specific items:

| Historical item | Finding | Historical status | Current state | Classification |
| --- | --- | --- | --- | --- |
| adj-02 | UNSUCCESSFUL_OUTCOME_OBSERVED, frame 41 | SUPPORTED_BY_PACKET_EVIDENCE | reclassified: emitted as RECOVERED_INTERMEDIATE_OUTCOME_OBSERVED with recovery evidence frames 41-43 | ALREADY_CORRECTED_DEFECT (corr-04 and the accepted cause-21 reclassification); the current record is a correct NON_BOUNDARY_SUPPORTING_ANOMALY |
| adj-17 | UNSUCCESSFUL_OUTCOME_OBSERVED candidate, frame 41 | POTENTIALLY_SPURIOUS (corr-04) | candidate no longer generated; the deviation is a non-candidate intermediate outcome | ALREADY_CORRECTED_DEFECT (corr-04) |

The remaining resync items follow the common pattern of section 5.2 (security-mode
completion, five unknown-or-reserved, five protected-envelope, registration
decision, PDU-session partial capture, two stage-less candidates), giving 11
corrected items and 6 still-emitted legitimate items for this case.

### 5.5 Why the five healthy-spectrum cases still compare as NEEDS_ADJUDICATION

The comparator's logic is faithful: when the independent baseline records
NO_SUPPORTED_ABNORMAL_BOUNDARY_OBSERVED, the pipeline reports
NO_ABNORMAL_BOUNDARY_OBSERVED, and the relevant Domain instances report a
positive deviation count, the comparison is NEEDS_ADJUDICATION with layer
attribution DOMAIN, because a scalar count cannot distinguish substantive
deviations from evidence limitations.

Per this reconciliation, every deviation currently counted for these five cases
is a legitimate capture limitation or a corrected-form record, and none is
candidate-eligible. The comparator cannot know this because the sanitized
summary's per-Domain status carries only a scalar deviation count, with no
per-type breakdown and no candidate-eligibility semantics. Classification:
MISSING_SEMANTIC_INFO_IN_SUMMARIES. This is not a Domain emission defect for
these cases: the records themselves are correctly emitted and correctly
non-candidate.

## 6. Resolved Findings (Evidence-Backed)

Across the six cases, 85 historical adjudication items were reconciled by
evidence-identity matching on (case, source Domain, deviation type, frame anchor
or observation window), cross-checked against the historical rationale text and
the reproduced current artifacts.

- 51 items are resolved by previously accepted corrections: 4 in
  public-5gc-auth-negative (corr-02 twice, corr-03 twice), 9 in each of the four
  recovery/baseline cases (corr-01 five times, corr-03 four times), and 11 in
  public-5gc-registration-resync (corr-01 five times, corr-03 four times, corr-04
  twice). The corresponding defective records are no longer emitted or have been
  reclassified into their corrected forms.
- 34 items remain emitted and are confirmed legitimate by this reconciliation:
  supported boundary observations (public-5gc-auth-negative), valid
  protected-envelope capture limitations, and the window-anchored PDU-session
  partial-capture limitations.
- 0 items remain unsupported by packet evidence.
- 0 Orchestration classification or selection defects were found in the six
  cases. Positive evidence: Orchestration passed the null stage through without
  invention; selected the frame-11 candidate that agrees with the independent
  baseline's frame anchor; produced no boundary on the five healthy captures;
  and treated the recovered intermediate outcome as non-candidate.

The reconciliations in this section are DERIVED from committed artifacts and the
reproduced pipeline outputs described in section 2.3.

## 7. Remaining Supported Discrepancies

- R-1 Stage identity is not attached to event-derived registration deviations
  (DOMAIN_RECONSTRUCTION_DEFECT). Every currently emitted registration deviation
  across the six cases carries a null stage identity although the instance stage
  model identifies the enclosing stage; for public-5gc-auth-negative the
  enclosing authentication stage carries HIGH confidence and spans exactly the
  deviation frames. The emitter constructs event-derived deviations with a
  literal null stage identity while absence-shaped deviations carry theirs.
- R-2 The sanitized summaries lack per-type and candidate-eligibility deviation
  semantics (MISSING_SEMANTIC_INFO_IN_SUMMARIES), which keeps the five
  healthy-spectrum cases in adjudication even though all counted deviations are
  non-candidate evidence limitations.
- R-3 Documentation drift: the benchmark README still describes
  public-5gc-registration-resync with the pre-correction FALSE_POSITIVE wording
  in its case-status table and its adjudication-history list, while the current
  differential records NEEDS_ADJUDICATION with layer DOMAIN on a
  no-boundary-selected outcome. README edits were not authorized for this task,
  so the drift is recorded here for ownership instead of being fixed.

## 8. Unresolved Evidence Limitations

- U-1 The public-5gc-auth-negative baseline stage label "security" cannot be
  equated with the packet-supported authentication stage identity without
  inventing stage semantics on the pipeline side or revising the frozen baseline
  under separate governance. UNRESOLVABLE_WITH_CURRENT_EVIDENCE.
- U-2 The protected NAS envelopes in the five healthy-spectrum captures remain
  genuinely undecodable; the records correctly avoid invention, and no further
  resolution is possible from the packets themselves.
- U-3 The PDU-session initiation evidence on the healthy-spectrum captures sits
  inside protected envelopes; PARTIAL_CAPTURE remains the honest classification
  for those instances.

## 9. Recommended Correction Ownership and Priorities

Each recommendation is separately authorizable; none is implemented by this
report, and none must be bundled.

- Priority: highest. Owner: Domain Skill 5gc-registration-mobility. Attach the
  enclosing stage identity to event-derived deviation records (unsuccessful
  outcome, protocol reject, recovered intermediate outcome, protected envelope,
  unknown value), mirroring what absence-shaped deviations already carry.
  Expected effect: the public-5gc-auth-negative boundary would report the
  authentication stage, closing the unreported-stage dimension, and all six
  cases would gain stage-anchored deviation semantics. Requires its own
  authorization, a golden-artifact refresh, and re-comparison; scoring and
  denominators must not change silently.
- Priority: high. Owner: golden-capture framework (summary and comparator
  governance). Extend the sanitized per-Domain summary status with per-type
  deviation counts or a candidate-eligible count, and let the comparator
  distinguish all-non-candidate evidence limitations from substantive deviations
  on healthy captures. This is a comparison-semantics governance decision; it
  must not be implemented as a silent match-rate improvement, and any accepted
  change requires a benchmark refresh and re-adjudication of the affected
  differentials.
- Priority: medium. Owner: benchmark documentation. Refresh the stale
  public-5gc-registration-resync narrative in the benchmark README (case-status
  table row and adjudication-history entry) to the post-correction reality.
- Priority: low, external to repository code. Owner: baseline governance. If the
  public-5gc-auth-negative baseline is ever revised under the authorized
  revision protocol (citing the superseded canonical digest), its stage label
  should be re-derived from the packet-supported authentication-stage identity.
  No baseline edit is authorized or performed by this report.

## 10. Records Intentionally Not Modified

- The six per-case adjudication files (revision 1) and the seventh out-of-scope
  case file.
- `adjudications/README.md`, `adjudications/summary.json` and
  `adjudications/schemas/`.
- All frozen benchmark artifacts: per-case case records, sanitized
  human-baseline records, sanitized skill-result summaries, sanitized
  differentials, and the benchmark summary.
- All Skill code, Skill versions, schemas, scoring logic, and denominators.

## 11. Method and Sanitization Notes

- Evidence-identity matching was performed on (case, source Domain, deviation
  type, frame anchor or observation window), cross-checked against the
  historical rationale text, the reproduced Domain analysis artifacts, the
  Orchestration analysis artifacts, the sanitized summaries, and the
  differentials.
- All identifiers cited in this report (case identifiers, capture file names,
  frame numbers, message identities, cause codes, instance identifiers, source
  commit digests) are already committed in the frozen benchmark and adjudication
  records; telecom identifiers in those records are illustrative benchmark
  identifiers.
- No raw packet dumps, no subscriber identifiers, no authentication vectors, and
  no workstation paths appear in this report. Reproduction work was performed in
  an external work directory outside the repository; only sanitized, committed
  artifacts were compared.
- Evidence vocabulary follows the repository evidence contract. The
  reconciliations above are DERIVED from OBSERVED committed evidence; no
  inference about network-element responsibility is made anywhere in this
  report, and causation is never asserted beyond what the packets show.

This reconciliation stops here per its task boundary. Each confirmed defect
recorded in section 7 requires separate authorization before any correction is
implemented.
