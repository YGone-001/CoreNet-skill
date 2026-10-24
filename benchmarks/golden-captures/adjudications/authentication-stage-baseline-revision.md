# Authentication-Negative Human Baseline Stage Revision

Record type: authorized human-baseline revision and its independent re-adjudication follow-up.

Subject case: `public-5gc-auth-negative`.

This record documents one evidence-supported baseline correction. It is a follow-up to the accepted
independent review `authentication-stage-baseline-review.md`; that accepted review is preserved
unchanged and is not amended here.

## 1. Authorization Basis

The accepted independent review established finding F-1: the frozen baseline stage label `security`
has no standing as a stage identifier under the accepted benchmark contract, and `authentication` is
independently supported for the frame 11 boundary by the packets and by the applicable procedure
definitions. The same review rejected a Domain stage-attribution defect, rejected semantic
equivalence between `security` and `authentication`, and explicitly deferred any correction to a
separately authorized task.

The current authorization is that separate task, and it is bounded to the following:

- correcting the two unsupported stage references in this one case's human baseline;
- recording the superseded provenance forward, without rewriting history;
- regenerating only the records that change as a mechanical consequence;
- adding this follow-up record and synchronizing the affected README statements.

The authorization does not extend to Skill runtime behavior, Registration Domain stage rules,
Protocol, Correlation or Orchestration behavior, comparator behavior or matching policy, a shared
stage vocabulary, an alias mechanism, any other case's baseline, frame numbers, abnormal-event
identities, capture hashes, `case.json`, the selected Skill boundary, candidate-boundary records,
historical adjudication records, the denominator definition, or any scoring shortcut.

## 2. Provenance

| Item | Value |
| --- | --- |
| Repository | CoreNet Skill |
| Branch | `main` |
| Starting commit | `9d6b4fb3eb734e33a0c78d5efd6c289d68baa5cc` |
| Remote `refs/heads/main` at start | identical to the starting commit |
| Working tree at start | clean |
| External corpus | `abdelrahman-fawaz18/5g-sa-core-protocol-lab` |
| Pinned external commit | `82934c2cc231540fa425e48177d4bed33210bfc1` |
| Capture path in corpus | `captures/fault-injection/authentication-key-mismatch/fault.pcap` |
| Capture SHA-256 | `70cc13c537a745625fc59d974653f5b819874a8f1a74b14db416dc97a91801c7` |
| Frame count | 16 |
| Decoder baseline for the accepted packet findings | TShark 4.7.1 with an isolated decoder profile |

The capture identity is unchanged by this record. The packet conclusions reused below are those the
accepted review established for this exact committed case, against the same pinned source commit and
the same capture digest. No capture was substituted, and no packet was re-extracted for this
baseline-only correction: this record is a differential recomputation from frozen evidence, not a
new empirical capture run.

## 3. Canonical Digests

| Digest | Value |
| --- | --- |
| Original (superseded) canonical digest | `74b7a9596b4687c050715d4b012a6f637bfa34bd3bc4b5478d82880afe2b129d` |
| Revised canonical digest | `281f2af9d8676d03c8c63a0d1dd2448f4c6081c65f152d7e3d6375436e394edc` |

The original digest was recomputed with the repository's accepted `canonical_json_sha256`
implementation before any edit, and it matched the `human_baseline_sha256` recorded in the committed
differential exactly.

The revised digest differs from the value the accepted review simulated for a bare stage edit,
because adding `baseline_revision` and `revision_reason` and removing the legacy `baseline_hash`
label necessarily changes the canonical document. The digest recorded in the regenerated
differential is the revised digest above, recomputed from the final document rather than assumed.

The legacy, unauthenticated `baseline_hash` label was removed. It was never produced by
`canonical_json_sha256`, was never verified by any validator, and was not used as an immutability
proof.

## 4. Changed Fields

Exactly two stage references changed. Both previously recorded the superseded label `security`.

| Location | Before | After |
| --- | --- | --- |
| `first_abnormal_boundary.procedure_stage` (frame 11 boundary) | `security` | `authentication` |
| `procedure_observations[]` entry spanning frames 10-12 | `security` | `authentication` |

Revision governance metadata was added:

| Field | Value |
| --- | --- |
| `baseline_revision` | `1` |
| `revision_reason` | cites the accepted adjudication, the frames 10-12 evidence, the superseded label and the superseded canonical digest |

Everything else in the baseline is preserved byte-for-byte in meaning: `analysis_status`
(`BOUNDARY_OBSERVED`), `baseline_confidence`, the procedure family, the frame 11 boundary anchor, the
Authentication failure message identity, the NAS-5GS protocol identity, all observation windows, all
supporting evidence entries, the capture scope, the capture SHA-256, and every evidence level. The
replacement was not a global text substitution: the observation for frames 9-10 still records
`registration`, and the observation for frames 13-15 still records `release`.

## 5. Frame-Level Packet Basis

| Frame | Direction | NGAP procedure | NAS-5GS identity | Field-level basis |
| --- | --- | --- | --- | --- |
| 10 | downlink | `id-DownlinkNASTransport` (4) | Authentication request (`0x56`), plain | one UE-NGAP-ID pair; challenge parameters present |
| 11 | uplink | `id-UplinkNASTransport` (46) | Authentication failure (`0x59`), plain | 5GMM cause 20 (MAC failure) |
| 12 | downlink | `id-DownlinkNASTransport` (4) | Authentication reject (`0x58`), plain | same UE-NGAP-ID pair |

Exhaustive negative results over the whole 16-frame capture:

- exactly four NAS messages exist, all plain: Registration request (`0x41`), Authentication request
  (`0x56`), Authentication failure (`0x59`), Authentication reject (`0x58`);
- no Security mode command (`0x5D`), Security mode complete (`0x5E`) or Security mode reject (`0x5F`)
  exists anywhere in the capture;
- no security-protected NAS envelope exists, so no message authentication code or ciphered region
  could conceal a security mode exchange;
- the NGAP procedure inventory is exactly NGSetup, InitialUEMessage, DownlinkNASTransport,
  UplinkNASTransport and UEContextRelease.

Frame 11 is therefore a fully visible unsuccessful outcome, not a protected-envelope limitation, and
it is the first abnormal message in the capture.

## 6. Applicable 3GPP Procedure Evidence

| Specification | Clauses | What they establish |
| --- | --- | --- |
| 3GPP TS 24.501 | 5.4.1.3.2, 5.4.1.3.5, 5.4.1.3.6, 5.4.1.3.7 c), 8.2.4.1, 9.11.3.2 with table 9.11.3.2.1, annex A.3 | the primary authentication and key agreement procedure, its failure and reject outcomes, and the meaning of 5GMM cause 20 |
| 3GPP TS 24.501 | 5.4.2, 5.4.2.1, 5.4.2.2, 8.2.25 | NAS security mode control is a distinct procedure, triggered by SECURITY MODE COMMAND, whose purpose is to take a NAS security context into use |
| 3GPP TS 33.501 | 6.1.3, 6.1.3.3.1, 6.7, 6.7.2 | authentication and NAS security mode control are separate procedures; a failed AUTN verification yields an Authentication Failure carrying a cause value |
| 3GPP TS 38.413 | 8.3.3.1, 8.3.3.2, `CauseNas` | the AMF initiates UE context release with UE CONTEXT RELEASE COMMAND |
| 3GPP TS 23.502 | 4.2.2.2.2 | the registration call flow groups primary authentication and NAS security establishment under one step labelled `Authentication/Security` |

Three consequences follow, and they are what the correction rests on:

1. Authentication failure with cause 20 is a message of the authentication procedure. TS 24.501
   clause 5.4.1.3.6 has the UE send AUTHENTICATION FAILURE with cause `#20` when the MAC code is
   invalid, and clause 5.4.1.3.7 c) names exactly that case. Annex A.3 defines cause 20 as MAC
   failure.
2. The Authentication reject that follows belongs to the same procedure: TS 24.501 clause 5.4.1.3.5
   is the non-acceptance outcome the clause 5.4.1.3.7 c) path terminates in.
3. Security mode control is a different procedure with a different trigger and a different purpose,
   and neither TS 24.501 clause 5.4.2 nor TS 33.501 clause 6.7.2 treats a failed authentication as
   part of it.

The TS 23.502 clause 4.2.2.2.2 `Authentication/Security` step remains what the accepted review
described: support for `security` as a coarse description of the enclosing registration step, not an
identity statement and not a stage taxonomy. Containment is asymmetric, so the enclosing step's name
cannot substitute for the contained procedure's name without losing information.

## 7. Why These Two Fields Changed

Both fields describe the same observed procedure. The frame 11 boundary is the Authentication
failure, and the observation that spans frames 10-12 is the exchange that begins with the
Authentication request, fails at frame 11 and closes with the Authentication reject. Recording
`authentication` in one place and `security` in the other would have left the baseline internally
inconsistent about a single procedure, so both references follow the same packet evidence.

The correction is a change of stage identity, not a change of finding. The boundary frame, the
message identity, the protocol, the observation windows and the capture scope are untouched.

This correction was decided on packet and normative evidence. It was not motivated by any
match-rate, score or acceptance improvement; the comparison and metric consequences in sections 9
and 10 are recorded strictly as consequences, and a match-rate change is never evidence about which
label is correct.

## 8. Baseline Revision Number

`baseline_revision` is `1`. The case carried no explicit revision number before this correction, so
the first authorized revision is recorded as revision 1 rather than as an increment over an
unrecorded value.

The superseded stage values and the superseded canonical digest are preserved inside
`revision_reason`; no earlier baseline content is rewritten in Git history.

## 9. Comparison Result Before and After

The differential was regenerated by executing the accepted comparator with the revised baseline and
the unchanged committed Skill summary. It was not edited by hand and no result was manufactured.

| Dimension | Before | After |
| --- | --- | --- |
| `comparison_status` | `PROCEDURE_MATCH_STAGE_DIFFERENCE` | `EXACT_MATCH` |
| `adjudication_required` | `true` | `false` |
| `layer_attribution` | `DOMAIN` | `NONE` |
| `recommended_next_action` | `CORRECT_DOMAIN_MODEL` | `NO_CHANGE` |
| `human_baseline_sha256` | `74b7a959...e2b129d` | `281f2af9...6e394edc` |
| `human_boundary.procedure_stage` | `security` | `authentication` |
| `upstream_intent_match` | `PARTIAL` | `MATCH` |

Unchanged across the comparison: the selected boundary frame 11, the `NAS-5GS` protocol identity on
both sides, the `Authentication failure` abnormal-event identity on both sides, the procedure family
`5gc-registration-mobility`, the zero frame delta, `evidence_overlap` `true`, `comparison_eligibility`
`ELIGIBLE`, `baseline_supported` `true`, the empty `capture_limitations`, and every one of the six
`evidence_layers` values.

The `recommended_next_action` and `layer_attribution` values are those the comparator emitted. Their
change from `DOMAIN` / `CORRECT_DOMAIN_MODEL` to `NONE` / `NO_CHANGE` is a mechanical consequence of
the boundary semantics now agreeing, not a re-adjudication of the comparator's attribution policy,
which remains unchanged and is still the subject of open finding F-3.

## 10. Metric Consequences

Aggregate metrics were recomputed with the existing `summarize_benchmark.calculate_metrics` function
over all 13 committed differential records. No value was assigned by hand.

| Metric | Before | After |
| --- | ---: | ---: |
| `case_count` | 13 | 13 |
| `executed_case_count` | 13 | 13 |
| `exact_match_count` | 0 | 1 |
| `stage_match_count` | 0 | 1 |
| `procedure_match_count` | 1 | 1 |
| `needs_adjudication_count` | 1 | 0 |
| `exact_match_rate` | 0.0 | 0.1667 |
| `stage_match_rate` | 0.0 | 0.1667 |
| `procedure_match_rate` | 0.1667 | 0.1667 |
| Bounded non-candidate agreements | 5 | 5 |
| `false_positive_count` | 0 | 0 |
| `false_negative_count` | 0 | 0 |
| `exact_frame_match_count` | 1 | 1 |
| `median_absolute_frame_delta` | 0.0 | 0.0 |
| Evaluated-in-scope denominator | 6 | 6 |

Two points require precision.

1. `procedure_match_count` does not fall to zero. The accepted `calculate_metrics` implementation
   counts an `EXACT_MATCH` as an exact match, a procedure match and a stage match, because an exact
   match entails both. The case therefore remains counted as one procedure-level agreement while
   additionally becoming the single exact match. Any expectation that a procedure-match count must
   decrease when a stage disagreement is resolved would contradict the implemented metric contract;
   the contract was not changed, and the computed value is reported as computed.
2. The denominator is unchanged at `13 - 1 - 1 - 0 - 5 = 6`, and `denominator_definition` is
   byte-identical to its previous value. No denominator rule was touched.

The recorded `generated_at`, `corenet_commit`, `external_source_commit`, `tshark_version`,
`python_version` and `skill_versions` values are preserved exactly. `corenet_commit` still names the
empirical generation revision `6d53019b96e26c7681c9921cd670aa6cce8292a4`; it is not set to this
revision, and this record does not imply that the capture corpus was re-run.

All other 12 case records are byte-identical, including their comparison statuses, layer
attributions, eligibility, frame anchors, adjudication flags and recommended actions.

## 11. Skill Behaviour Unchanged

No Skill runtime file changed. The Protocol, Correlation, Domain and Orchestration layers, the
sanitized `skill-result-summary.json`, the comparator, the schemas, the validators and the stage
vocabulary are untouched.

The Skill side of the comparison reports the same boundary, protocol, message identity, procedure
family and stage before and after this revision. The correction changes only the independent human
baseline's stage identity and the derived records that read it.

## 12. Timestamp Provenance Limitation

The timestamp-provenance limitation the accepted review recorded remains unresolved and is outside
this correction's scope.

- `case.json` is byte-identical. It was not edited.
- The baseline boundary timestamp is unchanged.
- No inference is drawn that the two timestamp sources agree, and timestamp agreement is not used as
  evidence of an exact match anywhere in this record.
- The comparator's existing authoritative frame-anchor semantics are unchanged: the exact match rests
  on the frame 11 anchor together with the stage, protocol, abnormal-event and family identities, not
  on any timestamp.
- The known discrepancy between the original capture epochs and the timestamps stored in the
  historical case and baseline records is retained here as a documented limitation, not repaired by
  an unauthorized field edit.

The discrepancy affects timestamp provenance only. Frame numbers, frame count and capture digest
agree, so the frame 11 boundary identity is not invalidated, and the narrowly authorized stage
correction could proceed.

## 13. Scope Separation

| Finding | Status after this record |
| --- | --- |
| F-1: the frozen baseline stage label was not supported as a stage identifier | Corrected for this one case by the authorized revision recorded here |
| F-2: no shared stage vocabulary contract exists between the baseline and the Domain catalog | Still open. Not addressed, not changed, and not implied to be resolved. |
| F-3: the differential's layer attribution is a policy default rather than an evidence finding | Still open. The comparator's attribution policy is unchanged; its new `NONE` value for this case is the policy's ordinary exact-match outcome. |

F-2 and F-3 each require their own separate authorization. This record does not correct them, does
not narrow them, and does not claim that the corpus-wide vocabulary separation or the attribution
expressiveness gap has been remedied. The other 12 baselines still use a vocabulary disjoint from the
Domain stage catalog, exactly as before.

## 14. Validation Evidence

| Check | Result |
| --- | --- |
| `python3 scripts/validate-repository.py` | passed |
| `python3 scripts/validate-architecture.py` | passed |
| `python3 scripts/validate-golden-captures.py` | passed, including baseline digest agreement and revision governance |
| Revised baseline schema validation | passed |
| Comparator execution | executed with the accepted CLI; emitted `EXACT_MATCH` |
| Revised canonical digest equals the differential's `human_baseline_sha256` | verified |
| Golden Capture test suite (`benchmarks/golden-captures/tests/`) | `Ran 251 tests`, `OK` |
| Root test suite (`tests/`) | `Ran 889 tests`, `OK (skipped=1)` |
| `python3 -m compileall scripts benchmarks/golden-captures/scripts` | passed |
| `git diff --check` | clean |

### 14.1 Test-Expectation Governance

Applying this correction made three existing assertions in
`benchmarks/golden-captures/tests/test_orchestration_consumption.py` fail, because each encoded the
pre-revision committed state rather than a behavioral contract. Those assertions were not weakened,
disabled, skipped or deleted. They were updated to the authorized state under a separate
test-governance authorization granted after the correction was reported as requiring one.

| Test | Assertion | Before | After |
| --- | --- | --- | --- |
| `test_committed_case_statuses_preserved` (formerly `test_eight_control_cases_preserved`) | expected `public-5gc-auth-negative` status | `PROCEDURE_MATCH_STAGE_DIFFERENCE` | `EXACT_MATCH` |
| `test_authentication_negative_boundary_semantics_preserved` | `diff["comparison_status"]` | `PROCEDURE_MATCH_STAGE_DIFFERENCE` | `EXACT_MATCH` |
| `test_authentication_negative_boundary_semantics_preserved` | `diff["human_boundary"]["procedure_stage"]` | `security` | `authentication` |
| `test_benchmark_metrics_and_denominator_invariance` | `exact_match_count` | `0` | `1` |
| `test_benchmark_metrics_and_denominator_invariance` | `stage_match_count` | `0` | `1` |
| `test_benchmark_metrics_and_denominator_invariance` | `needs_adjudication_count` | `1` | `0` |
| `test_benchmark_metrics_and_denominator_invariance` | `procedure_match_count` | `1` | `1`, unchanged |

The method previously named `test_eight_control_cases_preserved` was renamed to
`test_committed_case_statuses_preserved`, because this case is no longer one of the non-agreement
control cases. The suite count is unchanged at 251, and no other test, validator, schema or comparator
was touched. The boundary-frame, protocol, message-identity and Skill-stage assertions in the same
test are unchanged, so the test still proves that the frame 11 abnormal-boundary semantics were
preserved by the revision.

## 15. Acceptance Result

The authorized human-baseline correction is applied and verified: the revised baseline, the recomputed
differential, the recomputed aggregate summary, this follow-up record, the targeted README
synchronization, and the authorized update of the three frozen-state test expectations.

Every acceptance gate is satisfied. The validators pass; the revised baseline is schema-valid and
digest-authenticated; the comparator was executed rather than bypassed; the boundary remains anchored
at frame 11 with unchanged protocol, message identity and procedure family; the aggregate metrics are
recomputed from all 13 committed differentials under an unchanged denominator rule; the other 12 case
directories are byte-identical; and both test suites pass.

F-1 is corrected for this case. F-2 and F-3 remain open and untouched, the timestamp-provenance
discrepancy remains unresolved and outside scope, and no stage vocabulary, alias mechanism, comparator
policy, Skill runtime or other case baseline was changed.
