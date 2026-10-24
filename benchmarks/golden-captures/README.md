# Golden Capture Benchmark — Public 5GC Differential Validation

## 1. Overview and Objective

The **Golden Capture Benchmark** is an empirical, evidence-first validation framework for CoreNet Skill. It establishes a reproducible differential benchmark comparing independent, standards-based packet analysis against automated CoreNet Skill execution across public 5G Standalone (5G SA) core network signaling captures.

The objective of this framework is to measure:
- Whether automated Skills identify the same telecom procedure boundaries as independent protocol analysis;
- Whether automated Skills detect abnormal stages and protocol failures accurately;
- Whether Skills select compatible frame and packet evidence;
- False positive and false negative occurrences across healthy, recovery, and fault captures;
- Correlation and attribution safety across protocol layers; and
- Concrete coverage boundaries in the current protocol extractors, domain models, and failure boundary orchestration.

The benchmark framework is testing and evaluation infrastructure; it is **not** a Skill layer and does not introduce domain logic into the repository.

This README documents the current accepted committed benchmark state. Current results are read from the committed benchmark artifacts (`benchmark-summary.json` and the per-case records). Earlier investigation outcomes are preserved as clearly labelled historical records in section 8 and are never presented as current results.

---

## 2. Methodology and Governance

### 2.1 Independent Baseline Methodology and Freeze Order
To prevent bias, human/agent baseline analyses are conducted independently before running automated Skill execution:
1. **Raw Capture Inspection**: The packet capture is decoded and inspected against 3GPP and IETF normative specifications (3GPP TS 38.413 for NGAP, 3GPP TS 24.501 for NAS-5GS, 3GPP TS 29.244 for PFCP, 3GPP TS 29.281 for GTP-U, and RFC 7540 / 3GPP TS 29.500 for SBI HTTP/2).
2. **Independent Baseline Authoring**: An independent baseline record (`human-baseline.json`) is authored defining observed procedures, abnormal boundaries, supporting packet evidence, capture limitations, and baseline confidence.
3. **Canonical Schema and Hash Freezing**: The baseline is validated against `human-baseline.schema.json` and its deterministic, platform-independent canonical JSON hash (`canonical_json_sha256`) is computed and recorded in `differential.json` as `human_baseline_sha256`. That recorded digest is recomputed and compared by `scripts/validate-golden-captures.py` on every validation run and is the only baseline immutability proof the repository relies on. It guarantees cross-platform digest invariance across operating systems, line endings (LF vs CRLF), indentation, and JSON key ordering. The optional `baseline_hash` property in older baseline records is a legacy informational label: it is not produced by `canonical_json_sha256`, is not reproducible from the stored document, is not verified by any validator, and must never be presented or reused as an authenticated canonical hash. An authorized adjudication records the superseded digest inside `revision_reason` and increments `baseline_revision` rather than rewriting any file in Git history.
4. **Automated Skill Pipeline Execution**: The automated pipeline is executed mechanically in an isolated external working directory.
5. **Differential Comparison**: The frozen baseline and sanitized Skill summary are compared deterministically without tuning or modifying Skill implementations.

### 2.2 Evidentiary Pipeline Health and Comparison Eligibility
A baseline conclusion of `NO_SUPPORTED_ABNORMAL_BOUNDARY_OBSERVED` (or an out-of-scope non-boundary observation) is meaningful only when every upstream evidence layer actually produced the evidence the comparison consumes. `NO_ABNORMAL_BOUNDARY_OBSERVED` is never benchmark-success evidence on its own.

Comparison eligibility is evaluated across six independent layers in pipeline order. Success at layer N never substitutes for missing evidence at layer N+1, and every layer outcome is recorded in `differential.json` under `evidence_layers`:

| # | Layer | Question | Recorded values |
| --- | --- | --- | --- |
| 1 | Baseline support | Is the independent baseline itself supported and validated? | `SUPPORTED`, `UNSUPPORTED` |
| 2 | Capture sufficiency | Does the capture hold enough packet evidence for an authoritative boundary? | `SUFFICIENT`, `INSUFFICIENT` |
| 3 | Relevant Protocol extraction | Did every relevant Protocol Skill expose usable message identity? | `HEALTHY`, `DEFECT`, `BLOCKED` |
| 4 | Relevant Domain reconstruction | Did the relevant Domain Skill actually reconstruct a procedure instance? | `PRESENT`, `NO_RELEVANT_INSTANCE`, `NO_RELEVANT_DOMAIN`, `FAILED`, `NOT_APPLICABLE`, `NOT_EVALUATED` |
| 5 | Orchestration availability | Did Orchestration consume the reconstructed Domain evidence? | `AVAILABLE`, `FAILED`, `UNVERIFIED`, `NOT_RUN`, `NOT_REPORTED`, `NOT_APPLICABLE`, `NOT_EVALUATED` |
| 6 | Semantic boundary comparison | Do the human and automated boundaries agree? | `EVALUATED`, `NOT_EVALUATED` |

Per-Domain execution evidence is reported separately from Orchestration evidence in `skill-result-summary.json` (`domain_status` and `orchestration_status`), so one counter never carries two meanings: `domain_instances_count` is the number of procedure instances produced by executed Domain Skills, while `orchestration_status.source_domain_instances_count` is what Orchestration consumed. Each `domain_status` entry also records `execution_status`, `output_present`, `deviation_count` and a bounded, path-free `first_stop_reason` so a reconstruction that never started is never reported as a reconstruction that found nothing.

Layers 4 and 5 are `NOT_APPLICABLE` when the baseline observes only procedure families that no implemented Domain Skill owns (for example node-level `ngap-management` or a planned `5gc-user-plane` family): no Domain instance is expected, so absent reconstruction is reported as `DOMAIN_COVERAGE_GAP` with `DOMAIN_COVERAGE` attribution and `EXPAND_FUTURE_SCOPE`, never as a failure of an implemented Domain model, and such cases are excluded from the in-scope accuracy denominator. Semantic boundary comparison is recorded as `NOT_EVALUATED` there because no automated boundary evidence exists to compare.

`NO_RELEVANT_DOMAIN` records that the summary carries no execution evidence at all for a Domain the baseline makes relevant. Only relevant Domain keys are read: an executed instance of some other Domain never satisfies a missing relevant Domain, because that would substitute evidence from a procedure the independent baseline never observed.

The following states are strictly non-equivalent:
- **Evidence-Supported Health**: relevant protocol signaling parsed -> relevant Domain instance reconstructed with no deviation -> Orchestration ran and positively consumed the relevant Domain instances -> no abnormal boundary observed (`EXACT_MATCH`, eligibility `ELIGIBLE`).
- **Domain Reconstruction Failure**: protocol extraction healthy -> the relevant Domain Skill produced no instance, for example an input-contract rejection -> no boundary produced (`DOMAIN_MODEL_GAP`, layer `DOMAIN`).
- **Unextracted Pipeline Failure**: protocol extraction failed, or exposed no message identity for a case it reports as supported -> zero Domain instances -> no boundary produced (`PROTOCOL_COVERAGE_GAP`, layer `PROTOCOL`).
- **Unimplemented Domain Coverage**: the baseline observes a procedure family that no implemented Domain Skill owns -> Domain reconstruction is `NOT_APPLICABLE` -> there is no automated boundary evidence to compare (`DOMAIN_COVERAGE_GAP`, layer `DOMAIN_COVERAGE`, excluded from the in-scope accuracy denominator).

A healthy `EXACT_MATCH` therefore requires a relevant Domain instance to have been produced and consumed. Protocol success with zero relevant Domain instances is never `EXACT_MATCH`.

### 2.3 Standards-Based and Implementation-Neutral Discipline
The benchmark evaluates standardized protocol signaling behavior exclusively. Captures produced by external lab environments are treated as packet evidence only. In adherence with repository policy:
- No implementation-specific source code, internal state machines, log structures, configuration quirks, or project bug knowledge are incorporated into benchmark records or Skill definitions.
- All procedure definitions and boundary verdicts derive directly from standardized 3GPP specifications.

### 2.4 Artifact Safety and Repository Hygiene
- **Zero Raw PCAP in Git**: Binary packet capture files (`.pcap`, `.pcapng`, `.cap`) are strictly forbidden from being committed into the repository.
- **External Working Directory**: Benchmark runs execute entirely within an external temporary directory (`/tmp/corenet-golden-run/` or Windows equivalent). Intermediate raw protocol dumps (`*-events.jsonl`, `*-trace.jsonl`) remain in the external workspace.
- **Sanitized Summaries**: Only non-sensitive, aggregated summaries (`skill-result-summary.json`, `differential.json`) conforming to strict schemas are checked into the repository. Subscriber identifiers (SUPI/IMSI) and workstation-specific paths are excluded. Sanitized summaries carry bounded categorical metadata and integer counts only (deviation type names, instance counts, consumption counts); they never carry raw Domain or Orchestration documents.
- **External Path Isolation**: The corpus source directory, the pipeline work directory, and the sanitized output directory are external, separate locations. Sanitized artifacts enter the repository only through an explicit, reviewed import step (section 7). Routine reproduction never writes directly into the tracked `cases/` directory.

---

## 3. Differential Taxonomy and Discrepancy Attribution

### 3.1 Comparison Statuses
- `EXACT_MATCH`: For an abnormal boundary, the Skill selected a boundary whose analysis status, procedure family, procedure stage, protocol identity and abnormal-event identity are all compatible **and** whose evidence anchor is the same exact frame the baseline records (or the same window when the baseline holds no exact authoritative frame). For healthy traffic, both sides observed no abnormal boundary **and** a relevant Domain instance was actually reconstructed with zero deviations, Orchestration consumption of the relevant Domain instances is positively verified, and the selection and candidate metadata are internally consistent, under an eligible evidence pipeline.
- `NO_ABNORMAL_BOUNDARY_AGREEMENT_WITH_NONCANDIDATE_EVIDENCE`: Both the independent baseline and the automated pipeline observed no abnormal boundary within the capture and the implemented procedure scope, and every relevant Domain deviation is classified non-candidate evidence (evidence limitations and/or supporting anomalies) with zero candidate-eligible and zero unclassified deviations. Orchestration consumption of the relevant Domain instances is positively verified and the selection and candidate metadata are internally consistent. This is a **bounded agreement** on the absence of a supported abnormal boundary only: it is not `EXACT_MATCH`, it is never added to the exact-match count, and it never asserts `SUCCESS`, `HEALTHY_NETWORK`, `END_TO_END_SUCCESS` or `SERVICE_PASSED`. Attribution `NONE`, adjudication not required, recommended action `NO_CHANGE`.
- `BOUNDARY_FRAME_DIFFERENCE`: All abnormal-boundary semantics are compatible and the selected frame differs by 1-2 adjacent transaction frames, or the baseline records only a derived observation window that contains the selected frame. Adjacency alone is never enough.
- `PROCEDURE_MATCH_STAGE_DIFFERENCE`: Procedure family matches, but stage attribution differs, even when the frame anchor is identical.
- `ACCEPTABLE_DIFFERENCE`: Human baseline and Skill selected valid alternative boundaries supported by capture evidence.
- `FALSE_POSITIVE`: The Skill selected a concrete abnormal boundary in healthy/recovered signaling, or asserted one for an out-of-scope condition. A confirmed `FALSE_POSITIVE` requires evidence that the Skill emitted an unsupported abnormal conclusion; an unresolved candidate set is never a confirmed false positive.
- `FALSE_NEGATIVE`: A relevant Domain instance was reconstructed but reported no deviation supporting an abnormal boundary the independent baseline observed. (A missing Domain instance is `DOMAIN_MODEL_GAP`, and a Domain deviation that Orchestration did not consume is `ORCHESTRATION_GAP`; the benchmark never jumps from Protocol success to a generic false negative without recording the Domain evidence state.)
- `UNSAFE_CORRELATION`: Cross-protocol correlation grouped or ordered evidence unsafely.
- `PROTOCOL_COVERAGE_GAP`: Protocol extractor encountered an unhandled dissector field or decode error.
- `CORRELATION_GAP`: Cross-protocol correlation failed to group interrelated signaling events.
- `DOMAIN_MODEL_GAP`: An implemented Domain owns the observed procedure but reconstructed no relevant instance, emitted no deviation supporting a boundary the independent baseline observed, or reported no execution evidence for a Domain the baseline makes relevant.
- `DOMAIN_COVERAGE_GAP`: The observed procedure family is owned by no implemented Domain Skill (for example node-level `ngap-management` or `5gc-user-plane`). This is unimplemented coverage, not a defect of an implemented Domain model, and the case is excluded from the in-scope accuracy denominator.
- `ORCHESTRATION_GAP`: Domain detected the issue, but failure-boundary orchestration selected the wrong diagnostic candidate, declined to resolve a single first boundary, or failed to consume Domain instances that reported deviations. An established Orchestration consumption failure may produce this status; unverified consumption metadata may not (section 6).
- `CAPTURE_LIMITATION`: Truncated packet capture, encrypted payload or missing interfaces prevent authoritative analysis. Upstream scenario labels are not treated as evidence for this status.
- `OUT_OF_SCOPE`: Signaling occurs on interfaces outside current CoreNet scope (e.g. external N6 data routing).
- `HUMAN_BASELINE_UNSUPPORTED`: The independent baseline itself is unsupported and the comparison is not authoritative.
- `NEEDS_ADJUDICATION`: Boundary semantics disagree or are not reported on at least one side, an ambiguous candidate set was never resolved, the deviation evidence is not proven non-candidate (candidate-eligible, unclassified, or missing classification metadata remains), or the recorded evidence does not identify a responsible layer. No match and no fault is assumed.

### 3.2 Abnormal-Boundary Semantic Matching Contract
A shared frame number is an anchor, not a meaning. Before any anchor is consulted, the comparator requires compatible values on every reported dimension: analysis status, procedure family, procedure stage, protocol identity and abnormal-event (message) identity.

- Frame equality with a stage, protocol or abnormal-event disagreement is never `EXACT_MATCH`; a stage disagreement reports `PROCEDURE_MATCH_STAGE_DIFFERENCE`, and a protocol or abnormality disagreement reports `NEEDS_ADJUDICATION`.
- A one- or two-frame delta never overrides a stage, protocol or abnormality disagreement, so request/response adjacency is not automatic semantic equivalence.
- Sanitizer placeholders (`UNKNOWN`, empty, `None`) count as unreported, not as agreement. When the sanitized summary or the baseline lacks the detail needed to establish equivalence, the result is `NEEDS_ADJUDICATION`; missing semantic fields are never invented.
- Exact frames, observation windows and derived missing-evidence boundaries stay distinct. A baseline whose boundary carries only an observation window can at best yield `BOUNDARY_FRAME_DIFFERENCE`, because it holds no exact authoritative frame to match.
- Healthy traffic with an unresolved candidate set (`AMBIGUOUS_FIRST_BOUNDARY`, `INSUFFICIENT_COMPARABLE_EVIDENCE`) reports `NEEDS_ADJUDICATION` with `MULTIPLE` attribution, recording separately that candidate deviations were emitted, that no boundary was selected, and that the ambiguity was preserved. A confirmed `FALSE_POSITIVE` requires evidence that the Skill emitted an unsupported abnormal conclusion, not merely an unresolved candidate set.
- `layer_attribution` is `UNKNOWN` when the recorded evidence does not identify a responsible layer, and `MULTIPLE` when more than one layer legitimately shares the outcome, so no single-layer fault is invented.

### 3.3 Lowest-Layer Attribution Rule
When a discrepancy occurs between the independent baseline and automated execution, the discrepancy is attributed to the **lowest layer** that accounts for it:
$$\text{Protocol} \longrightarrow \text{Correlation} \longrightarrow \text{Domain} \longrightarrow \text{Orchestration}$$
If a protocol extractor fails to extract a message or field, the discrepancy is attributed to `PROTOCOL` (`PROTOCOL_COVERAGE_GAP`), rather than blaming higher Domain or Orchestration layers for missing evidence.

### 3.4 Protocol Extraction Statuses
`skill-result-summary.json.protocol_status` records one status per Protocol Skill, judged against that Skill's own message-identity contract: PFCP and GTP-U expose identity inside the bounded `header` object, while NGAP, NAS-5GS and SBI-HTTP2 expose it at the detailed-event top level. Probing a single shared path for every protocol misreports healthy extraction as a failure.

- `SUCCESS`: extraction succeeded and every record the Skill reports as `SUPPORTED` exposes a usable message identity.
- `SUCCESS_WITH_UNSUPPORTED_SEMANTICS`: extraction succeeded and supported records are fully identified, but the capture also contains procedures the bounded Skill intentionally does not own (for example NGAP `NGSetup`). Bounded scope, not an extractor failure.
- `SUCCESS_WITH_PROTECTED_PAYLOAD`: extraction succeeded, but identity is unavailable for records whose payload is security-protected (ciphered NAS after Security Mode). A capture and security limitation, not an extractor failure.
- `MISSING_MESSAGE_TYPE`: a record the Skill itself classifies as `SUPPORTED` exposed no message identity. This is a precise extractor compatibility failure; it never means the Skill recognized a procedure it does not own.
- `NOT_OBSERVED_IN_CAPTURE`: the extractor matched no packets of that protocol.
- `ERROR_<code>`: the extractor exited with a failure code other than the empty-match code.

Only `MISSING_MESSAGE_TYPE`, `ERROR_*`, a missing status for a relevant protocol, and `NOT_OBSERVED_IN_CAPTURE` for a protocol the baseline declares present are counted as Protocol defects. The three `SUCCESS*` states keep the comparison eligible.

---

## 4. Public Capture Corpus and Current Empirical Results

### 4.1 Corpus, Decoder and Recorded Provenance

The benchmark evaluates 13 captures from the public repository `abdelrahman-fawaz18/5g-sa-core-protocol-lab` pinned at commit `82934c2cc231540fa425e48177d4bed33210bfc1`. Every capture is verified against its recorded SHA-256 digest before execution, and no capture is refreshed or replaced by this documentation.

The frozen records were produced with the pinned decoder baseline **TShark 4.7.1** (`v4.7.1-0-g667ab240e6de`). No other TShark version is an accepted substitute; TShark 4.2.x in particular is not a substitute for the frozen decoder baseline.

`benchmarks/golden-captures/benchmark-summary.json` records the corpus-generation provenance exactly as captured at run time, and those recorded values are preserved as-is:

| Recorded field | Value |
| --- | --- |
| `corenet_commit` | `6d53019b96e26c7681c9921cd670aa6cce8292a4` |
| `external_source_commit` | `82934c2cc231540fa425e48177d4bed33210bfc1` |
| `generated_at` | `2026-10-22T08:53:54.659006+00:00` |
| `tshark_version` | `TShark (Wireshark) 4.7.1 (v4.7.1-0-g667ab240e6de).` |
| `python_version` | `3.13.14` |

Three revisions must be kept distinct and must never be conflated:

1. **The source revision recorded for the benchmark generation** — the `corenet_commit` value recorded inside `benchmark-summary.json`. It may be an earlier revision than the commit that stored the regenerated artifacts, and it is preserved as recorded.
2. **The Git commit that stored the regenerated benchmark artifacts** — `955105bed87d44a582410e29c2fa2d35f270d685`, which committed the sanitized summaries carrying the per-Domain consumption map and the recomputed records.
3. **The later documentation-only synchronization commit** that updates this README. It performs no empirical run, changes no artifact, and must not make an older empirical run appear to have been performed again.

No new empirical reproduction was performed for this documentation change; all results below are read from the committed artifacts and their recorded provenance.

### 4.2 Current Case Results (13 cases)

The table below reflects the committed `differential.json` of every case. The upstream scenario intent column is secondary metadata from the corpus definition and is never packet evidence; the comparison columns report only observed evidence. Evidence counts shown are the committed per-Domain records (instances and deviations as reported by the executed Domain Skills).

| Case ID | Upstream scenario intent (metadata only) | Independent baseline observation | Automated pipeline observation | Comparison | Layer | Adjudication |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `public-5gc-baseline-lifecycle` | baseline full lifecycle registration session and release | No supported abnormal boundary observed | No abnormal boundary observed; Registration 1 instance / 5 deviations (protected-envelope limitations), PDU Session 1 instance / 1 deviation (partial-capture limitation), 1 diagnostic group, 0 candidates | `NO_ABNORMAL_BOUNDARY_AGREEMENT_WITH_NONCANDIDATE_EVIDENCE` | `NONE` | not required |
| `public-5gc-baseline-user-plane` | baseline pdu session user plane data exchange | No supported abnormal boundary observed | No abnormal boundary observed; Registration 1 instance / 5 deviations (protected-envelope limitations), PDU Session 1 instance / 1 deviation (partial-capture limitation), 1 diagnostic group, 0 candidates | `NO_ABNORMAL_BOUNDARY_AGREEMENT_WITH_NONCANDIDATE_EVIDENCE` | `NONE` | not required |
| `public-5gc-registration-resync` | registration authentication synch failure and subsequent resynchronization recovery | No supported abnormal boundary observed (recovered synchronization) | No abnormal boundary observed; Registration 1 instance / 6 deviations (5 protected-envelope limitations, 1 supporting anomaly `RECOVERED_INTERMEDIATE_OUTCOME_OBSERVED`), PDU Session 1 instance / 1 deviation (partial-capture limitation), 1 diagnostic group, 0 candidates | `NO_ABNORMAL_BOUNDARY_AGREEMENT_WITH_NONCANDIDATE_EVIDENCE` | `NONE` | not required |
| `public-5gc-auth-recovery` | authentication recovery with matching keys | No supported abnormal boundary observed | No abnormal boundary observed; Registration 1 instance / 5 deviations (protected-envelope limitations), PDU Session 1 instance / 1 deviation (partial-capture limitation), 1 diagnostic group, 0 candidates | `NO_ABNORMAL_BOUNDARY_AGREEMENT_WITH_NONCANDIDATE_EVIDENCE` | `NONE` | not required |
| `public-5gc-dnn-recovery` | supported dnn session establishment recovery | No supported abnormal boundary observed | No abnormal boundary observed; Registration 1 instance / 5 deviations (protected-envelope limitations), PDU Session 1 instance / 1 deviation (partial-capture limitation), 1 diagnostic group, 0 candidates | `NO_ABNORMAL_BOUNDARY_AGREEMENT_WITH_NONCANDIDATE_EVIDENCE` | `NONE` | not required |
| `public-5gc-auth-negative` | authentication key mismatch resulting in MAC failure and reject (metadata only) | Boundary observed at frame 11, NAS-5GS `Authentication failure`, procedure family `5gc-registration-mobility`, stage `authentication` (baseline revision 1) | Boundary selected at frame 11, NAS-5GS `Authentication failure`, procedure family `5gc-registration-mobility`, stage `authentication`; Registration 1 instance / 2 candidate-eligible deviations (frame 11 `Authentication failure`, frame 12 `Authentication reject`), 2 frame-anchored candidates, 1 selected | `EXACT_MATCH` | `NONE` | not required |
| `public-5gc-access-plmn-negative` | plmn mismatch resulting in NGSetupFailure (metadata only) | Boundary observed at frame 7, NGAP `NGSetupFailure`, stage `ng-setup` | No Domain inputs; observed procedure family `ngap-management` is owned by no implemented Domain Skill | `DOMAIN_COVERAGE_GAP` | `DOMAIN_COVERAGE` | not required |
| `public-5gc-access-plmn-recovery` | plmn recovery resulting in NGSetupResponse (metadata only) | No supported abnormal boundary observed | No Domain inputs; observed procedure family `ngap-management` is owned by no implemented Domain Skill | `DOMAIN_COVERAGE_GAP` | `DOMAIN_COVERAGE` | not required |
| `public-5gc-access-tai-negative` | tac mismatch resulting in NGSetupFailure (metadata only) | Boundary observed at frame 7, NGAP `NGSetupFailure`, stage `ng-setup` | No Domain inputs; observed procedure family `ngap-management` is owned by no implemented Domain Skill | `DOMAIN_COVERAGE_GAP` | `DOMAIN_COVERAGE` | not required |
| `public-5gc-access-tai-recovery` | tac recovery resulting in NGSetupResponse (metadata only) | No supported abnormal boundary observed | No Domain inputs; observed procedure family `ngap-management` is owned by no implemented Domain Skill | `DOMAIN_COVERAGE_GAP` | `DOMAIN_COVERAGE` | not required |
| `public-5gc-external-path-negative` | missing n6 return route causing unanswered uplink icmp echo requests (metadata only) | Outside current CoreNet scope (N6 data plane) | No Domain inputs; pipeline safely remained conservative | `OUT_OF_SCOPE` | `OUT_OF_SCOPE` | not required |
| `public-5gc-external-path-recovery` | n6 return route recovered with bidirectional icmp ping (metadata only) | No supported abnormal boundary observed | GTP-U extracted (`G-PDU`); observed N3 procedure family `5gc-user-plane` is owned by no implemented Domain Skill | `DOMAIN_COVERAGE_GAP` | `DOMAIN_COVERAGE` | not required |
| `public-5gc-dnn-negative` | unsupported dnn request resulting in session rejection without PFCP session (metadata only) | Insufficient evidence: protected NAS exchange, no 5GSM identity or cause decodable in any frame (baseline revision 3) | No abnormal boundary observed; Registration 1 instance / 7 deviations (all protected-envelope limitations), PDU Session 0 instances (no `ngap.pDUSessionID` value in the capture) | `CAPTURE_LIMITATION` | `CAPTURE` | not required |

Observed evidence is reported separately from upstream test intent in every row: a scenario label such as "session rejection" is never read as packet evidence of a rejection, and an unimplemented Domain family is never converted into an implemented Domain failure.

### 4.3 Authentication-Negative Case (exact match after an authorized baseline revision)

The committed result is presented exactly as recorded:

```text
Case:
public-5gc-auth-negative

Human status:
BOUNDARY_OBSERVED

Skill status:
SELECTED

Boundary frame:
11

Protocol:
NAS-5GS

Message:
Authentication failure

Human stage:
authentication

Skill stage:
authentication

Comparison:
EXACT_MATCH

Layer:
NONE

Adjudication:
not required
```

Both sides anchor the boundary at frame 11 with the same protocol, message identity, procedure family
and stage, so the comparison is `EXACT_MATCH`. The Skill stage `authentication` is unchanged and was
never missing or `UNKNOWN`; what changed is the independent human baseline's stage identity.

The human baseline records `authentication` at `baseline_revision` 1. The superseded label was
`security`, in exactly two places: the frame 11 boundary stage and the procedure observation spanning
frames 10-12. The correction rests on packet and normative evidence — a plain NAS-5GS Authentication
request at frame 10, a plain NAS-5GS Authentication failure with 5GMM cause 20 at frame 11 and a plain
NAS-5GS Authentication reject at frame 12, with no security mode exchange anywhere in the 16-frame
capture — and it was not motivated by the match-rate consequence. The superseded canonical digest is
preserved inside `revision_reason`. The revision is recorded in
`adjudications/authentication-stage-baseline-revision.md`; the accepted review
`adjudications/authentication-stage-baseline-review.md` is unchanged.

### 4.4 Five Bounded No-Abnormal-Boundary Agreements

The following five cases currently report `NO_ABNORMAL_BOUNDARY_AGREEMENT_WITH_NONCANDIDATE_EVIDENCE`:

```text
public-5gc-auth-recovery
public-5gc-baseline-lifecycle
public-5gc-baseline-user-plane
public-5gc-dnn-recovery
public-5gc-registration-resync
```

For each of these cases the committed records establish that:

- The independent baseline observed no supported abnormal boundary.
- The automated pipeline selected no abnormal boundary (`selection_status` `NO_ABNORMAL_BOUNDARY_OBSERVED`, zero selected boundary).
- Relevant Domain instances were reconstructed (for example Registration and PDU Session instances on the full-chain captures).
- Orchestration positively consumed the relevant Domain instances (verified per-Domain consumption, section 6).
- The reported relevant Domain deviations are classified non-candidate evidence (evidence limitations and/or supporting anomalies).
- The candidate-eligible deviation count is zero.
- The unclassified deviation count is zero.
- The result is not `EXACT_MATCH` and is never added to the exact-match count.
- The result does not establish end-to-end service success; it asserts only the absence of a supported abnormal boundary within the capture and the implemented procedure scope.

For `public-5gc-registration-resync`, the Registration instance additionally reports the supporting anomaly `RECOVERED_INTERMEDIATE_OUTCOME_OBSERVED` (a packet-observed recovered intermediate Authentication outcome). That observation is retained as supporting evidence, not as an abnormal-boundary candidate: it is classified `supporting_anomaly`, contributes zero candidates, and the case reports no selected abnormal boundary. This case is **not** a `FALSE_POSITIVE` in the current committed state.

### 4.5 Remaining Control Cases

| Cases | Current comparison | What the evidence shows |
| :--- | :--- | :--- |
| `public-5gc-dnn-negative` | `CAPTURE_LIMITATION` | Protected NAS envelopes leave the inner 5GSM message and cause undecodable; no authoritative boundary is provable from the packets. The upstream "session rejection" label is metadata only. |
| `public-5gc-access-plmn-negative` | `DOMAIN_COVERAGE_GAP` | Baseline observed an NGAP `NGSetupFailure` boundary at frame 7; the `ngap-management` procedure family is owned by no implemented Domain Skill. |
| `public-5gc-access-plmn-recovery` | `DOMAIN_COVERAGE_GAP` | Only node-level `ngap-management` signaling is present; the family is unowned coverage. |
| `public-5gc-access-tai-negative` | `DOMAIN_COVERAGE_GAP` | Baseline observed an NGAP `NGSetupFailure` boundary at frame 7; the `ngap-management` procedure family is owned by no implemented Domain Skill. |
| `public-5gc-access-tai-recovery` | `DOMAIN_COVERAGE_GAP` | Only node-level `ngap-management` signaling is present; the family is unowned coverage. |
| `public-5gc-external-path-negative` | `OUT_OF_SCOPE` | Signaling occurs on the external N6 data path, outside current CoreNet scope. |
| `public-5gc-external-path-recovery` | `DOMAIN_COVERAGE_GAP` | GTP-U user-plane evidence is extracted, but the observed N3 procedure family `5gc-user-plane` is owned by no implemented Domain Skill. |

Every row distinguishes observed evidence from upstream test intent. An unimplemented Domain family is reported as unimplemented coverage (`DOMAIN_COVERAGE_GAP`, `DOMAIN_COVERAGE`, `EXPAND_FUTURE_SCOPE`) and excluded from the in-scope denominator; it is never converted into an implemented Domain failure.

### 4.6 Benchmark Metrics

All values are read directly from `benchmarks/golden-captures/benchmark-summary.json`:

| Metric | Current committed value |
| --- | ---: |
| `case_count` | 13 |
| `executed_case_count` | 13 |
| `blocked_case_count` | 0 |
| `exact_match_count` | 1 |
| `procedure_match_count` | 1 |
| `stage_match_count` | 1 |
| `false_positive_count` | 0 |
| `false_negative_count` | 0 |
| `domain_coverage_gap_count` | 5 |
| `capture_limitation_count` | 1 |
| `out_of_scope_count` | 1 |
| `needs_adjudication_count` | 0 |
| `no_abnormal_boundary_agreement_with_noncandidate_evidence_count` | 5 |
| `exact_frame_match_count` | 1 |
| `median_absolute_frame_delta` | 0.0 |
| `within_1_frame_count` | 1 |
| `within_3_frames_count` | 1 |
| `exact_match_rate` | 0.1667 |
| `procedure_match_rate` | 0.1667 |
| `stage_match_rate` | 0.1667 |
| `acceptable_difference_count` | 0 |
| `correlation_gap_count` | 0 |
| `domain_model_gap_count` | 0 |
| `orchestration_gap_count` | 0 |
| `protocol_coverage_gap_count` | 0 |
| `human_baseline_unsupported_count` | 0 |
| `unsafe_correlation_count` | 0 |

The accepted denominator remains:

```text
evaluated_in_scope =
    executed_case_count
    - out_of_scope_count
    - capture_limitation_count
    - human_baseline_unsupported_count
    - domain_coverage_gap_count
```

With the current committed values this is `13 - 1 - 1 - 0 - 5 = 6` evaluated in-scope cases. Current exact-match rate: `1 / 6 = 0.1667`. Current procedure-match rate: `1 / 6 = 0.1667` (recorded as `procedure_match_rate` `0.1667`), because an exact match entails a procedure match. Current stage-match rate: `1 / 6 = 0.1667`.

### 4.7 Metric Interpretation

The metric families answer different questions and must not be conflated:

- **Exact abnormal-boundary matching** (`exact_match_count`): full semantic agreement on the abnormal boundary, including stage, protocol, abnormal-event identity and evidence anchor. Currently `1`.
- **Frame agreement** (`exact_frame_match_count` `1`, `median_absolute_frame_delta` `0.0`): the authentication-negative case anchors both sides on frame 11. Frame agreement is never sufficient by itself: that case counts as an exact match only because its stage, protocol and abnormal-event identities agree as well.
- **Procedure-level matching** (`procedure_match_count` `1`): the procedure family matches. An exact match entails a procedure match, so this count includes the authentication-negative case and does not decrease when that case's stage disagreement is resolved.
- **Bounded no-abnormal-boundary agreement** (`no_abnormal_boundary_agreement_with_noncandidate_evidence_count` `5`): both sides observed no supported abnormal boundary and all relevant deviations are proven non-candidate. These five cases are **not** added to the exact-match count, and their zero contribution to `exact_match_count` is not evidence that they failed: they agree, boundedly, on the absence of a supported abnormal boundary.
- **Adjudication-required mismatches** (`needs_adjudication_count` `0`): no case currently requires adjudication; the authentication-negative stage difference was resolved by an authorized baseline revision.
- **Coverage exclusions** (`out_of_scope_count` `1`, `capture_limitation_count` `1`, `domain_coverage_gap_count` `5`): excluded from the in-scope denominator because no implemented Domain evidence can decide them; they are coverage boundaries, not accuracy failures.

---

## 5. Evidence-Type Classification of Domain Deviations

### 5.1 Accepted Deviation Taxonomy

Every Domain deviation type is classified into exactly one of four disjoint, exhaustive categories:

```text
candidate_eligible
evidence_limitation
supporting_anomaly
unclassified
```

The benchmark imports the accepted classification directly from the authoritative Orchestration model rather than inventing its own candidate-eligibility taxonomy. The three authoritative sets live in the Orchestration model (`skills/orchestration/5gc-failure-boundary/scripts/failure_boundary_model.py`) and are imported by the benchmark classifier (`benchmarks/golden-captures/scripts/deviation_classification.py`):

```text
ELIGIBLE_DEVIATION_TYPES
EVIDENCE_LIMITATION_TYPES
SUPPORTING_ANOMALY_TYPES
```

- `candidate_eligible`: in `ELIGIBLE_DEVIATION_TYPES` (for example `PROTOCOL_REJECT_OBSERVED`, `UNSUCCESSFUL_OUTCOME_OBSERVED`, `MISSING_EXPECTED_COUNTERPART`, `FIELD_CONFLICT`). May become an abnormal-boundary candidate.
- `evidence_limitation`: in `EVIDENCE_LIMITATION_TYPES` (for example `PARTIAL_CAPTURE`, `PROTECTED_INNER_MESSAGE_UNAVAILABLE`, `CORRELATION_AMBIGUITY`). A capture or association limitation that invents no observation and is never a candidate.
- `supporting_anomaly`: in `SUPPORTING_ANOMALY_TYPES` (`UNKNOWN_OR_RESERVED_PROTOCOL_VALUE`, `RECOVERED_INTERMEDIATE_OUTCOME_OBSERVED`). A non-candidate supporting observation retained as evidence.
- `unclassified`: everything else, including a missing or non-string deviation type. An unknown deviation type is never silently treated as benign and never silently folded into the limitation category.

The import direction is benchmark -> Skill: no Skill package imports benchmark code, so the frozen Skill architecture gains no reverse dependency.

### 5.2 Count Invariant

Every per-Domain deviation classification block satisfies the required count invariant:

```text
total_count =
    candidate_eligible_count
    + evidence_limitation_count
    + supporting_anomaly_count
    + unclassified_count
```

Each category count equals the sum of its per-type map. A block that cannot satisfy the invariant is rejected rather than repaired, because a silently inconsistent summary would let unknown evidence be read as proven non-candidate evidence.

### 5.3 Contract Semantics

- **Candidate eligibility is not boundary selection.** A deviation may be candidate-eligible and still never be selected as a boundary; eligibility never implies that Orchestration actually selected it.
- **A protected NAS envelope can be an evidence limitation.** When a NAS record's security envelope reports that the inner message is unavailable, the protected-envelope limitation (`PROTECTED_INNER_MESSAGE_UNAVAILABLE`) is the one deviation emitted for that record; the payload is never decoded or guessed.
- **A recovered intermediate Authentication outcome is supporting evidence.** `RECOVERED_INTERMEDIATE_OUTCOME_OBSERVED` records a packet-observed recovered intermediate outcome (as in `public-5gc-registration-resync`) and is never an abnormal-boundary candidate.
- **An unknown deviation type remains unclassified and requires review.** It is never defaulted to non-candidate.
- **Missing classification metadata is not treated as zero deviations.** A summary that omits the classification block is reported as unavailable and forces conservative review; absent evidence never becomes proven non-candidate evidence.
- **Non-candidate evidence does not automatically require Domain correction.** When every relevant deviation is classified and proven non-candidate and Orchestration consumption is verified, the bounded agreement status applies with `NO_CHANGE`.
- **Candidate-eligible evidence must not be silently ignored.** Candidate-eligible or unclassified deviations on a no-boundary outcome produce `NEEDS_ADJUDICATION`, never a quiet pass.

### 5.4 The Bounded Agreement Status Precisely

`NO_ABNORMAL_BOUNDARY_AGREEMENT_WITH_NONCANDIDATE_EVIDENCE` reports agreement only on the absence of a supported abnormal boundary within the capture and the implemented procedure scope. It does not assert:

```text
SUCCESS
HEALTHY_NETWORK
END_TO_END_SUCCESS
SERVICE_PASSED
```

Upstream scenario intent remains secondary metadata and is never independent proof of packet-level success.

---

## 6. Verified Orchestration Consumption

### 6.1 Positive-Consumption Contract

A healthy or recovery comparison cannot be considered positively agreed merely because `selection_status = NO_ABNORMAL_BOUNDARY_OBSERVED`. The benchmark must positively establish that relevant Domain instances were reconstructed and consumed. An absence of evidence never satisfies a positive acceptance condition.

The structured evidence fields are reported in `skill-result-summary.json`:

```text
domain_status
orchestration_status
source_domain_instances_count
consumed_domain_instance_counts
consumed_unmapped_source_domain_instance_count
candidate_boundary_count
candidate_boundaries_count
```

- `domain_status`: per-Domain execution evidence (`execution_status`, `output_present`, `instance_count`, `deviation_count`, `deviation_classification`, bounded `first_stop_reason`).
- `orchestration_status`: Orchestration execution evidence (`execution_status`, `output_present`, `diagnostic_group_count`, `source_domain_instances_count`, `candidate_boundary_count`, the per-Domain consumed-instance map, and the unmapped consumed count).
- `candidate_boundaries_count` (summary level) and `orchestration_status.candidate_boundary_count` must both be non-negative integers, both be zero for a no-boundary agreement, and agree with each other.

### 6.2 Source Identity Mapping

The Orchestration source Domain names map to the benchmark Domain keys as follows:

| Orchestration source Domain | Benchmark key |
| --- | --- |
| `5gc-registration-mobility` | `registration` |
| `5gc-pdu-session` | `pdu_session` |
| `5gc-handover-mobility` | `handover_mobility` |

### 6.3 Consumption-Count Invariant

The required consumption-count invariant is:

```text
sum(consumed_domain_instance_counts.values())
    + consumed_unmapped_source_domain_instance_count
    == source_domain_instances_count
```

Per-Domain consumed counts must additionally never exceed the produced instance counts for the same Domain.

### 6.4 Evaluation Rules

- **Primary diagnostic-group authority.** A diagnostic-group count is not consumption evidence by itself; the per-Domain consumed-instance map is. An aggregate consumed-instance count alone does not identify the contributing Domain.
- **Per-Domain instance consumption.** Consumption is verified per relevant Domain key. Only relevant Domain keys are read; an unrelated Domain instance never satisfies a missing relevant Domain.
- **Produced-versus-consumed count limits.** A consumed count greater than the produced count for the same Domain makes the metadata internally inconsistent.
- **Missing execution evidence.** `execution_status` values that never started, or a missing `orchestration_status`, are reported as missing evidence, never as successful consumption.
- **Unrelated Domain consumption.** Consuming instances of Domains the baseline never made relevant does not establish relevant consumption.
- **Missing legacy consumption maps.** A legacy summary without `consumed_domain_instance_counts` cannot positively verify consumption and is never read as successful consumption.
- **Inconsistent candidate-boundary counts.** Disagreeing or non-zero candidate counts block a positive agreement; contradictions are recorded as discrepancies and never resolved by discarding actual candidates.
- **Established consumption failure versus unverified metadata.** An established Orchestration consumption failure (for example Orchestration consumed no instance of a relevant Domain that was reconstructed from capture evidence, or produced no diagnostic group from Domain instances that reported deviations) may produce `ORCHESTRATION_GAP` with `ORCHESTRATION` attribution. Unverified consumption metadata (missing fields, malformed counts, violated invariants) must remain conservative: it blocks positive agreement but authorizes no failing-layer claim and no positive result.

These states are exactly the implemented comparator contract and are not reinterpreted beyond it.

---

## 7. Reproduction and Execution Instructions

### 7.1 Prerequisites

- Python 3.10+ (the frozen records were generated with Python 3.13.14; other untested platforms and Python versions are not claimed as supported).
- **TShark 4.7.1 exactly** — the pinned decoder baseline. Verify with `tshark --version`. No currently installed TShark version is acceptable by default: TShark 4.2.x is not a substitute, and decoder output is not stable across Wireshark releases.
- The external capture corpus cloned outside the repository at the pinned commit.
- A clean, isolated Wireshark configuration directory (section 7.2).

### 7.2 Wireshark Profile Isolation

Empirical configuration prerequisite: the reproduction must use a clean, isolated Wireshark configuration directory, selected through the `WIRESHARK_CONFIG_DIR` environment variable.

A host Wireshark preference such as:

```text
nas-5gs.null_decipher: TRUE
```

changes how protected NAS envelopes are dissected and may cause ambiguous mixed 5GMM/5GSM extraction records. The accepted reproduction requires the relevant preference to remain at its clean-profile default:

```text
nas-5gs.null_decipher: FALSE
```

A personal Wireshark profile must not be modified. Isolate the configuration before launching the benchmark instead:

```bash
# Linux / macOS example: point TShark at a clean, empty configuration directory
export WIRESHARK_CONFIG_DIR=/tmp/corenet-wireshark-profile
mkdir -p "$WIRESHARK_CONFIG_DIR"
```

```powershell
# Windows example: same isolation before launching the benchmark
$env:WIRESHARK_CONFIG_DIR = "C:\temp\corenet-wireshark-profile"
New-Item -ItemType Directory -Force -Path $env:WIRESHARK_CONFIG_DIR | Out-Null
```

Do not invent decoder configuration options or rely on undocumented environment behavior; the only requirement is the clean-profile default above, enforced through `WIRESHARK_CONFIG_DIR` isolation.

### 7.3 External Path Isolation

Four locations stay distinct:

1. **External corpus source directory** — the cloned public capture repository (read-only input).
2. **External pipeline work directory** — raw intermediate artifacts (`*-events.jsonl`, `*-trace.jsonl`) produced by the pipeline; never committed.
3. **External sanitized output directory** — where the runner writes sanitized `skill-result-summary.json`, `differential.json` and `benchmark-summary.json` during routine reproduction.
4. **Explicit, reviewed import into the repository** — the only path by which sanitized artifacts are copied into `benchmarks/golden-captures/cases/`.

The normal reproduction instructions must not write benchmark outputs directly into the tracked `cases/` directory. Note that the runner's own default `--output-root` is repository-local (`benchmarks/golden-captures/cases`), so a safe reproducibility command must explicitly supply an external output path. Ordinary offline validation never requires an external capture checkout.

### 7.4 Full Public-Corpus Reproduction

1. Clone the external public capture corpus into a temporary directory and check out the pinned commit:

   ```bash
   git clone https://github.com/abdelrahman-fawaz18/5g-sa-core-protocol-lab /tmp/corenet-golden-source
   git -C /tmp/corenet-golden-source checkout 82934c2cc231540fa425e48177d4bed33210bfc1
   ```

   Each of the 13 captures is checked against its recorded SHA-256 digest by the runner before execution.

2. Execute the public corpus runner with **external** work and output roots:

   ```bash
   python benchmarks/golden-captures/scripts/run_public_corpus.py \
       --source-root /tmp/corenet-golden-source \
       --work-root /tmp/corenet-golden-run \
       --output-root /tmp/corenet-golden-output
   ```

   Accepted runner CLI:

   ```text
   run_public_corpus.py
       --source-root
       --work-root
       --output-root
       [--import-to-cases]
   ```

   `--import-to-cases` copies the sanitized summaries and differentials into `benchmarks/golden-captures/cases/`. It is an explicitly authorized artifact-update action taken only after review, not part of routine reproduction.

### 7.5 Recomputing Differential Records (artifact-update flow)

When only the comparison contract or an adjudicated baseline changes, differential records can be recomputed from the already frozen baselines and sanitized summaries. No capture, Protocol, Correlation, Domain or Orchestration execution is involved, so the Skill runtime stays byte-identical. This flow writes repository artifacts and therefore belongs to an authorized artifact update, not routine reproduction:

```bash
python benchmarks/golden-captures/scripts/compare_results.py \
    --baseline benchmarks/golden-captures/cases/<case-id>/human-baseline.json \
    --skill-summary benchmarks/golden-captures/cases/<case-id>/skill-result-summary.json \
    --output benchmarks/golden-captures/cases/<case-id>/differential.json \
    --intent "<upstream scenario intent>"
python benchmarks/golden-captures/scripts/summarize_benchmark.py \
    --corenet-commit <generation-revision-sha> --source-commit 82934c2cc231540fa425e48177d4bed33210bfc1
```

A regenerated corpus records the benchmark generation revision, the unchanged Skill runtime state, and the pinned external source commit; nothing is edited after the recomputation begins.

### 7.6 Offline Validation (no external corpus)

Standard repository validation is deterministic and offline. It does not require the external capture corpus, a checkout of the corpus repository, or TShark:

```bash
python scripts/validate-repository.py
python scripts/validate-architecture.py
python scripts/validate-golden-captures.py

python -m unittest discover \
  -s benchmarks/golden-captures/tests \
  -p 'test_*.py' -v

python -m unittest discover \
  -s tests \
  -p 'test_*.py' -v

python -m compileall scripts
```

Offline unit testing (validators and the deterministic test suites) is distinct from real corpus reproduction: passing the offline gates does not claim that a TShark corpus run was executed, and a full 13-case TShark rerun is required only when new empirical claims are introduced.

### 7.7 Ubuntu Development Helper

On Ubuntu 24.04, `scripts/dev.sh` wraps the environment checks and validation gates:

```bash
./scripts/dev.sh doctor
./scripts/dev.sh validate
./scripts/dev.sh golden-preflight --source-root /path/to/external/corpus
```

- `doctor` checks development prerequisites (read-only diagnosis of platform, Python, and tooling readiness).
- `validate` runs repository validation and deterministic tests.
- `golden-preflight` checks the pinned external reproduction prerequisites (TShark presence and the exact `4.7.1` version, external corpus layout and path containment) before a full public-corpus run.

Standard offline validation is distinct from full public-corpus reproduction. `scripts/dev.sh` targets Ubuntu 24.04; it is not a native Windows executable. A Windows reproduction environment using a separately available TShark binary must follow the same pinned corpus, pinned decoder (`4.7.1`) and profile-isolation rules (sections 7.1-7.3). No support for untested platforms or Python versions is claimed.

---

## 8. Historical Findings and Provenance

### 8.1 Historical Investigation Findings

The findings below are preserved historical investigation records from earlier benchmark and correction passes. They describe outcomes **as recorded at their own commits** and are not current accepted results; where a recorded outcome has since been superseded, section 8.3 names the supersession. The current committed empirical state is section 4 and must be read from the committed artifacts.

During empirical benchmark execution with TShark 4.7.1, several protocol extraction differences were uncovered:
1. **NGAP Column Casing**: TShark 4.7.1 outputs `_ws.col.info` (lowercase), whereas legacy dissector parsing strictly checked for `_ws.col.Info` (uppercase), causing extraction exit code 4.
2. **NAS-5GS Field Delimiters**: TShark 4.7.1 uses underscore delimiters for 5GMM message types (`nas_5gs.mm.message_type`), causing extractors configured for dashed keys (`nas-5gs.mm.message_type`) to parse message types as `None`.
3. **PFCP and GTP-U JSON Field Formatting**: TShark 4.7.1 JSON formatting variations led to extraction exit code 4.

The authorized correction pass that followed reproduced every case against the frozen corpus and adjudicated three further findings:

4. **Benchmark identity probe read one shared JSON path**: the pipeline checked a top-level `message_type` for every protocol, while the accepted PFCP and GTP-U Skills expose identity inside their bounded `header` object (`header.message_type`, `header.message_type_code`). Healthy extraction of `PFCP Session Establishment Request` (50) and `G-PDU` (255) was therefore reported as `MISSING_MESSAGE_TYPE`. The probe is now contract-aware per protocol (see 3.4).
5. **NGAP composite Info column**: TShark renders `_ws.col.info` as a composite string when a frame also carries SCTP acknowledgement text, a nested NAS message name, or coalesced NGAP PDUs (for example `SACK (Ack=1, Arwnd=106496) , DownlinkNASTransport, Authentication request`). Exact whole-string matching against the reviewed branch vocabulary left `message_type` null for procedures the bounded NGAP Skill does own. `ngap` 0.3.2 matches the reviewed vocabulary against the whole string first and then against its comma- and bracket-delimited segments; only exact segment equality resolves, so no message name outside the reviewed table is produced and `NGSetup` stays `UNSUPPORTED` with a null identity.
6. **Domain input contract rejects mixed-ownership captures**: each 5GC Domain Skill required a `message_type` string on every NGAP record and therefore exited with a malformed-input error on captures containing NGAP procedures outside bounded NGAP ownership (for example `NGSetup` at the start of every capture in this corpus). Reconstruction stopped at input validation, before any procedure instance was formed. This was recorded at the time as the first Domain contract gap with the exact per-Domain `first_stop_reason`; Domain runtime semantics were frozen and were not modified during that pass. Finding 11 records the authorized correction.

A later evidence and scoring contract correction pass reproduced every case against the same frozen corpus and adjudicated four further findings, without touching any Skill runtime:

7. **Encrypted NAS cannot carry a decoded verdict**: independent TShark 4.7.1 field inspection of `captures/fault-injection/unsupported-dnn/fault.pcap` shows no `nas-5gs.sm.message_type` or 5GSM cause value in any of its 28 frames, frames 13 and 17-21 expose only `nas-5gs.security_header_type` 2 or 4 with `nas-5gs.ciphered_msg`, and the protected exchange continues past frame 18 through frames 19, 20 and 21. The `public-5gc-dnn-negative` baseline therefore moved from `BOUNDARY_OBSERVED` to `INSUFFICIENT_EVIDENCE` at `baseline_revision` 3 with no first abnormal boundary: a protected NAS envelope plus an absent `PDUSessionResourceSetup` proves neither a PDU Session Reject nor its Cause, the upstream fault-injection label is secondary metadata only, and no precise abnormal frame was invented. The superseded canonical digest is recorded inside `revision_reason`.
8. **Frame agreement is not semantic agreement**: the comparator previously reported `EXACT_MATCH` on procedure family plus frame equality alone, and scored a one- or two-frame delta as a near-frame match without checking stage, protocol or abnormal-event identity. Both paths now require compatible reported semantics and treat sanitizer placeholders as unreported detail that must be adjudicated.
9. **Coverage, ambiguity and Domain relevance**: unowned procedure families were counted as implemented Domain failures, an unresolved `AMBIGUOUS_FIRST_BOUNDARY` on healthy traffic was scored as a confirmed `FALSE_POSITIVE`, and a missing relevant Domain fell back to sorted Domain keys so an unrelated Domain instance could satisfy it. They now report `DOMAIN_COVERAGE_GAP`, `NEEDS_ADJUDICATION` with `MULTIPLE` attribution, and an explicit `NO_RELEVANT_DOMAIN` state respectively, and only relevant Domain keys are read.
10. **Legacy `baseline_hash` is not a digest proof**: the informational `baseline_hash` recorded in the frozen baselines matches neither `canonical_json_sha256` of the stored document, nor of the document without that field, nor the raw file digest. It is documented as a legacy label, is never verified, and no comparator or metric consumes it; a regression test asserts that removing it changes no comparison result. Baseline immutability rests solely on `differential.human_baseline_sha256`, which `scripts/validate-golden-captures.py` recomputes, and an authorized revision must cite the digest it supersedes while dropping the legacy label.

A later Domain input-contract correction pass reproduced every case against the same frozen corpus and adjudicated one further finding:

11. **Unowned Protocol evidence is not malformed Protocol evidence**: the three 5GC Domain loaders rejected any NGAP record without a `message_type` string, so a capture whose first NGAP records were the node-level NG Setup exchange failed the whole Domain input before the supported UE evidence downstream could be read. The loaders now classify by identity first, matching the reviewed Protocol health vocabulary in section 3.4: a record that exposes a message identity is usable evidence; a record that declares `SUPPORTED` while exposing no identity is a `MISSING_MESSAGE_TYPE` contract failure and still fails loudly; a record the ngap Skill recognizes but declares `UNSUPPORTED` with no identity is accepted as bounded, unowned evidence. Unowned records never open or extend a UE context or handover half, never form an instance or attempt, never contribute a frame to a provenance join or a timestamp to an observation window or chronology judgement, and therefore never become a stage, deviation, or Orchestration candidate. `5gc-pdu-session` retains them as unbound N2 evidence and `5gc-handover-mobility` retains them as unbound mobility evidence with their original provenance; `5gc-registration-mobility` accepts them and models nothing from them, because its only unbound carrier emits stage records and an unowned record must not create a procedure stage. `UNKNOWN` records, absent `support_status`, and missing provenance keep failing loudly. No NG Setup, N6, or new procedure semantics were added, and no Domain was tuned toward a benchmark outcome.

12. **A UE context is not a PDU Session**: `5gc-pdu-session` created a procedure instance whenever a capture carried any NAS, owned NGAP, PFCP, or SBI record and no instance had been discovered, using an assumed PDU Session ID 1. Two real captures exposed the defect: in `captures/fault-injection/authentication-key-mismatch/fault.pcap` and `captures/fault-injection/unsupported-dnn/fault.pcap` the field `ngap.pDUSessionID` has no value in any frame, no PDU Session Resource message, PFCP, or GTP-U session traffic is present, and no 5GSM message identity is decodable, yet each produced one instance whose only deviation was a `PARTIAL_CAPTURE` carrying an empty `evidence_refs` array and a null observation window. The Skill now forms an instance only when a PDU Session ID is explicitly present in a decoded 5GSM NAS message, an NGAP PDU Session Resource item, or an SBI session-management payload, and it binds a UE context only when the capture leaves exactly one candidate. A PFCP SEID, GTP-U TEID, and QFI are never read as a session identity, an unresolved identity is never defaulted, and evidence that cannot be bound stays visible in the unbound-evidence sections. The five captures with observable `ngap.pDUSessionID` values keep their session instances unchanged, so a partial capture that starts after initiation remains legitimate procedure evidence; no complete establishment sequence is required, no terminal outcome is invented, and the correction removed no Orchestration candidate. This implements adjudication reference `corr-02`; the Registration deviation-carrier finding (`corr-01`) is recorded as finding 13, and `corr-03` and `corr-04` remained open at that time. The adjudication records stay frozen at the runtime they describe.

13. **One physical observation must carry one deviation type**: a NAS record whose payload is security-protected and cannot be opened arrives from the lower layers with no dissected message-type octet at all, so the nas-5gs Skill declares its support status `UNKNOWN`. `5gc-registration-mobility` reported that status as `UNKNOWN_OR_RESERVED_PROTOCOL_VALUE` and then reported the same record again as `PROTECTED_INNER_MESSAGE_UNAVAILABLE`, so a single frame appeared under two deviation types and inflated every Registration deviation total on captures that continue past Security Mode Command. The Skill now tests the stated envelope first: when a NAS record's `security` object says `inner_message_available` is `false`, the protected-envelope limitation is the one deviation emitted for that record, and no protocol-value deviation is added. A record that genuinely exposes a dissected message type the Domain does not own keeps `UNKNOWN_OR_RESERVED_PROTOCOL_VALUE`, an `UNKNOWN` status with no stated protected envelope keeps it, and an unowned NGAP record with a null identity is still never a stage, deviation, or candidate, so finding 11's contract is unchanged. Across the corpus the correction removed exactly 32 duplicated protocol-value deviations, 5 in each of `public-5gc-baseline-lifecycle`, `public-5gc-baseline-user-plane`, `public-5gc-registration-resync`, `public-5gc-auth-recovery`, and `public-5gc-dnn-recovery` and 7 in `public-5gc-dnn-negative`, and removed none in `public-5gc-auth-negative`, whose three deviations carry no protected envelope. Because Analysis Orchestration classifies `UNKNOWN_OR_RESERVED_PROTOCOL_VALUE` as a supporting anomaly and never as a boundary candidate, candidate counts, diagnostic group counts, selection statuses, comparison statuses, attributions, eligibilities and every aggregate metric were unchanged at that time; nothing was reinterpreted as evidence of anything else, no protected payload was decoded or guessed, and no DNN or authentication conclusion was invented.

14. **An absence is a finding only when the evidence can carry it**: `5gc-registration-mobility` published `MISSING_EXPECTED_COUNTERPART` from two places. The stage evaluator published it for any entered conditional branch whose expected outcome was not observed, including a Security Mode Command whose following uplink NAS is ciphered. A separate terminal rule published it for the `registration-decision` stage whenever a Registration request or `InitialUEMessage` was present and no accept or reject had been observed, and because that branch is activated only by an observed accept or reject, no stage record existed to give it a position. Analysis Orchestration treats `MISSING_EXPECTED_COUNTERPART` as boundary-eligible, so all 13 of those deviations across the seven Registration cases became window-only candidates with `frame_number: null` and `stage_position: null` — the candidates the accepted adjudication recorded as `POTENTIALLY_SPURIOUS` — and each tied against every other, which is why every one of those captures ended in `AMBIGUOUS_FIRST_BOUNDARY`. The Domain now separates the four statements the single deviation type had been collapsing. A counterpart that could be inside a protected envelope is recorded as a stage limitation naming the hiding frames. A window that ends at the branch trigger is recorded as a capture limitation. Absence of a Registration accept or reject stays carried by the terminal observation `NO_REGISTRATION_TERMINAL_OBSERVATION_IN_WINDOW` plus a stage limitation, because that branch was never entered. A branch that was entered, whose counterpart stayed decodable, and whose window continued past the trigger still publishes the deviation, and 6 such findings remain in the package fixtures (`accept-no-complete`, `binding-conflict`, `complete-then-release`, `duplicate`, `partial-start`, `release-paging-no-response`, all on the authentication branch). No stage position was invented.

15. **The sanitized summary cannot read a selected boundary** (historical harness gap, since corrected — see finding 16): the removal of the unanchored candidates let two captures reach `SELECTED` for the first time, which exposed a harness gap that no accepted run had ever exercised. `scripts/sanitize_result.py` read `selected_boundary.boundary_anchor`, `selected_boundary.deviation_type` and `selected_boundary.source_domain`, while the accepted `5gc-failure-boundary` output schema publishes those fields one level deeper, under `selected_boundary.boundary_ref`. Every field therefore fell through to its placeholder, and the summary recorded the selected boundary as frame `1`, message `UNKNOWN`, protocol `UNKNOWN`, domain `UNKNOWN`. The raw Orchestration artifact in the same pipeline run was correct: `public-5gc-auth-negative` selected `boundary_anchor.frame_number 11`, `NAS-5GS Authentication failure`, exactly the boundary the independent human baseline records, yet the frozen comparator scored that case `ORCHESTRATION_GAP` with a placeholder artifact frame delta. This was a reporting defect in the benchmark harness, not an Orchestration selection defect and not a Domain defect.

16. **The selected-boundary harness gap is corrected**: `scripts/sanitize_result.py` now reads the selected boundary through the nested `selected_boundary.boundary_ref` object the accepted `5gc-failure-boundary` output schema publishes, instead of reading `boundary_anchor`, `deviation_type` and `source_domain` directly under `selected_boundary` and falling through to frame-1 / `UNKNOWN` placeholders. The sanitized summary for a `SELECTED` result now reproduces the selected candidate's actual source domain, procedure family, procedure stage (including a legitimate null), anchor frame, timestamp, protocol, message identity, deviation type and evidence level, and fails loudly when a `SELECTED` result lacks its `boundary_ref` or its required anchor or identity fields. At that commit, `public-5gc-auth-negative` moved from `ORCHESTRATION_GAP` with a fabricated frame-1 anchor to `NEEDS_ADJUDICATION` with the exact frame-11 `NAS-5GS Authentication failure` the baseline records. (That intermediate comparison status is itself historical; the current committed comparison is `PROCEDURE_MATCH_STAGE_DIFFERENCE` — see section 4.3.) No Skill, comparator, baseline or adjudication changed in that pass.

Later accepted correction passes added the evidence-type deviation classification and the verified Orchestration-consumption contract documented in sections 5 and 6, and recomputed the sanitized summaries and differentials accordingly. Those passes are runtime and harness corrections with their own commits; their outcomes are the current state described in section 4, not historical findings.

### 8.2 Provenance of Committed Records

Three provenance layers are deliberately distinguished:

1. **The source revision used to generate the benchmark** — recorded as `corenet_commit` inside `benchmark-summary.json` (`6d53019b96e26c7681c9921cd670aa6cce8292a4` as committed) together with `external_source_commit` (`82934c2cc231540fa425e48177d4bed33210bfc1`), `generated_at`, `tshark_version`, `python_version` and the per-Skill `skill_versions` map. These recorded values may reflect an earlier revision than the commit that later stored the regenerated artifacts, and they are preserved exactly as recorded.
2. **The Git commit storing regenerated benchmark artifacts** — `955105bed87d44a582410e29c2fa2d35f270d685` (sanitized summaries carrying the per-Domain consumption map and recomputed records).
3. **The later documentation-only synchronization commit** — this README change. It runs no empirical benchmark and must not make an older empirical run appear to have been performed again.

Earlier investigation passes named their own framework and runtime commits in the findings above; those references are provenance for the historical records only.

### 8.3 Supersession Notes

To keep historical records from being read as current results, the following historical statements are explicitly superseded by the current committed state (section 4):

- The registration-resynchronization case is **no longer** reported as `FALSE_POSITIVE`; its current committed comparison is `NO_ABNORMAL_BOUNDARY_AGREEMENT_WITH_NONCANDIDATE_EVIDENCE` with the recovered intermediate Authentication outcome retained as supporting anomaly `RECOVERED_INTERMEDIATE_OUTCOME_OBSERVED`.
- The five bounded-agreement cases are **no longer** reported as `NEEDS_ADJUDICATION`; their current committed comparison is `NO_ABNORMAL_BOUNDARY_AGREEMENT_WITH_NONCANDIDATE_EVIDENCE` with `NONE` attribution.
- The authentication-negative case is **no longer** reported with an unreported/`UNKNOWN` stage, as `NEEDS_ADJUDICATION`/`ORCHESTRATION_GAP`, or as a stage difference; its current committed comparison is `EXACT_MATCH` with `NONE` attribution and no adjudication requirement, after the authorized human-baseline revision recorded in `adjudications/authentication-stage-baseline-revision.md`.
- The current adjudication-required count is **zero**; the authentication-negative stage difference that previously accounted for the single adjudication requirement was resolved by an authorized baseline revision.
- Statements in earlier notes that "the comparator is unchanged" describe only the pass in which they were written; the comparator has since gained evidence-type classification and verified Orchestration consumption (sections 5 and 6).

---

## 9. Remaining Limitations and Open Governance Questions

The authentication-negative procedure-stage difference is resolved. The independent human baseline now
records the stage `authentication` at `baseline_revision` 1, matching the Skill Domain stage, and the
case is an `EXACT_MATCH` with `NONE` attribution and no adjudication requirement. The correction is
recorded in `adjudications/authentication-stage-baseline-revision.md`.

Resolving that single case did not resolve the corpus-wide governance questions the accepted
independent review recorded:

- **Baseline stage vocabulary.** The baseline schema still leaves `procedure_stage` free-form while the
  comparator requires exact normalized identity, and the other 12 baselines still use a vocabulary
  disjoint from the Domain stage catalog. Stage agreement therefore remains undefined for any baseline
  label not drawn from that catalog; this case is simply no longer the visible instance of the gap,
  because it no longer carries a mismatched label. Whether a shared vocabulary or an explicit mapping
  should exist is a governance decision no benchmark record settles.
- **Layer attribution expressiveness.** The differential still assigns `DOMAIN` and
  `CORRECT_DOMAIN_MODEL` to any in-family boundary-semantics mismatch without evaluating which side
  departed. That policy is unchanged; the `NONE` attribution now recorded for this case is its ordinary
  exact-match outcome, not a repair of the attribution gap.

Both questions require their own separate authorization.

Two further limitations remain unchanged. The timestamp-provenance discrepancy between the original
capture epochs and the timestamps stored in the historical case and baseline records is unresolved and
was deliberately left outside the authorized correction: `case.json` is byte-identical, the boundary
timestamp is unchanged, and no timestamp agreement is asserted. The documented coverage exclusions of
section 4.5 (unimplemented `ngap-management` and `5gc-user-plane` procedure families, the external N6
path) and the protected-NAS capture limitation of `public-5gc-dnn-negative` are scope boundaries of the
current repository, not asserted defects.

Further work beyond this baseline revision and its required synchronization requires separate
authorization.
