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

---

## 2. Methodology and Governance

### 2.1 Independent Baseline Methodology and Freeze Order
To prevent bias, human/agent baseline analyses are conducted independently before running automated Skill execution:
1. **Raw Capture Inspection**: The packet capture is decoded and inspected against 3GPP and IETF normative specifications (3GPP TS 38.413 for NGAP, 3GPP TS 24.501 for NAS-5GS, 3GPP TS 29.244 for PFCP, 3GPP TS 29.281 for GTP-U, and RFC 7540 / 3GPP TS 29.500 for SBI HTTP/2).
2. **Independent Baseline Authoring**: An independent baseline record (`human-baseline.json`) is authored defining observed procedures, abnormal boundaries, supporting packet evidence, capture limitations, and baseline confidence.
3. **Canonical Schema and Hash Freezing**: The baseline is validated against `human-baseline.schema.json` and its deterministic, platform-independent canonical JSON hash (`canonical_json_sha256`) is computed and recorded. This guarantees cross-platform digest invariance across operating systems, line endings (LF vs CRLF), indentation, and JSON key ordering.
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
| 4 | Relevant Domain reconstruction | Did the relevant Domain Skill actually reconstruct a procedure instance? | `PRESENT`, `NO_RELEVANT_INSTANCE`, `FAILED`, `NOT_APPLICABLE`, `NOT_EVALUATED` |
| 5 | Orchestration availability | Did Orchestration consume the reconstructed Domain evidence? | `AVAILABLE`, `FAILED`, `NOT_RUN`, `NOT_REPORTED`, `NOT_APPLICABLE`, `NOT_EVALUATED` |
| 6 | Semantic boundary comparison | Do the human and automated boundaries agree? | `EVALUATED`, `NOT_EVALUATED` |

Per-Domain execution evidence is reported separately from Orchestration evidence in `skill-result-summary.json` (`domain_status` and `orchestration_status`), so one counter never carries two meanings: `domain_instances_count` is the number of procedure instances produced by executed Domain Skills, while `orchestration_status.source_domain_instances_count` is what Orchestration consumed. Each `domain_status` entry also records `execution_status`, `output_present`, `deviation_count` and a bounded, path-free `first_stop_reason` so a reconstruction that never started is never reported as a reconstruction that found nothing.

Layers 4 and 5 are `NOT_APPLICABLE` when the baseline observes only procedure families that no implemented Domain Skill owns (for example node-level `ngap-management` or a planned `5gc-user-plane` family): no Domain instance is expected, so absent reconstruction is an ownership gap reported as `DOMAIN_MODEL_GAP` with `EXPAND_FUTURE_SCOPE`, never as a Domain model defect requiring correction.

The following states are strictly non-equivalent:
- **Evidence-Supported Health**: relevant protocol signaling parsed -> relevant Domain instance reconstructed with no deviation -> Orchestration ran -> no abnormal boundary observed (`EXACT_MATCH`, eligibility `ELIGIBLE`).
- **Domain Reconstruction Failure**: protocol extraction healthy -> the relevant Domain Skill produced no instance, for example an input-contract rejection -> no boundary produced (`DOMAIN_MODEL_GAP`, layer `DOMAIN`).
- **Unextracted Pipeline Failure**: protocol extraction failed, or exposed no message identity for a case it reports as supported -> zero Domain instances -> no boundary produced (`PROTOCOL_COVERAGE_GAP`, layer `PROTOCOL`).

A healthy `EXACT_MATCH` therefore requires a relevant Domain instance to have been produced and consumed. Protocol success with zero relevant Domain instances is never `EXACT_MATCH`.

### 2.3 Standards-Based and Implementation-Neutral Discipline
The benchmark evaluates standardized protocol signaling behavior exclusively. Captures produced by external lab environments are treated as packet evidence only. In adherence with repository policy:
- No implementation-specific source code, internal state machines, log structures, configuration quirks, or project bug knowledge are incorporated into benchmark records or Skill definitions.
- All procedure definitions and boundary verdicts derive directly from standardized 3GPP specifications.

### 2.4 Artifact Safety and Repository Hygiene
- **Zero Raw PCAP in Git**: Binary packet capture files (`.pcap`, `.pcapng`, `.cap`) are strictly forbidden from being committed into the repository.
- **External Working Directory**: Benchmark runs execute entirely within an external temporary directory (`/tmp/corenet-golden-run/` or Windows equivalent). Intermediate raw protocol dumps (`*-events.jsonl`, `*-trace.jsonl`) remain in the external workspace.
- **Sanitized Summaries**: Only non-sensitive, aggregated summaries (`skill-result-summary.json`, `differential.json`) conforming to strict schemas are checked into the repository. Subscriber identifiers (SUPI/IMSI) and workstation-specific paths are excluded.

---

## 3. Differential Taxonomy and Discrepancy Attribution

### 3.1 Comparison Statuses
- `EXACT_MATCH`: Automated Skill selected the exact same procedure family and frame boundary, or both observed no abnormal boundary in healthy/recovered traffic **and** a relevant Domain instance was actually reconstructed with zero deviations under an eligible evidence pipeline.
- `BOUNDARY_FRAME_DIFFERENCE`: Procedure family matches, but the selected frame differs by 1–2 adjacent transaction frames.
- `PROCEDURE_MATCH_STAGE_DIFFERENCE`: Procedure family matches, but stage attribution differs.
- `ACCEPTABLE_DIFFERENCE`: Human baseline and Skill selected valid alternative boundaries supported by capture evidence.
- `FALSE_POSITIVE`: Skill selected an abnormal boundary in healthy/recovered signaling.
- `FALSE_NEGATIVE`: A relevant Domain instance was reconstructed but reported no deviation supporting an abnormal boundary the independent baseline observed. (A missing Domain instance is `DOMAIN_MODEL_GAP`, and a Domain deviation that Orchestration did not consume is `ORCHESTRATION_GAP`; the benchmark never jumps from Protocol success to a generic false negative without recording the Domain evidence state.)
- `PROTOCOL_COVERAGE_GAP`: Protocol extractor encountered an unhandled dissector field or decode error.
- `CORRELATION_GAP`: Cross-protocol correlation failed to group interrelated signaling events.
- `DOMAIN_MODEL_GAP`: Observed procedure is unowned by currently implemented domain skills (e.g. node-level management vs UE signaling), or the relevant Domain Skill executed and reconstructed no procedure instance / emitted no deviation supporting a boundary the independent baseline observed.
- `ORCHESTRATION_GAP`: Domain detected the issue, but failure-boundary orchestration selected the wrong diagnostic candidate, declined to resolve a single first boundary, or failed to consume Domain instances that reported deviations.
- `CAPTURE_LIMITATION`: Truncated packet capture or missing interfaces prevent authoritative analysis.
- `OUT_OF_SCOPE`: Signaling occurs on interfaces outside current CoreNet scope (e.g. external N6 data routing).

### 3.2 Lowest-Layer Attribution Rule
When a discrepancy occurs between the independent baseline and automated execution, the discrepancy is attributed to the **lowest layer** that accounts for it:
$$\text{Protocol} \longrightarrow \text{Correlation} \longrightarrow \text{Domain} \longrightarrow \text{Orchestration}$$
If a protocol extractor fails to extract a message or field, the discrepancy is attributed to `PROTOCOL` (`PROTOCOL_COVERAGE_GAP`), rather than blaming higher Domain or Orchestration layers for missing evidence.

### 3.3 Protocol Extraction Statuses
`skill-result-summary.json.protocol_status` records one status per Protocol Skill, judged against that Skill's own message-identity contract: PFCP and GTP-U expose identity inside the bounded `header` object, while NGAP, NAS-5GS and SBI-HTTP2 expose it at the detailed-event top level. Probing a single shared path for every protocol misreports healthy extraction as a failure.

- `SUCCESS`: extraction succeeded and every record the Skill reports as `SUPPORTED` exposes a usable message identity.
- `SUCCESS_WITH_UNSUPPORTED_SEMANTICS`: extraction succeeded and supported records are fully identified, but the capture also contains procedures the bounded Skill intentionally does not own (for example NGAP `NGSetup`). Bounded scope, not an extractor failure.
- `SUCCESS_WITH_PROTECTED_PAYLOAD`: extraction succeeded, but identity is unavailable for records whose payload is security-protected (ciphered NAS after Security Mode). A capture and security limitation, not an extractor failure.
- `MISSING_MESSAGE_TYPE`: a record the Skill itself classifies as `SUPPORTED` exposed no message identity. This is a precise extractor compatibility failure; it never means the Skill recognized a procedure it does not own.
- `NOT_OBSERVED_IN_CAPTURE`: the extractor matched no packets of that protocol.
- `ERROR_<code>`: the extractor exited with a failure code other than the empty-match code.

Only `MISSING_MESSAGE_TYPE`, `ERROR_*`, a missing status for a relevant protocol, and `NOT_OBSERVED_IN_CAPTURE` for a protocol the baseline declares present are counted as Protocol defects. The three `SUCCESS*` states keep the comparison eligible.

---

## 4. Public Capture Corpus and Empirical Results

The benchmark evaluates 13 captures from the public repository `abdelrahman-fawaz18/5g-sa-core-protocol-lab` pinned at commit `82934c2cc231540fa425e48177d4bed33210bfc1`. The results below were produced by a single frozen run against CoreNet commit `e6d08d1ff1dbca21d8a6e6f055f5ea1cce3997ea` with TShark 4.7.1 (v4.7.1-0-g667ab240e6de); every capture SHA-256 was verified before execution and no Skill was modified while the run was in progress.

| Case ID | Scenario Type | Human Baseline Status | Evidence Chain Health | Skill Status | Differential Status | Attribution |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `public-5gc-baseline-lifecycle` | Baseline Lifecycle | Healthy (no abnormal boundary) | Protocol healthy (NGAP/PFCP/GTP-U identified); Domain rejected input | No boundary | `DOMAIN_MODEL_GAP` | `DOMAIN` |
| `public-5gc-baseline-user-plane` | Baseline User Plane | Healthy (no abnormal boundary) | Full chain executed: 2 Domain instances, 1 diagnostic group, 2 candidates | Ambiguous first boundary | `FALSE_POSITIVE` | `DOMAIN` |
| `public-5gc-registration-resync` | Baseline Resynchronization | Healthy (recovered synch) | Protocol healthy; Domain rejected input | No boundary | `DOMAIN_MODEL_GAP` | `DOMAIN` |
| `public-5gc-auth-recovery` | Auth Recovery | Healthy (no abnormal boundary) | Protocol healthy; Domain rejected input | No boundary | `DOMAIN_MODEL_GAP` | `DOMAIN` |
| `public-5gc-access-plmn-recovery` | PLMN Recovery | Healthy (no abnormal boundary) | Protocol healthy; only NGSetup present, family unowned | No boundary | `DOMAIN_MODEL_GAP` | `DOMAIN` |
| `public-5gc-access-tai-recovery` | TAC Recovery | Healthy (no abnormal boundary) | Protocol healthy; only NGSetup present, family unowned | No boundary | `DOMAIN_MODEL_GAP` | `DOMAIN` |
| `public-5gc-dnn-recovery` | DNN Recovery | Healthy (no abnormal boundary) | Protocol healthy (NGAP/PFCP identified); Domain rejected input | No boundary | `DOMAIN_MODEL_GAP` | `DOMAIN` |
| `public-5gc-external-path-recovery` | N6 Path Recovery | Healthy (no abnormal boundary) | GTP-U extracted (G-PDU 255); observed family unowned | No Domain inputs | `DOMAIN_MODEL_GAP` | `DOMAIN` |
| `public-5gc-external-path-negative` | Missing N6 NAT | Out of Scope (N6 data plane) | GTP-U extracted (G-PDU 255); no N1/N2 signaling | No Domain inputs | `OUT_OF_SCOPE` | `OUT_OF_SCOPE` |
| `public-5gc-auth-negative` | Auth Key Mismatch | Abnormal Boundary (NAS MAC failure) | Protocol healthy; Domain rejected input before reconstruction | No boundary | `DOMAIN_MODEL_GAP` | `DOMAIN` |
| `public-5gc-access-plmn-negative` | PLMN Mismatch | Abnormal Boundary (NGSetupFailure) | Protocol healthy; NGSetup is unowned node-level management | No boundary | `DOMAIN_MODEL_GAP` | `DOMAIN` |
| `public-5gc-access-tai-negative` | TAC Mismatch | Abnormal Boundary (NGSetupFailure) | Protocol healthy; NGSetup is unowned node-level management | No boundary | `DOMAIN_MODEL_GAP` | `DOMAIN` |
| `public-5gc-dnn-negative` | Unsupported DNN | Abnormal Boundary (protected downlink NAS transport, baseline revision 2) | Protocol healthy; Domain rejected input | No boundary | `DOMAIN_MODEL_GAP` | `DOMAIN` |

### Benchmark Metrics Summary
- **Total Cases Evaluated**: 13
- **Executed Case Count**: 13
- **In-Scope Cases Evaluated**: 12 (denominator excludes 1 out-of-scope case)
- **Comparison Eligibility**: 7 `ELIGIBLE`, 6 `INELIGIBLE` (Domain reconstruction failed after healthy Protocol extraction)
- **Exact Match Count**: 0
- **Exact Match Rate**: 0.0% (0 / 12)
- **Healthy / Recovery Exact Match Rate**: 0.0% (0 / 8)
- **False Positive Count**: 1 (`public-5gc-baseline-user-plane`: Domain deviations on a capture the independent baseline records as healthy, Orchestration could not resolve a single first boundary)
- **False Negative Count**: 0
- **Protocol Coverage Gaps**: 0 (previously 13; every relevant Protocol Skill now exposes usable message identity for the cases it supports)
- **Domain Model Gaps**: 11 (6 from the Domain input contract rejecting NGAP records without a message identity, 5 from procedure families no implemented Domain owns: 4 node-level `ngap-management` and 1 `5gc-user-plane`)
- **Out of Scope Count**: 1
- **Orchestration Gaps**: 0
- **Needs Adjudication Count**: 7
- **Blocked Cases**: 0
- **Acceptable Difference Count**: 0

The single case that exercises the complete chain (`public-5gc-baseline-user-plane`, the only capture in this corpus without an NGSetup preamble) proves Protocol, Correlation, Domain and Orchestration all execute on real captures: NGAP, PFCP and GTP-U identity resolve, 2 Domain instances are reconstructed, and Orchestration forms 1 diagnostic group with 2 candidates. Its `FALSE_POSITIVE` result is an adjudication item about Domain deviation semantics on encrypted-NAS captures, not an extraction failure.

---

## 5. Technical Findings and Dissector Observations

During empirical benchmark execution with TShark 4.7.1, several protocol extraction differences were uncovered:
1. **NGAP Column Casing**: TShark 4.7.1 outputs `_ws.col.info` (lowercase), whereas legacy dissector parsing strictly checked for `_ws.col.Info` (uppercase), causing extraction exit code 4.
2. **NAS-5GS Field Delimiters**: TShark 4.7.1 uses underscore delimiters for 5GMM message types (`nas_5gs.mm.message_type`), causing extractors configured for dashed keys (`nas-5gs.mm.message_type`) to parse message types as `None`.
3. **PFCP and GTP-U JSON Field Formatting**: TShark 4.7.1 JSON formatting variations led to extraction exit code 4.

The authorized correction pass that followed reproduced every case against the frozen corpus and adjudicated three further findings:

4. **Benchmark identity probe read one shared JSON path**: the pipeline checked a top-level `message_type` for every protocol, while the accepted PFCP and GTP-U Skills expose identity inside their bounded `header` object (`header.message_type`, `header.message_type_code`). Healthy extraction of `PFCP Session Establishment Request` (50) and `G-PDU` (255) was therefore reported as `MISSING_MESSAGE_TYPE`. The probe is now contract-aware per protocol (see 3.3).
5. **NGAP composite Info column**: TShark renders `_ws.col.info` as a composite string when a frame also carries SCTP acknowledgement text, a nested NAS message name, or coalesced NGAP PDUs (for example `SACK (Ack=1, Arwnd=106496) , DownlinkNASTransport, Authentication request`). Exact whole-string matching against the reviewed branch vocabulary left `message_type` null for procedures the bounded NGAP Skill does own. `ngap` 0.3.2 matches the reviewed vocabulary against the whole string first and then against its comma- and bracket-delimited segments; only exact segment equality resolves, so no message name outside the reviewed table is produced and `NGSetup` stays `UNSUPPORTED` with a null identity.
6. **Domain input contract rejects mixed-ownership captures**: each 5GC Domain Skill requires a `message_type` string on every NGAP record and therefore exits with a malformed-input error on captures containing NGAP procedures outside bounded NGAP ownership (for example `NGSetup` at the start of every capture in this corpus). Reconstruction stops at input validation, before any procedure instance is formed. This is recorded as the first Domain contract gap with the exact per-Domain `first_stop_reason`; Domain runtime semantics are frozen and were not modified.

The original benchmark task altered no Skills. The correction pass changed only the NGAP Protocol runtime (0.3.2) and the benchmark harness; Correlation, Domain and Orchestration runtimes are byte-unchanged.

---

## 6. Reproduction and Execution Instructions

### Prerequisites
- Python 3.10+
- Wireshark / TShark installed and on `PATH` (verify with `tshark --version`)
- Cloned capture corpus outside the repository

### Step-by-Step Reproduction
1. Clone the external public capture corpus into a temporary directory:
   ```bash
   git clone https://github.com/abdelrahman-fawaz18/5g-sa-core-protocol-lab /tmp/corenet-golden-source
   git -C /tmp/corenet-golden-source checkout 82934c2cc231540fa425e48177d4bed33210bfc1
   ```

2. Execute the public corpus runner:
   ```bash
   python benchmarks/golden-captures/scripts/run_public_corpus.py \
       --source-root /tmp/corenet-golden-source \
       --work-root /tmp/corenet-golden-run \
       --output-root benchmarks/golden-captures/cases
   ```

3. Validate benchmark artifacts, schemas, and safety gates:
   ```bash
   python scripts/validate-golden-captures.py
   python -m unittest discover -s benchmarks/golden-captures/tests -p 'test_*.py' -v
   ```
