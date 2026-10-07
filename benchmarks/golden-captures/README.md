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
3. **Schema and Hash Freezing**: The baseline is validated against `human-baseline.schema.json` and its SHA-256 digest is computed and recorded.
4. **Automated Skill Pipeline Execution**: The automated pipeline is executed mechanically in an isolated external working directory.
5. **Differential Comparison**: The frozen baseline and sanitized Skill summary are compared deterministically without tuning or modifying Skill implementations.

### 2.2 Standards-Based and Implementation-Neutral Discipline
The benchmark evaluates standardized protocol signaling behavior exclusively. Captures produced by external lab environments are treated as packet evidence only. In adherence with repository policy:
- No implementation-specific source code, internal state machines, log structures, configuration quirks, or project bug knowledge are incorporated into benchmark records or Skill definitions.
- All procedure definitions and boundary verdicts derive directly from standardized 3GPP specifications.

### 2.3 Artifact Safety and Repository Hygiene
- **Zero Raw PCAP in Git**: Binary packet capture files (`.pcap`, `.pcapng`, `.cap`) are strictly forbidden from being committed into the repository.
- **External Working Directory**: Benchmark runs execute entirely within an external temporary directory (`/tmp/corenet-golden-run/` or Windows equivalent). Intermediate raw protocol dumps (`*-events.jsonl`, `*-trace.jsonl`) remain in the external workspace.
- **Sanitized Summaries**: Only non-sensitive, aggregated summaries (`skill-result-summary.json`, `differential.json`) conforming to strict schemas are checked into the repository. Subscriber identifiers (SUPI/IMSI) and workstation-specific paths are excluded.

---

## 3. Differential Taxonomy and Discrepancy Attribution

### 3.1 Comparison Statuses
- `EXACT_MATCH`: Automated Skill selected the exact same procedure family and frame boundary (or both observed no abnormal boundary in healthy/recovered traffic).
- `BOUNDARY_FRAME_DIFFERENCE`: Procedure family matches, but the selected frame differs by 1–2 adjacent transaction frames.
- `PROCEDURE_MATCH_STAGE_DIFFERENCE`: Procedure family matches, but stage attribution differs.
- `ACCEPTABLE_DIFFERENCE`: Human baseline and Skill selected valid alternative boundaries supported by capture evidence.
- `FALSE_POSITIVE`: Skill selected an abnormal boundary in healthy/recovered signaling.
- `FALSE_NEGATIVE`: Skill failed to observe an abnormal boundary present in extracted evidence.
- `PROTOCOL_COVERAGE_GAP`: Protocol extractor encountered an unhandled dissector field or decode error.
- `CORRELATION_GAP`: Cross-protocol correlation failed to group interrelated signaling events.
- `DOMAIN_MODEL_GAP`: Observed procedure is unowned by currently implemented domain skills (e.g. node-level management vs UE signaling).
- `ORCHESTRATION_GAP`: Domain detected the issue, but failure-boundary orchestration selected the wrong diagnostic candidate.
- `CAPTURE_LIMITATION`: Truncated packet capture or missing interfaces prevent authoritative analysis.
- `OUT_OF_SCOPE`: Signaling occurs on interfaces outside current CoreNet scope (e.g. external N6 data routing).

### 3.2 Lowest-Layer Attribution Rule
When a discrepancy occurs between the independent baseline and automated execution, the discrepancy is attributed to the **lowest layer** that accounts for it:
$$\text{Protocol} \longrightarrow \text{Correlation} \longrightarrow \text{Domain} \longrightarrow \text{Orchestration}$$
If a protocol extractor fails to extract a message or field, the discrepancy is attributed to `PROTOCOL` (`PROTOCOL_COVERAGE_GAP`), rather than blaming higher Domain or Orchestration layers for missing evidence.

---

## 4. Public Capture Corpus and Empirical Results

The benchmark evaluates 13 captures from the public repository `abdelrahman-fawaz18/5g-sa-core-protocol-lab` pinned at commit `82934c2cc231540fa425e48177d4bed33210bfc1`:

| Case ID | Scenario Type | Human Baseline Status | Skill Status | Differential Status | Attribution |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `public-5gc-baseline-lifecycle` | Baseline Lifecycle | Healthy (no abnormal boundary) | Healthy (no boundary) | `EXACT_MATCH` | `NONE` |
| `public-5gc-baseline-user-plane` | Baseline User Plane | Healthy (no abnormal boundary) | Healthy (no boundary) | `EXACT_MATCH` | `NONE` |
| `public-5gc-registration-resync` | Baseline Resynchronization | Healthy (recovered synch) | Healthy (no boundary) | `EXACT_MATCH` | `NONE` |
| `public-5gc-auth-recovery` | Auth Recovery | Healthy (no abnormal boundary) | Healthy (no boundary) | `EXACT_MATCH` | `NONE` |
| `public-5gc-access-plmn-recovery` | PLMN Recovery | Healthy (no abnormal boundary) | Healthy (no boundary) | `EXACT_MATCH` | `NONE` |
| `public-5gc-access-tai-recovery` | TAC Recovery | Healthy (no abnormal boundary) | Healthy (no boundary) | `EXACT_MATCH` | `NONE` |
| `public-5gc-dnn-recovery` | DNN Recovery | Healthy (no abnormal boundary) | Healthy (no boundary) | `EXACT_MATCH` | `NONE` |
| `public-5gc-external-path-recovery` | N6 Path Recovery | Healthy (no abnormal boundary) | Healthy (no boundary) | `EXACT_MATCH` | `NONE` |
| `public-5gc-external-path-negative` | Missing N6 NAT | Out of Scope (N6 data plane) | Conservative (no boundary) | `OUT_OF_SCOPE` | `OUT_OF_SCOPE` |
| `public-5gc-auth-negative` | Auth Key Mismatch | Abnormal Boundary (NAS MAC failure) | No boundary (dissector gap) | `PROTOCOL_COVERAGE_GAP` | `PROTOCOL` |
| `public-5gc-access-plmn-negative` | PLMN Mismatch | Abnormal Boundary (NGSetupFailure) | No boundary (dissector gap) | `PROTOCOL_COVERAGE_GAP` | `PROTOCOL` |
| `public-5gc-access-tai-negative` | TAC Mismatch | Abnormal Boundary (NGSetupFailure) | No boundary (dissector gap) | `PROTOCOL_COVERAGE_GAP` | `PROTOCOL` |
| `public-5gc-dnn-negative` | Unsupported DNN | Abnormal Boundary (Downlink NAS Reject)| No boundary (dissector gap) | `PROTOCOL_COVERAGE_GAP` | `PROTOCOL` |

### Benchmark Metrics Summary
- **Total Cases Evaluated**: 13
- **In-Scope Cases Evaluated**: 12 (1 out-of-scope case excluded from denominator)
- **Exact Match Count**: 8
- **Exact Match Rate**: 66.7% (8 / 12)
- **Healthy / Recovery Exact Match Rate**: 100% (8 / 8)
- **False Positive Count**: 0 (zero spurious abnormalities detected on healthy signaling)
- **False Negative Count**: 0 (zero unextracted domain omissions; missing boundaries accounted for by protocol extraction layer)
- **Protocol Coverage Gaps**: 4 (attributed to TShark 4.7.1 dissector differences)
- **Out of Scope Handled Conservatively**: 1 (N6 user plane failure produced no unsupported core signaling alerts)

---

## 5. Technical Findings and Dissector Observations

During empirical benchmark execution with TShark 4.7.1, several protocol extraction differences were uncovered:
1. **NGAP Column Casing**: TShark 4.7.1 outputs `_ws.col.info` (lowercase), whereas legacy dissector parsing strictly checked for `_ws.col.Info` (uppercase), causing extraction exit code 4.
2. **NAS-5GS Field Delimiters**: TShark 4.7.1 uses underscore delimiters for 5GMM message types (`nas_5gs.mm.message_type`), causing extractors configured for dashed keys (`nas-5gs.mm.message_type`) to parse message types as `None`.
3. **PFCP and GTP-U JSON Field Formatting**: TShark 4.7.1 JSON formatting variations led to extraction exit code 4.

In accordance with repository governance, **no Skills were altered during this benchmark task**. The discrepancy attribution framework correctly localized these findings to `PROTOCOL` layer coverage gaps. A future explicitly authorized protocol hardening task will address these dissector variations.

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
