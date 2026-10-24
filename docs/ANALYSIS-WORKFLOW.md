# Unified Core-Network PCAP Analysis Workflow

`scripts/corenet-analyze.py` is one executable entry point for mobile core-network
signaling analysis. It runs the accepted Protocol, Correlation, Domain and
Orchestration Skills for a capture and writes a domain-neutral JSON report and a
readable text report.

The workflow is an application-level execution entry point. It is not a Skill layer,
it owns no telecom protocol or procedure semantics, and it does not score the Golden
Capture benchmark. It executes real 5GC analysis and bounded EPC EPS Attach
procedure evidence analysis. IMS is a declared capability that reports `UNSUPPORTED`
until its Protocol and Domain Skills exist.

## 1. Prerequisites

| Requirement | Detail |
| --- | --- |
| Python | 3.12 or newer, standard library only. The workflow has no third-party dependency. |
| TShark | Required for capture reading. Any TShark release that decodes NGAP, NAS-5GS, PFCP, GTP-U and HTTP/2 works. The Golden Capture benchmark separately pins TShark 4.7.1 for its frozen corpus. |
| Repository checkout | The workflow executes the Skills in this checkout, so run it from the repository or pass absolute paths to the script. |

Install TShark on Ubuntu 24.04:

```bash
sudo apt-get update
sudo apt-get install -y tshark
tshark --version
```

`docs/DEVELOPMENT-UBUNTU.md` documents the wider development environment, including
`./scripts/dev.sh doctor`.

## 2. Supported inputs

- Classic PCAP (`*.pcap`, `*.cap`).
- PCAPNG (`*.pcapng`).
- Any link type TShark can decode.

The file must start with a recognised capture container signature. A file that is not
a PCAP or PCAPNG container is rejected before any decoding is attempted.

## 3. Commands

Analyze a 5GC capture explicitly:

```bash
python3 scripts/corenet-analyze.py \
  --capture /data/captures/registration.pcap \
  --domains 5gc \
  --work-dir /tmp/corenet-work \
  --output-dir /tmp/corenet-output
```

Let the workflow choose the domain from observed evidence:

```bash
python3 scripts/corenet-analyze.py \
  --capture /data/captures/core-network.pcapng \
  --domains auto \
  --work-dir /tmp/corenet-work \
  --output-dir /tmp/corenet-output
```

Request several domains at once:

```bash
python3 scripts/corenet-analyze.py \
  --capture /data/captures/mixed-core.pcap \
  --domains 5gc,ims \
  --work-dir /tmp/corenet-work \
  --output-dir /tmp/corenet-output
```

| Option | Meaning |
| --- | --- |
| `--capture PATH` | Input capture. Required. |
| `--domains SPEC` | `auto`, `5gc`, `epc`, `ims`, or a comma-separated list. Default `auto`. |
| `--work-dir PATH` | Scratch directory for intermediate extraction artifacts. Must be outside the repository and must not overlap the output directory. |
| `--output-dir PATH` | Destination for `analysis.json` and `report.txt`. Must not be inside `benchmarks/golden-captures/` and must not contain, or be contained by, the work directory. |
| `--force` | Replace an existing `analysis.json` and `report.txt` pair. It never deletes work directories. |
| `--help` | Full usage text, including exit codes. |

## 4. Automatic domain detection

`--domains auto` inspects observed dissector evidence from the capture, never the
file name or a scenario description, and assigns one detection status per domain:

| Status | Meaning |
| --- | --- |
| `CONFIRMED` | Domain-specific access signaling was observed. |
| `SUSPECTED` | Only evidence that is typical for the domain was observed, without proving it. |
| `AMBIGUOUS` | Only protocols shared by several technology domains were observed. |
| `NOT_OBSERVED` | No relevant protocol evidence was observed. |

Detection rules in force:

- NGAP or NAS-5GS confirms 5GC, because both are 5GC access signaling.
- PFCP or SBI/HTTP2 without N1/N2 access signaling only makes 5GC `SUSPECTED`; PFCP
  alone does not prove a capture belongs to 5GC.
- GTP-U alone is `AMBIGUOUS`, because 5GC and EPC share it.
- S1AP, NAS-EPS or GTPv2-C confirms EPC.
- SIP, SDP or RTP only makes IMS `SUSPECTED`; SIP traffic alone does not prove an IMS
  registration or an IMS session.
- Diameter is cross-domain and never confirms EPC or IMS on its own.
- Mixed traffic is never collapsed into one domain: every domain with confirmed
  evidence is reported separately.

`auto` selects only domains that are both `CONFIRMED` and implemented. If nothing is
confirmed, nothing is executed and the run reports `INSUFFICIENT_EVIDENCE` with the
observed ambiguity recorded as a limitation.

An explicit request is always honoured as written: `--domains 5gc` runs the 5GC
analysis even when detection is not confirmed, and the report records the detection
status alongside the execution result.

## 5. Outputs

| File | Content |
| --- | --- |
| `analysis.json` | Machine-readable report envelope: capture identity, toolchain, requested domains, observed protocols, per-domain results, diagnostic subjects, overall status, limitations. |
| `report.txt` | Human-readable companion report with the same evidence, in stable evidence-safe language. |
| `analysis.failure.json` | Written only when a run fails while an earlier `analysis.json` already exists. It records the failed attempt so a stale successful report is never mistaken for the current result. |

Intermediate artifacts stay in `--work-dir`. Every 5GC run creates its own scratch
directory under `<work-dir>/5gc/runs/<run-id>/`, so an interrupted or failed run can
never be read as fresh evidence from an earlier one, and nothing is deleted to
achieve that. The work directory is scratch data and may be removed by the operator
between runs.

The JSON envelope contains:

```text
report_schema_version
capture                 name, sha256, size, frame count, observed time range
toolchain               analyzer version, repository revision, python and decoder versions,
                        executed protocol extractors, executed Domain analyzers, orchestration status
requested_domains
observed_protocols
domain_capabilities     the three declared domains, their availability and execution status
domain_results          one record per requested domain
overall_execution_status
limitations
interpretation          explicit statements bounding what the report does and does not establish
```

Each `domain_results` record carries `domain`, `implementation_status`,
`execution_status`, `detection`, `protocol_evidence`, `procedure_summaries`,
`diagnostic_groups`, `diagnostic_subjects`, `first_abnormal_boundary`,
`evidence_limitations`, `additional_evidence_needed` and `degradation`. A domain that
could not be analyzed still appears in the list; it is never silently dropped.

## 6. Execution statuses and exit codes

Execution statuses describe the workflow, not the network:

| Status | Meaning |
| --- | --- |
| `COMPLETED` | Every requested implemented domain completed cleanly: all observed-protocol extractors succeeded, every Domain ran or was legitimately skipped, and Orchestration ran. |
| `PARTIAL` | Usable evidence exists, but at least one required component failed or one requested domain is unsupported. The report names every failed component. |
| `UNSUPPORTED` | No requested domain is executable in this repository. |
| `INSUFFICIENT_EVIDENCE` | Processing ran but no procedure instance was reconstructed from the evidence. |
| `FAILED` | No trustworthy usable result: malformed input, missing decoder, required extraction failure without any Domain result, Domain failure without any result, adapter failure, unsafe path, refused overwrite, or invalid arguments. |

| Exit code | Condition |
| --- | --- |
| `0` | `COMPLETED` or `PARTIAL`. |
| `2` | `UNSUPPORTED`. |
| `3` | `INSUFFICIENT_EVIDENCE`. |
| `4` | `FAILED`. |

### Required versus optional components

An extractor failure is judged against what the capture actually contained:

- If the protocol the extractor owns was observed in the capture, its failure is a
  **required** failure: procedure evidence for that protocol is lost.
- If the protocol was never observed, its failure is **optional** and loses nothing.

A required failure can never be hidden behind another Domain's success. When a Domain
still produced usable evidence the run is `PARTIAL` and the lost protocol is named in
`degradation`. When no Domain produced a result, the run is `FAILED` with
`EXTRACTION_FAILED`.

An orchestration failure is never reported as completed boundary localization: the
run becomes `PARTIAL` with `ORCHESTRATION_FAILED`, `first_abnormal_boundary` is null,
and the limitation is stated in the report.

A security-protected payload is not an extractor failure. It bounds interpretation,
and the report says so.

## 7. Diagnostic subjects

One capture may contain several independent diagnostic subjects: several UEs, several
PDU Sessions, or several lifecycle generations of the same numeric PDU Session ID.

The accepted `5gc-failure-boundary` Skill already establishes diagnostic groups and
their subject associations. The workflow does not re-derive them and does not create a
second correlation engine. It publishes every group the Skill established:

```text
diagnostic_group_reference     stable reference from the producing Skill
boundary_selection_status      that subject's own selection status
boundary_confidence            selection confidence, never causal confidence
first_abnormal_boundary        that subject's selected boundary, or null
candidate_boundary_count
source_domain_instances        source Domain plus a pseudonymous instance reference
subject_link                   the association basis the Skill used, and its context count
evidence_limitations
additional_evidence_needed
```

Rules the workflow preserves:

- Every subject keeps its own boundary status. A boundary selected for one subject is
  never presented as the result of another.
- A subject with no supported boundary stays explicitly `NO_ABNORMAL_BOUNDARY_OBSERVED`
  or `INSUFFICIENT_COMPARABLE_EVIDENCE`.
- Ambiguous associations stay ambiguous and never join another subject.
- The top-level `first_abnormal_boundary` field remains for compatibility. It is a
  limited summary view of the primary subject; `diagnostic_subjects` is the
  authoritative collection.

The workflow reads the accepted Orchestration output and projects it through an
explicit allowlist. Raw Orchestration JSON is never republished, and internal instance
identities become pseudonymous `inst-…` / `subj-…` references. At most 64 subjects are
published per domain; any omitted group is counted and reported as a limitation.

## 8. Reading the report

The text report has these sections, each of which states explicitly when it has no
supported data:

```text
Capture and Toolchain
Observed Protocols
Domain Detection and Execution
Protocol Extraction Coverage
Procedure Instances
Diagnostic Subjects
First Abnormal Boundary per Subject
Evidence Limitations
Additional Evidence Needed
Execution Failures
Interpretation Boundaries
```

For each selected boundary the report shows the exact frame number, protocol, message
identity, procedure family, procedure stage, deviation type, evidence level, selection
confidence, capture file, candidate reference, observation window and the accepted
evidence references, so every claim stays traceable to a frame.

### Boundary localization is not root-cause diagnosis

The workflow localizes the first abnormal evidence boundary per subject. It does not
establish a root cause, does not assign blame to a network function, does not rank
events by severity, and does not state that a procedure or a service succeeded. A
successful command exit means the workflow completed its supported processing.

`NO_ABNORMAL_BOUNDARY_OBSERVED` is a bounded statement about the analyzed scope. It is
not `NETWORK_HEALTHY`, `END_TO_END_SUCCESS` or `SERVICE_PASSED`.

### User-facing analysis versus benchmark scoring

The Golden Capture benchmark in `benchmarks/golden-captures/` compares automated
outputs against frozen independent human baselines and computes match rates. That
scoring is benchmark infrastructure. This workflow does not read or write benchmark
records, does not compute match rates, and does not move benchmark classification
policy into the product path. Running an analysis leaves the frozen benchmark tree
untouched.

## 9. Privacy and file-system safety

Public reports are built from explicit allowlists, not by dumping internal records:

- Capture identity is limited to base name, SHA-256, size, frame count and time range.
- Diagnostic subjects publish a stable reference, the source Domain, a pseudonymous
  instance reference and the association basis — never raw UE, session or subscriber
  identifiers.
- Subscriber identities, authentication material, raw NAS or GTP-U payloads and
  credential values are never published.
- Free-text statements coming from the accepted components are scrubbed of absolute
  paths and long identifier-like digit runs. Structured evidence fields such as frame
  numbers and protocol identities are preserved exactly.

File-system rules:

- The input capture is opened read-only and never modified.
- The work directory must be outside the repository.
- The output directory must not be inside `benchmarks/golden-captures/`.
- Work and output directories must not be equal or contain one another, so final
  reports never sit among raw intermediate artifacts.
- Paths are resolved before comparison, so a symlink cannot reach a protected tree.
- Existing reports are never replaced without `--force`, and `--force` replaces only
  the report pair.
- Both reports are staged before publication. Publication is sequential with rollback:
  if the text report cannot be published, the previous JSON report is restored. This
  is a deterministic recovery contract, not transactional atomicity against process
  death — after an interrupted publication, re-run the command.
- A failed run never leaves a stale successful report unmarked: when an earlier
  `analysis.json` exists it is preserved and the failure is recorded in
  `analysis.failure.json`.

## 10. EPC protocol extraction versus EPC procedure diagnosis

Three capabilities must not be conflated:

| Capability | Status |
| --- | --- |
| EPC protocol extraction (S1AP, EPS NAS) | Implemented as standalone Protocol Skills |
| EPC procedure diagnosis | Implemented for bounded EPS Attach evidence only |
| Unified EPC execution through this workflow | Implemented for the bounded Attach path |

The two EPC Protocol Skills remain independently executable:

```bash
python3 skills/protocol/s1ap/scripts/extract-s1ap.py capture.pcap --output s1ap-events.jsonl
python3 skills/protocol/s1ap/scripts/s1ap_timeline.py s1ap-events.jsonl --format text

python3 skills/protocol/nas-eps/scripts/extract-nas-eps.py capture.pcap --output nas-eps-events.jsonl
python3 skills/protocol/nas-eps/scripts/nas_eps_timeline.py nas-eps-events.jsonl --format text
```

`--domains epc` runs the bounded chain — S1AP extraction, NAS-EPS extraction, EPS
Attach analysis — and `--domains auto` selects it when EPC access signaling is
confirmed. The EPC result reports procedure instances, per-stage observations and
procedure-local deviations with exact frames. It never reports a bearer, PDN or
service verdict, and it never selects a global first-abnormal boundary: EPC boundary
selection is reported as `NOT_EVALUATED` until an EPC Analysis Orchestration Skill
exists. GTPv2-C, Diameter EPC, complete ESM semantics and user-plane verification
remain outside the implemented scope.

## 11. Roadmap for EPC and IMS

IMS appears in the capability contract with `implementation_status: UNSUPPORTED`, no
entry point and an explicit reason. It is not a placeholder: no empty Skill package,
no stub parser and no simulated output exists for it. EPC is implemented for the
bounded EPS Attach path described in section 10, and its unimplemented scope is
declared through `not_implemented_capabilities`.

Adding a domain means adding its real Protocol and Domain Skills, then registering a
domain adapter that produces the same `domain_results` shape. The report envelope,
execution statuses, exit codes, privacy rules, subject reporting and output layout
already support multiple independent domains: EPC was added this way without changing
the 5GC procedure path, and IMS can follow the same route.
