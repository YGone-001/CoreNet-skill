# Unified Core-Network PCAP Analysis Workflow

`scripts/corenet-analyze.py` is one executable entry point for mobile core-network
signaling analysis. It runs the accepted Protocol, Correlation, Domain and
Orchestration Skills for a capture and writes a domain-neutral JSON report and a
readable text report.

The workflow is an application-level execution entry point. It is not a Skill layer,
it owns no telecom protocol or procedure semantics, and it does not score the Golden
Capture benchmark. Today it executes real 5GC analysis. EPC and IMS are declared
capabilities that report `UNSUPPORTED` until their Protocol and Domain Skills exist.

## 1. Prerequisites

| Requirement | Detail |
| --- | --- |
| Python | 3.12 or newer, standard library only. The workflow has no third-party dependency. |
| TShark | Required for capture reading. Any TShark release that decodes NGAP, NAS-5GS, PFCP, GTP-U and HTTP/2 works; the Golden Capture benchmark separately pins TShark 4.7.1 for its frozen corpus. |
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

The file must start with a recognised capture container signature. A file that is
not a PCAP or PCAPNG container is rejected before any decoding is attempted.

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
| `--work-dir PATH` | Scratch directory for intermediate extraction artifacts. Must be outside the repository. |
| `--output-dir PATH` | Destination for `analysis.json` and `report.txt`. Must not be inside `benchmarks/golden-captures/`. |
| `--force` | Replace existing `analysis.json` and `report.txt`. Without it, existing outputs are never overwritten. |
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
| `analysis.json` | Machine-readable report envelope: capture identity, toolchain, requested domains, observed protocols, per-domain results, overall status, limitations. |
| `report.txt` | Human-readable companion report with the same evidence, in stable evidence-safe language. |

Intermediate artifacts (raw per-protocol events, logs, sanitized pipeline summary)
stay in `--work-dir`. They are scratch data: the directory may be overwritten by a
later run, and it must live outside the repository.

The JSON envelope contains:

```text
report_schema_version
capture                 name, sha256, size, frame count, observed time range
toolchain               analyzer version, repository revision, python and decoder versions
requested_domains
observed_protocols
domain_capabilities     the three declared domains and their availability
domain_results          one record per requested domain
overall_execution_status
limitations
```

Each `domain_results` record carries `domain`, `implementation_status`,
`execution_status`, `detection`, `protocol_evidence`, `procedure_summaries`,
`diagnostic_groups`, `first_abnormal_boundary`, `evidence_limitations` and
`additional_evidence_needed`. A domain that could not be analyzed still appears in
the list; it is never silently dropped.

## 6. Execution statuses and exit codes

Execution statuses describe the workflow, not the network:

| Status | Meaning |
| --- | --- |
| `COMPLETED` | Every requested implemented domain completed its supported processing. |
| `PARTIAL` | At least one requested domain completed and at least one was unsupported or could not complete. |
| `UNSUPPORTED` | No requested domain is executable in this repository. |
| `INSUFFICIENT_EVIDENCE` | Processing ran but no procedure instance was reconstructed from the evidence. |
| `FAILED` | Malformed input, missing decoder, extraction or pipeline failure, unsafe path, refused overwrite, or invalid arguments. |

| Exit code | Condition |
| --- | --- |
| `0` | `COMPLETED` or `PARTIAL`. |
| `2` | `UNSUPPORTED`. |
| `3` | `INSUFFICIENT_EVIDENCE`. |
| `4` | `FAILED`. |

A failed extractor is never reported as a successful empty extraction: when no
Domain produced an instance and an extractor reported an error, the run is `FAILED`
with the failure code `EXTRACTION_FAILED`.

## 7. Reading the report

- `first_abnormal_boundary` is the earliest evidence-supported abnormal boundary the
  Orchestration Skill could order. `null` means none was established; it never means
  the network is healthy.
- `evidence_limitations` and `additional_evidence_needed` are the Skill's own bounded
  statements about missing evidence. Empty lists mean no limitation was recorded,
  not that the analysis is exhaustive.
- `diagnostic_groups` reports Orchestration-level evidence: how many diagnostic
  groups were formed, how many candidate boundaries were emitted, and which Domain
  contributed the consumed instances.
- `protocol_evidence` reports each protocol's extraction status and the number of
  extracted events. Event content is not published.

### Boundary localization is not root-cause diagnosis

The workflow localizes the first abnormal evidence boundary inside a capture. It does
not establish a root cause, does not assign blame to a network function, and does not
state that a procedure or a service succeeded. A successful command exit means the
workflow completed its supported processing.

`NO_ABNORMAL_BOUNDARY_OBSERVED` is a bounded statement about the analyzed scope. It is
not `NETWORK_HEALTHY`, `END_TO_END_SUCCESS` or `SERVICE_PASSED`.

### User-facing analysis versus benchmark scoring

The Golden Capture benchmark in `benchmarks/golden-captures/` compares automated
outputs against frozen independent human baselines and computes match rates. That
scoring is benchmark infrastructure. This workflow does not read or write benchmark
records, does not compute match rates, and does not move benchmark classification
policy into the product path. Running an analysis leaves the frozen benchmark tree
untouched.

## 8. Privacy and file-system safety

- Capture content is never copied into a report; only the base name, SHA-256, size,
  frame count and time range are recorded.
- Absolute workstation and temporary paths are redacted from every published string,
  and long digit runs that resemble subscriber identifiers are masked.
- Subscriber identities, authentication key material and raw protocol dumps are never
  published by the workflow.
- The input capture is opened read-only and never modified.
- The work directory must be outside the repository; the output directory must not be
  inside the frozen benchmark tree.
- Existing outputs are never replaced without `--force`.
- The workflow performs no network access and no Git operation.

## 9. Roadmap for EPC and IMS

EPC and IMS appear in the capability contract with `implementation_status:
UNSUPPORTED`, no entry point and an explicit reason. They are not placeholders: no
empty Skill package, no stub parser and no simulated output exists for them.

Adding a domain means adding its real Protocol and Domain Skills, then registering a
domain adapter that produces the same `domain_results` shape. The report envelope,
execution statuses, exit codes, privacy rules and output layout already support
multiple independent domains, so EPC and IMS can be added without changing the 5GC
procedure path or the report contract.
