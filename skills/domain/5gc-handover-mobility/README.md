# 5gc-handover-mobility

`5gc-handover-mobility` is the bounded Domain-layer Skill for 5GC N2
handover and Path Switch procedure analysis, version 0.1.0. It consumes
already-extracted NGAP (>=0.3.0), PFCP, GTP-U, and SBI-HTTP2 detailed
events — plus an optional `5gc-pdu-session` (>=0.4.0) analysis summary for
lifecycle context — and forms two separate attempt families:
`handover_attempts[]` and `path_switch_attempts[]`. A Path Switch attempt
stays independent unless a safe, documented relationship to a handover
attempt exists; neither family is mandatory for the other.

The Skill associates source and target NG-RAN contexts only through the
same capture, a scoped AMF-UE-NGAP-ID context, compatible reviewed message
roles, and temporal sanity — never through timestamp proximity, RAN-UE-ID
equality, or identifier matches alone. It evaluates branch-aware
conditional stages, preserves item-scoped PDU Session resource outcomes,
binds N11/N4/N3 supporting evidence only through safe session and tunnel
context, and emits procedure-local deviations with structured
`evidence_refs` for Analysis Orchestration.

Boundaries: it never decodes protocols, never parses NGAP opaque mobility
transfer bytes, never derives N3 tunnel identity from NGAP, never issues
handover/path-switch success or failure verdicts, never claims UPF
relocation or user-plane success, never diagnoses radio layers, and never
produces root-cause, vendor, or implementation findings. Missing evidence
stays missing evidence under the capture boundary.

## Package structure

- `scripts/mobility_model.py`: standalone analysis engine (attempt
  formation, source/target association, branch-aware stages, deviations,
  supporting-plane association).
- `scripts/analyze_handover_mobility.py`: CLI driver producing the analysis
  summary JSON and optional generic procedure-evidence stage records.
- `scripts/mobility_timeline.py`: bounded mobility timeline (text/JSON).
- `schemas/5gc-handover-mobility-analysis.schema.json`: analysis contract
  (no root-cause, culprit, responsible-NF, vendor, radio-fault, handover-
  success, or path-switch-success fields).
- `schemas/procedure-evidence.schema.json`: byte-identical copy of the
  generic procedure-evidence framework schema.
- `references/`: procedure model, handover model, path-switch model,
  source/target association, resource model, supporting planes, deviation
  model, failure cases.
- `examples/inputs/`, `examples/expected/`: deterministic scenario fixtures
  covering handover branches, Path Switch independence, association
  safety, supporting planes, and input robustness. The `malformed-input`
  scenario fails loudly and intentionally produces no expected output.
- `tests/`: package-local test suite.

## Usage

```bash
python scripts/analyze_handover_mobility.py \
  --ngap ngap-events.jsonl \
  --output analysis.json

python scripts/analyze_handover_mobility.py \
  --ngap ngap-events.jsonl --pfcp pfcp-events.jsonl \
  --gtpu gtpu-events.jsonl --sbi sbi-events.jsonl \
  --pdu-session pdu-session-analysis.json \
  --output analysis.json --stage-output stages.jsonl

python scripts/mobility_timeline.py analysis.json --format text
```

## Output and limitations

- `handover_attempts[]` preserve source/target contexts, association
  strength and basis, conditional stages, item-scoped PDU Session resource
  findings, terminal observations (for example HANDOVER_NOTIFY_OBSERVED,
  HANDOVER_CANCEL_ACK_OBSERVED, NO_TERMINAL_MOBILITY_OBSERVATION,
  PARTIAL_CAPTURE), deviations, `earliest_observed_deviation`, and plane
  bindings.
- `path_switch_attempts[]` preserve the serving context, the optional
  `related_handover_attempt_id` with `relationship_basis` and
  `relationship_strength`, stages, resources, and deviations.
- `unbound_mobility_evidence[]` preserves events that could not be safely
  associated, including lower-layer UNSUPPORTED/UNKNOWN reports.
- `attempt_id` values are derived display references only; consumers must
  read the structured context fields and never parse the strings.
- Cancellation is a branch, not a failure verdict; HandoverNotify is
  progress evidence, not end-to-end success; PathSwitchRequestAcknowledge
  is a protocol outcome, not user-plane success.

## Standalone validation

Copy this directory anywhere and run:
```bash
python tests/test_5gc_handover_mobility.py
```
No repository-root runtime files or external network access are required.
