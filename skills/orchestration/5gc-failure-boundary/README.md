# 5gc-failure-boundary

`5gc-failure-boundary` is the bounded Analysis Orchestration Skill for
evidence-safe first abnormal boundary localization across currently supported
5GC Domain analyses, version 0.1.0.
It composes already-produced analysis JSON from `5gc-registration-mobility`
(>=0.2.0) and `5gc-pdu-session` (>=0.4.0) into diagnostic groups linked only by
exact common context (capture file, SCTP association, RAN-UE-NGAP-ID,
AMF-UE-NGAP-ID), preserves PDU Session lifecycle generations and multi-UE
isolation, builds boundary candidates only from Domain-emitted deviations,
orders them by evidence provenance (never severity), and selects the earliest
safely orderable abnormal evidence boundary per group with selection outcomes
`SELECTED`, `NO_ABNORMAL_BOUNDARY_OBSERVED`, `AMBIGUOUS_FIRST_BOUNDARY`, and
`INSUFFICIENT_COMPARABLE_EVIDENCE`.
It consumes no raw protocol events, decodes no packets, and never issues
success, failure, root-cause, or blame verdicts.

Normative basis: none of its own. The Skill owns no protocol semantics; all
procedure and protocol interpretation is owned by the source Domain Skills.

## Package Structure

- `scripts/failure_boundary_model.py`: standalone orchestration engine
  (Domain input adapters, diagnostic group formation, candidate extraction,
  evidence-limitation filtering, evidence ordering, boundary selection).
- `scripts/analyze_failure_boundary.py`: CLI driver producing the analysis
  summary JSON and the text investigation report.
- `scripts/failure_boundary_report.py`: report renderer (text) from an
  analysis summary.
- `schemas/5gc-failure-boundary-analysis.schema.json`: analysis summary JSON
  contract (no root-cause, culprit, responsible NF, vendor, or implementation
  fields; no hypotheses array).
- `references/`: boundary model, subject linking, ordering model, confidence
  model, failure cases.
- `examples/inputs/`, `examples/expected/`: 30 deterministic scenarios covering
  selection, no-abnormal, ambiguity, insufficiency, isolation, lifecycle
  generation, limitation handling, and input robustness.
- `tests/`: package-local test suite (`test_5gc_failure_boundary.py`).

## Usage

```bash
python scripts/analyze_failure_boundary.py \
  --registration registration-analysis.json \
  --pdu-session pdu-session-analysis.json \
  --output analysis.json \
  --report report.txt

# Or auto-detect Domain inputs from a directory:
python scripts/analyze_failure_boundary.py \
  --input-dir examples/inputs/registration-complete-pdu-reject \
  --output analysis.json
```

## Output and Limitations

- Boundary candidates come only from Domain-emitted deviations and their
  structured `evidence_refs`; the Skill never invents a deviation, never parses
  description/limitation/observed_evidence prose for identity or ordering, and
  rejects source Domain versions older than 0.2.0 (registration) / 0.4.0
  (PDU Session) loudly instead of guessing.
- `MISSING_EXPECTED_COUNTERPART` stays `DERIVED` and is blocked from selection
  when the source Domain marks the observation window partial.
- First means earliest safely orderable boundary; a later but "more serious"
  negative outcome never wins. Selection is candidate-centric: a candidate
  proven before every competitor is selected even when later competitors are
  mutually incomparable; an observed frame inside a derived absence window
  cannot be ordered against it without the source Domain stage order and stays
  ambiguous otherwise.
- Same-frame or overlapping-window candidates remain
  `AMBIGUOUS_FIRST_BOUNDARY`; candidates without comparable provenance yield
  `INSUFFICIENT_COMPARABLE_EVIDENCE`.
- `NO_ABNORMAL_BOUNDARY_OBSERVED` is never success or health.
- Downstream observations use `OBSERVED_AFTER_BOUNDARY`, never
  `CAUSED_BY_BOUNDARY`.
- Boundary confidence (`HIGH`/`MEDIUM`/`LOW`) is selection confidence, never
  causal confidence.

## Standalone Validation

Copy this directory anywhere and run:
```bash
python -m unittest tests/test_5gc_failure_boundary.py
```
No repository-root runtime files or external network access are required.
