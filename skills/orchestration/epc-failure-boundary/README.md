# EPC Failure Boundary Orchestration

Per-subject abnormal-boundary selection over accepted EPC Domain evidence.

## What it does

For every accepted EPC diagnostic subject it answers: which observed
abnormality came first, at which frame, in which protocol message, and how
strong is that selection?

It does not decode packets and does not diagnose a network function.

## Quick start

```bash
# Attach only
python3 scripts/analyze_epc_failure_boundary.py \
  --attach epc-attach-analysis.json \
  --output boundary.json \
  --report boundary.txt

# Session control only
python3 scripts/analyze_epc_failure_boundary.py \
  --session epc-session-analysis.json \
  --output boundary.json

# Both
python3 scripts/analyze_epc_failure_boundary.py \
  --attach epc-attach-analysis.json \
  --session epc-session-analysis.json \
  --output boundary.json --report boundary.txt
```

Re-render a stored analysis without re-running it:

```bash
python3 scripts/epc_boundary_report.py boundary.json
```

## Reading the result

| Status | Meaning |
| --- | --- |
| `SELECTED` | One eligible abnormal observation is the earliest supported candidate in this subject. |
| `NO_ABNORMAL_BOUNDARY_OBSERVED` | No selectable abnormal deviation was observed. Not a success statement. |
| `AMBIGUOUS_FIRST_BOUNDARY` | Two eligible candidates share the earliest frame and differ in provenance. |
| `INSUFFICIENT_COMPARABLE_EVIDENCE` | The candidate list is truncated, or an ambiguous transaction could conceal an earlier negative result. |

Each group also reports `boundary_confidence` (`HIGH`/`MEDIUM`/`LOW`), the
candidate list with per-candidate eligibility, and `downstream_observations`
labelled `OBSERVED_AFTER_BOUNDARY`.

## What it never claims

- That the selected boundary is the root cause.
- That a downstream observation was caused by the boundary.
- That an Attach subject and a GTPv2-C subject are the same UE or session.
- That an S11 subject and an S5/S8 subject are the same session.
- That an absence of a boundary means the procedure, bearer or service worked.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Analysis written |
| 5 | Malformed, wrong-kind or too-old Domain artifact |
| 6 | No input supplied |
| 7 | Output problem |

## Tests

```bash
python3 -m unittest discover -s tests -p 'test_*.py' -v
```
