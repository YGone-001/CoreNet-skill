# EPC Failure Boundary

## Purpose

Answer one narrow question per diagnostic subject: WHAT is the earliest abnormal
observation that the accepted EPC Domain evidence supports, at which frame, in
which protocol message, and with what evidence?

This is an Analysis Orchestration Skill. It consumes already-produced Domain
analyses and never reads a capture, never runs TShark and never decodes a
protocol.

## Scope

- Form one diagnostic group per accepted subject: one EPS Attach procedure
  instance, or one EPC session-control subject.
- Build machine-readable boundary candidates only from explicit negative Domain
  deviations that already carry an exact frame anchor.
- Classify every other deviation as non-selectable evidence quality.
- Order candidates by exact frame provenance and select the earliest eligible
  candidate inside one subject.
- Report `SELECTED`, `NO_ABNORMAL_BOUNDARY_OBSERVED`,
  `AMBIGUOUS_FIRST_BOUNDARY` or `INSUFFICIENT_COMPARABLE_EVIDENCE` per subject.
- Report downstream observations as `OBSERVED_AFTER_BOUNDARY` without attributing
  them to the boundary.
- Refuse to claim an earliest boundary when the source candidate list is
  truncated.

## Non-Goals

- No root cause, no network-function blame, no severity ranking.
- No merge of independent Attach, S11 and S5/S8 subjects into one EPC failure.
- No Attach-to-session or S11-to-S5/S8 identity bridge; the accepted Domains
  publish those associations as `NOT_ESTABLISHED`.
- No PDN, bearer, user-plane or service verdict.
- No Diameter, IMS or 5GC semantics.

## Inputs

| Input | Description |
| --- | --- |
| `--attach` | `epc-procedures` EPS Attach analysis JSON; repeatable. |
| `--session` | `epc-procedures` EPC session-control analysis JSON; repeatable. |

At least one input is required. A missing optional Domain is not an error. A
supplied but unusable artifact fails visibly with exit 5.

## Outputs

| Output | Description |
| --- | --- |
| `--output` | Analysis JSON (`schemas/epc-failure-boundary-analysis.schema.json`). |
| `--report` | Text investigation report rendered from the same analysis. |

Each diagnostic group publishes its subject type, source instances, subject
link, candidates with eligibility, the selected boundary with exact protocol and
frame evidence, confidence, downstream observations, limitations and additional
evidence needed.

## Selection rules

| Rule | Behaviour |
| --- | --- |
| Eligible types | The five Attach negative outcomes and the four GTPv2-C negative outcomes. |
| Non-selectable types | Open request, response-only, ambiguous transaction, interface uncertainty, context reuse, unbound bearer binding, protected payload, insufficient terminal evidence. |
| Unknown type | Reported as `UNKNOWN_DEVIATION_TYPE` and never promoted. |
| Anchor validity | The frame must be an integer, present in the source evidence references, inside the observation window, with a protocol and message identity. |
| Ordering | Exact frame number only. Severity, cause magnitude, message labels and list order never order candidates. |
| Ties | Two eligible candidates at the earliest frame with different provenance produce `AMBIGUOUS_FIRST_BOUNDARY`. |
| Truncation | A non-zero omitted-deviation count produces `INSUFFICIENT_COMPARABLE_EVIDENCE`. |
| Ambiguity ahead | An ambiguous transaction at or before the earliest eligible candidate produces `INSUFFICIENT_COMPARABLE_EVIDENCE`. |

## Confidence

`HIGH` requires a complete candidate list, `OBSERVED` evidence, an exact frame
and a `STRONG` or `SUPPORTED` subject link. `MEDIUM` is the same with a weaker
link. `LOW` applies to derived evidence or a weak anchor. Confidence describes
selection quality only; it says nothing about the cause of the observation.

## Evidence safety

A selected boundary is an observed abnormality. It is not a root cause, not a
network-function verdict and not a service verdict. `NO_ABNORMAL_BOUNDARY_OBSERVED`
means no supported abnormal boundary was observed in that subject; it is not a
statement that the procedure, session or service succeeded. Downstream
observations are ordered after the boundary and are never described as caused by
it.

## Failure behavior

| Condition | Exit |
| --- | --- |
| No input supplied | 6 |
| Malformed, wrong-kind or too-old Domain artifact | 5 |
| Output exists without `--force`, or an unwritable path | 7 |
| Success | 0 |

## Standalone usage

```bash
python3 scripts/analyze_epc_failure_boundary.py \
  --attach epc-attach-analysis.json \
  --output epc-boundary-analysis.json

python3 scripts/analyze_epc_failure_boundary.py \
  --session epc-session-analysis.json \
  --output epc-boundary-analysis.json

python3 scripts/analyze_epc_failure_boundary.py \
  --attach epc-attach-analysis.json \
  --session epc-session-analysis.json \
  --output epc-boundary-analysis.json \
  --report epc-boundary-report.txt

python3 scripts/epc_boundary_report.py epc-boundary-analysis.json
```

The package copies and runs outside the repository; it has no dependency beyond
the Python standard library.

## Testing

```bash
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

## Provenance

Original CoreNet Orchestration-layer package. No upstream material imported.
Normative references are the accepted EPC Domain contracts and 3GPP TS 24.301,
TS 36.413 and TS 29.274 for message identity only. Version 0.1.0.
