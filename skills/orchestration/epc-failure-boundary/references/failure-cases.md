# Failure cases and evidence-safe language

## Input failures

| Condition | Exit | Behaviour |
| --- | --- | --- |
| No `--attach` and no `--session` | 6 | `at least one of --attach or --session is required`. |
| File missing or unreadable | 5 | Reports the path. |
| Invalid JSON | 5 | Reports the JSON error and the file. |
| Wrong Domain kind (not `epc-procedures`) | 5 | Rejects the artifact instead of guessing. |
| Attach artifact without `procedure_instances` | 5 | Rejects the artifact. |
| Session artifact without `control_plane_subjects` | 5 | Rejects the artifact. |
| `domain_version` below the supported floor | 5 | Names the floor. |
| Domain analyses contain no subject | 5 | Nothing to orchestrate. |
| Output exists without `--force` | 7 | Leaves the existing file untouched. |
| Output directory missing | 7 | Reports the directory. |

A missing optional Domain is not an error: an Attach-only or session-only run is
a normal execution.

## Selection edge cases

| Case | Result |
| --- | --- |
| Source reports more deviations than it publishes | `INSUFFICIENT_COMPARABLE_EVIDENCE`, no selected boundary. |
| Two eligible candidates at the earliest frame with different provenance | `AMBIGUOUS_FIRST_BOUNDARY`, no selected boundary. |
| Ambiguous transaction at or before the earliest eligible candidate | `INSUFFICIENT_COMPARABLE_EVIDENCE`. |
| Deviation type not in the reviewed set | Candidate stays ineligible, `UNKNOWN_DEVIATION_TYPE` limitation. |
| Candidate frame absent from `evidence_refs` | Candidate stays ineligible with a stated reason. |
| Candidate frame outside the observation window | Candidate stays ineligible with a stated reason. |
| Accepted Cause 16 with a rejected bearer item | Bearer-scoped candidate only; the message is not classified as rejected. |
| Protected NAS payload | `PROTECTED_INNER_MESSAGE_UNAVAILABLE` limitation; never a boundary. |
| No eligible candidate at all | `NO_ABNORMAL_BOUNDARY_OBSERVED`; not a success statement. |

## Language rules

- "First abnormal evidence boundary observed at frame N" — never "the root cause
  is at frame N".
- "Downstream observations are ordered after the boundary" — never "caused by
  the boundary".
- "No supported abnormal boundary was observed in this subject" — never "the
  procedure succeeded".
- The output sanitizer refuses any produced document containing causal wording
  such as "root cause is", "root-cause chain", "caused by the boundary" or
  "network function is responsible".

## Execution failure

When orchestration fails inside the unified workflow, the EPC domain keeps its
usable Domain evidence, reports a degraded status with `ORCHESTRATION_FAILED`,
leaves every per-subject boundary null and never converts the exception into
`NO_ABNORMAL_BOUNDARY_OBSERVED`.
