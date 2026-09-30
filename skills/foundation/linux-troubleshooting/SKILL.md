# Linux Troubleshooting

## Purpose

Provide general Linux host and service troubleshooting methodology.

## Scope

Process and service state, logs, resource utilization, file descriptors, sockets, filesystems, CPU, memory, I/O, host networking, and process tracing where appropriate.

## Non-Goals

This Skill does not contain product-specific service knowledge, protocol semantic diagnosis, or telecom network-function configuration ownership.

## Inputs

Authorized host command output, service logs, resource observations, configuration excerpts, and a bounded host question.

## Outputs

Evidence-labeled host findings, reproducible checks, a scoped failure boundary, hypotheses, and next collection steps.

## Dependencies

No CoreNet Skill dependency. Standard Linux tools are optional external tools.

## Workflow

1. Confirm authorization and avoid exposing secrets in collected artifacts.
2. Read `upstream/SKILL.md` for the relevant host workflow.
3. Check one host boundary at a time: process, service, resources, logs, or sockets.
4. Preserve direct evidence and distinguish it from interpretations.
5. Escalate protocol or implementation questions outside this Skill's scope.

## Evidence Rules

Logs and command output are `OBSERVED`; deterministic summaries are `DERIVED`. A service restart or open socket does not confirm application behavior or root cause.

## Failure Handling

If access, logs, or safe reproduction are unavailable, report the gap and state the least invasive next check.

## Validation

Verify `upstream-manifest.json` against local `upstream/` bytes; this package is self-contained.

## References

See `UPSTREAM.md` and `upstream/SKILL.md`.
