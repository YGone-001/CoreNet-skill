# Network Engineer

## Purpose

Provide general IP and transport-network investigation methods.

## Scope

IPv4, IPv6, routing, DNS, reachability, TCP, UDP, SCTP transport behavior, MTU, fragmentation, NAT, firewalls, loss, latency, and basic network-path reasoning.

## Non-Goals

This Skill does not diagnose application or telecom procedure semantics, own protocol-specific behavior, or assign ownership of an end-to-end failure.

## Inputs

Topology context, authorized command output, packet observations, configuration excerpts, and a bounded connectivity question.

## Outputs

Evidence-labeled path findings, reproducible checks, derived network facts, hypotheses, and next checks.

## Dependencies

No CoreNet Skill dependency. Standard host networking tools are optional external tools.

## Workflow

1. Establish the expected path and measurement points.
2. Read `upstream/SKILL.md` for general investigation guidance.
3. Test one network layer or boundary at a time with reproducible commands.
4. Correlate direct artifacts before interpreting failures.
5. Report whether the boundary is network/transport-level or needs deeper analysis.

## Evidence Rules

Command output and captures are `OBSERVED`; repeatable calculations are `DERIVED`. Reachability does not confirm higher-layer correctness. Keep causal claims as inference or hypothesis until proven.

## Failure Handling

If path visibility, authorization, or measurements are missing, identify the required capture point, log, or controlled test.

## Validation

Verify `upstream-manifest.json` against `upstream/`; the package remains standalone.

## References

See `UPSTREAM.md` and `upstream/SKILL.md`.
