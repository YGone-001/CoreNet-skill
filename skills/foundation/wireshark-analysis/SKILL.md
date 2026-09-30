# Wireshark Analysis

## Purpose

Provide a reproducible, authorized packet-capture analysis method using Wireshark or tshark-oriented workflows.

## Scope

Capture inspection, filters, packet navigation, stream inspection, extraction strategy, and recognizing when deeper protocol expertise is needed.

## Non-Goals

This Skill does not interpret telecom procedures, state machines, application semantics, or assign root-cause ownership.

## Inputs

Authorized capture artifacts, an investigation question, available capture context, and any applicable privacy constraints.

## Outputs

Evidence-labeled observations, reproducible filters or extraction steps, derived facts, limits, and next evidence to collect.

## Dependencies

No CoreNet Skill dependency. Wireshark or tshark is optional when available.

## Workflow

1. Confirm capture authorization and protect sensitive artifacts.
2. Read `upstream/SKILL.md` and relevant embedded reference material.
3. Preserve original artifacts; use reproducible filters and stable identifiers.
4. Separate observed packets from deterministic derivations and interpretation.
5. State the investigation boundary and request deeper expertise where needed.

When the task concerns EPC, IMS, 5GC, mobile-core signaling, or a core-network host, also read `extensions/telecom-core-network.md`.

## Evidence Rules

Directly visible packet fields are `OBSERVED`; deterministic extraction or correlation is `DERIVED`. Interpretation is not confirmation. Keep uncertainty explicit; do not claim a cause without sufficient validation.

## Failure Handling

If the capture, authorization, decryption material, or context is insufficient, report the gap and identify the next safe capture or artifact required.

## Validation

Verify `upstream-manifest.json` against local `upstream/` bytes. This package has no runtime dependency on the repository root.

## References

See `UPSTREAM.md`, `upstream/SKILL.md`, and `upstream/references/`.
