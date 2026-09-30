# Systematic Debugging

## Purpose

Provide evidence-driven debugging and fault-isolation methodology before proposing changes.

## Scope

Reproduction, last-known-good and first-known-bad boundaries, evidence gathering, hypothesis testing, controlled validation, and distinguishing mitigation from confirmed repair.

## Non-Goals

This Skill does not define protocol truth, embed domain procedures, or claim that a component caused a failure without evidence.

## Inputs

An observed failure, reproducible command or scenario, relevant artifacts, revision/runtime context, and authorized test access.

## Outputs

Observed evidence, derived facts, a failure boundary, inferences, hypotheses, confirmation status, and next checks.

## Dependencies

No CoreNet Skill dependency. Project-specific test tools are optional external inputs.

## Workflow

1. Reproduce or document why reproduction is unavailable.
2. Read `upstream/SKILL.md` and embedded supporting material as relevant.
3. Identify the last known-good and first abnormal or missing event.
4. Form one testable hypothesis at a time and validate it with minimal change.
5. Keep mitigation distinct from a confirmed repair.

## Evidence Rules

Use `OBSERVED`, `DERIVED`, `INFERRED`, `HYPOTHESIS`, and `CONFIRMED` only when supported. A likely explanation is not a confirmed cause.

## Failure Handling

When artifacts are insufficient, say so and request the next smallest useful observation rather than guessing or changing code.

## Validation

Verify `upstream-manifest.json` against `upstream/`; no repository-root content is needed at runtime.

## References

See `UPSTREAM.md` and `upstream/`.
