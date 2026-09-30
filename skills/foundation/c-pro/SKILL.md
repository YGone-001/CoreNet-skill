# C Pro

## Purpose

Provide general C systems-programming and debugging support.

## Scope

Pointers, memory ownership, structs, macros, callbacks, state-machine implementation patterns, compiler diagnostics, GDB, sanitizers, Valgrind, and POSIX-oriented engineering.

## Non-Goals

This Skill does not map source trees, implement protocol parsers, or own any product-specific implementation behavior.

## Inputs

Relevant C source, compiler or runtime diagnostics, build context, tests, and a bounded engineering question.

## Outputs

Evidence-labeled code observations, ownership or control-flow findings, testable hypotheses, validation steps, and limitations.

## Dependencies

No CoreNet Skill dependency. Compiler, debugger, or sanitizer tooling is optional and external.

## Workflow

1. Preserve the failing input and build context.
2. Read `upstream/SKILL.md` for embedded generic guidance.
3. Establish an observable failure and inspect ownership, bounds, and return values.
4. Test one hypothesis at a time with focused diagnostics.
5. Validate any change with the relevant build or test artifact.

When the task concerns EPC, IMS, 5GC, mobile-core signaling, or a core-network host, also read `extensions/telecom-core-network.md`.

## Evidence Rules

Compiler output, debugger state, and test results are `OBSERVED`; deterministic analysis is `DERIVED`. Do not present a suspected defect as confirmed without validation.

## Failure Handling

If a reproduction, toolchain, or relevant source is unavailable, record the limitation and request the minimum needed artifact.

## Validation

Verify `upstream-manifest.json` against local `upstream/` bytes; no repository-root files are required.

## References

See `UPSTREAM.md` and `upstream/SKILL.md`.
