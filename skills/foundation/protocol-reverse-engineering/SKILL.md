# Protocol Reverse Engineering

## Purpose

Provide a cautious method for understanding unknown, malformed, partially documented, or vendor-specific protocol structures.

## Scope

Field-boundary analysis, TLV-style discovery, differential capture comparison, state inference, dissector-oriented investigation, and uncertainty documentation.

## Non-Goals

This Skill does not provide authoritative telecom protocol knowledge, field dictionaries, or protocol-specific dissector implementations. It does not assume unknown fields are proprietary without evidence.

## Inputs

Authorized samples, captures or logs, known-good comparisons where available, and an explicit investigation question.

## Outputs

Evidence-labeled structural observations, candidate interpretations, hypotheses, reproducible comparison steps, and unresolved questions.

## Dependencies

No CoreNet Skill dependency. Capture tooling or a dissector may be optional external tools.

## Workflow

1. Preserve samples and establish provenance.
2. Read `upstream/SKILL.md` and the embedded implementation playbook as relevant.
3. Compare stable samples before proposing structure or state behavior.
4. Record field boundaries and candidate meanings separately from observations.
5. Stop at the evidence boundary and request additional samples when needed.

## Evidence Rules

Observed bytes and artifacts are `OBSERVED`; deterministic offsets or comparisons are `DERIVED`. Candidate meanings remain `INFERRED` or `HYPOTHESIS` until independently confirmed.

## Failure Handling

If samples are incomplete, encrypted, or insufficiently varied, report the limitation and specify the comparison artifacts required.

## Validation

Verify `upstream-manifest.json` against local `upstream/` bytes; no repository-root path is required.

## References

See `UPSTREAM.md`, `upstream/SKILL.md`, and `upstream/resources/`.
