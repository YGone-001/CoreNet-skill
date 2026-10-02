# procedure-evidence

## Purpose

Define the common evidence framework future Domain/Procedure Skills
consume: expected observation points, stage representation, observed and
missing evidence, evidence confidence, and a procedure timeline
abstraction. The framework answers "What evidence is required to
determine whether a telecom procedure progressed through expected
stages?" It does not answer "Did the procedure succeed?", "Which network
element caused failure?", or "Which implementation code failed?"

## Scope

- Procedure evidence records: expected evidence, observed evidence,
  missing evidence, and limitations per stage.
- Generic stage model: an expected observation point described by
  stage_id, stage_name, expected_protocols, and expected_message_types.
- Evidence confidence: HIGH/MEDIUM/LOW over evidence coverage only.
- Observed-versus-derived separation: OBSERVED for evidence directly
  provided by lower layers, DERIVED for evidence created from
  correlation output.
- Ordered procedure timeline rendering (text and JSON) that always
  shows observed and missing evidence.

## Non-Goals

- No concrete telecom procedure is implemented: no registration, no
  EPC attach, no IMS registration, no mobility, no voice call logic.
- No NAS or NGAP decoding and no protocol field interpretation;
  protocol references inside records are opaque strings.
- No subscriber identity or session identity handling.
- No success, failure, or root-cause verdicts; verdict wording is
  rejected on input and never emitted. Missing evidence stays missing
  evidence under the observation boundary and is never converted into
  an outcome.
- No implementation-specific source mapping.

## Inputs

- Procedure evidence JSONL: one stage record per line conforming to
  schemas/procedure-evidence.schema.json. Stage records are authored by
  future Domain Skills (or by an analyst) from protocol events and
  correlation output; this framework validates and renders them.

## Outputs

- scripts/procedure_timeline.py <records.jsonl> [--format text|json] —
  ordered stage timeline with observed and missing evidence.

## Dependencies

None required. Optional: cross-protocol-evidence >=0.1.0 as the
correlation layer whose output may back DERIVED evidence records.
Standalone: the package needs nothing outside its own directory.

## Workflow

1. Define the procedure's stages as expected observation points
   (generic stage records; no verdicts).
2. Fill observed_evidence from lower-layer protocol events and
   correlation output; keep evidence_basis truthful (OBSERVED versus
   DERIVED).
3. List every expected item that was not observed as missing_evidence;
   missing evidence is reported, never interpreted as failure.
4. Record confidence over evidence coverage and state limitations.
5. Render the timeline; hand interpretation to Analysis Orchestration.

## Evidence Rules

- OBSERVED: directly provided by lower layers.
- DERIVED: created from correlation output.
- Confidence: HIGH/MEDIUM/LOW evidence coverage; never causal
  confidence.
- Missing evidence is never converted into failure. Allowed: "The
  confirmation-stage evidence was not observed." Forbidden: any
  success/failed/root-cause wording — the framework rejects it.

## Failure Handling

Malformed records (missing fields, wrong basis or confidence values,
verdict wording, non-object lines) fail loudly with non-zero exits
(malformed input 5, no records 6, output failure 7). Empty inputs are
reported, not guessed around.

## Validation

Run python tests/test_procedure_evidence.py from this package.
Repository checkouts also run scripts/validate-procedure-evidence.py.

## References

references/evidence-model.md.
