# procedure-evidence

`procedure-evidence` is a standalone Domain-layer framework package that
defines the common evidence model future telecom procedure Skills
consume. Version 0.1.0 implements only the generic framework: procedure
evidence records, generic stage representation (expected observation
points), observed/missing evidence, evidence confidence, observed versus
derived separation, and an ordered procedure timeline. It implements no
telecom procedure and issues no verdicts.

## Package structure

- `scripts/procedure_model.py`: shared standalone record validation and
  timeline rendering helpers.
- `scripts/procedure_timeline.py`: evidence timeline CLI (text/JSON).
- `schemas/procedure-evidence.schema.json`: stage evidence record
  contract.
- `references/evidence-model.md`: model rules and boundary.
- `examples/stages/`: synthetic generic fixtures (no telecom procedure
  names, no subscriber or session data).
- `examples/expected/`: deterministic expected timelines.
- `tests/`: package-local test entry point.

## Usage

```bash
python scripts/procedure_timeline.py examples/stages/observed-flow.jsonl
python scripts/procedure_timeline.py examples/stages/observed-flow.jsonl --format json
python scripts/procedure_timeline.py stages.jsonl --format text --output timeline.txt
```

Records are validated before rendering (missing fields, wrong basis or
confidence values, and verdict wording fail loudly); existing outputs
are refused unless `--force` is given; identical input yields identical
output.

## Output and limits

Each timeline entry shows the stage, its expected protocols and message
types, expected/observed/missing evidence, the record's evidence basis
(OBSERVED or DERIVED), evidence confidence (HIGH/MEDIUM/LOW), and
limitations. Missing evidence is rendered as missing evidence — never
as failure — and the output contains no SUCCESS, FAILED, or ROOT_CAUSE
wording. Records render in input order; the input owns the ordering.

Domain Skills consume protocol evidence and correlation output; this
framework does not replace protocol decoding or correlation, and it
handles no subscriber or session identity.

## Standalone validation

Copy this directory anywhere and run
`python tests/test_procedure_evidence.py`. No repository-root runtime
files are required.
