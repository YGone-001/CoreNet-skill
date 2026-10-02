# 5gc-registration-mobility

`5gc-registration-mobility` is the first concrete Domain Skill of the
CoreNet repository: a bounded N1/N2 procedure-level analysis of 5GC
registration and access signaling, version 0.1.0. It consumes
already-extracted NGAP events, NAS-5GS events, and cross-protocol
correlation output, forms evidence-safe procedure instances, evaluates
the conditional TS 23.502 registration stage model, recognizes
protocol-defined rejections and unsuccessful outcomes, reports missing
expected evidence, and exposes the lower-layer fields supporting each
procedure-local deviation. It never decodes protocols, never requires
or exposes subscriber identity, and never issues success, failure, or
root-cause verdicts.

Reviewed basis: 3GPP TS 23.502 Release 19, version 19.9.0 (5G System
procedures), with TS 24.501 Release 19 lineage and TS 38.413 semantics
supplied through the nas-5gs and ngap Skill contracts. The reviewed
lower-layer tool basis is Wireshark/TShark 4.7.1. No incompatible
Release mixing is claimed.

## Package structure

- `scripts/procedure_model.py`: standalone analysis engine (loading,
  instance formation, conditional stage evaluation, deviations, field
  findings).
- `scripts/analyze-registration.py`: analysis CLI producing the summary
  JSON and generic stage JSONL.
- `scripts/registration_timeline.py`: per-instance evidence timeline
  (text/JSON).
- `rules/`: registration-model.json (conditional stage graph),
  service-access-model.json, deviation-rules.json.
- `schemas/5gc-registration-analysis.schema.json`: analysis summary
  contract.
- `schemas/procedure-evidence.schema.json`: byte-identical copy of the
  generic procedure-evidence contract.
- `references/`: procedure model, stage references, field findings,
  limitations.
- `examples/inputs/`, `examples/expected/`: synthetic scenario fixtures
  and deterministic expected outputs (no production data).
- `tests/`: package-local test entry point.

## Usage

```bash
python scripts/analyze-registration.py --ngap ngap.jsonl --nas nas.jsonl --output analysis.json --stage-output stages.jsonl
python scripts/analyze-registration.py --ngap ngap.jsonl --nas nas.jsonl --correlation groups.jsonl --output analysis.json --stage-output stages.jsonl
python scripts/registration_timeline.py analysis.json --format text
```

Inputs are validated (provenance fields required; 5GSM-family records
refused; verdict wording rejected); existing outputs are refused unless
`--force` is given; identical input yields identical output.

## Output and limits

The analysis summary reports, per procedure instance: the derived local
identifier (`5gc-reg:<capture>:<association>:<ran-id>`, explicitly
DERIVED and not a 3GPP identifier), the NGAP UE context, the observation
window (first/last timestamp and frame), the observed stage evidence,
the terminal protocol observation (Registration complete observed,
Registration reject observed, or no terminal observation in the
window), procedure-local deviations, field findings limited to
lower-layer fields, and missing-evidence limitations. Timestamp
proximity never merges instances; unresolvable evidence stays UNBOUND;
capture termination may explain missing counterparts near the window
edge.

## Standalone validation

Copy this directory anywhere and run
`python tests/test_5gc_registration.py`. No repository-root runtime
files are required.
