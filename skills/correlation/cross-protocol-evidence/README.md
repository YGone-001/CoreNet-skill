# cross-protocol-evidence

`cross-protocol-evidence` is a standalone Correlation-layer package that
joins already-extracted NGAP and NAS-5GS protocol events into
deterministic evidence groups and a unified observed-evidence timeline.
It answers "what protocol observations belong together?" and nothing
more: it parses no capture and no protocol, owns no protocol semantics,
and never determines registration success, failure, or root cause.

## Package structure

- `scripts/correlate_events.py`: shared standalone correlation model
  (loaders, provenance key, strength classification, sensitive-data
  policy).
- `scripts/correlate-events.py`: CLI producing correlation-event JSONL.
- `scripts/evidence-timeline.py`: unified observed-evidence timeline
  (text or JSON) with missing-source visibility.
- `schemas/correlation-event.schema.json`: correlation record contract.
- `schemas/trace-event.schema.json`: byte-identical copy of the shared
  trace-event schema.
- `references/`: correlation model, provenance rules, timeline model,
  failure boundaries.
- `examples/ngap-input/`, `examples/nas-input/`: synthetic protocol
  event fixtures (no payloads, no subscriber data, no secrets).
- `examples/expected/`: deterministic expected correlation outputs.
- `tests/`: package-local test entry point.

## Usage

```bash
python scripts/correlate-events.py --ngap-events ngap.jsonl --nas-events nas.jsonl --output groups.jsonl
python scripts/correlate-events.py --ngap-events ngap.jsonl --output groups.jsonl
python scripts/correlate-events.py --ngap-events a.jsonl --nas-events b.jsonl --output groups.jsonl --window-seconds 1.0
python scripts/evidence-timeline.py groups.jsonl --format text
python scripts/evidence-timeline.py groups.jsonl --format json --output timeline.json
```

Inputs are validated (provenance fields required; sensitive identity or
authentication-secret fields rejected); existing outputs are refused
unless `--force` is given; identical input yields identical bytes.

## Output and limits

Groups carry the provenance key, group frame numbers, the protocol
sources present, the embedded events verbatim as foreign evidence,
STRONG/MEDIUM/WEAK strength, and DERIVED evidence with its basis.
NGAP UE-context identifiers inside embedded events are preserved
without interpretation. MEDIUM joins chain events whose adjacent
timestamps differ by at most the bounded window (default 1.0 second,
configurable); WEAK events stay single and unmerged. Groups with only
one protocol source are reported with missing evidence notes — that is
missing evidence under the capture boundary, not failure.

## Standalone validation

Copy this directory anywhere and run
`python tests/test_cross_protocol_evidence.py`. No repository-root
runtime files are required.
