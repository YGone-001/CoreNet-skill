# Testing Policy

The repository foundation uses Python standard library validation only. The repository validator checks layout, required documentation, JSON syntax, placeholder Skill shape, naming, and accidental generated files. The tests parse schemas and fixture examples, verify the template layout, and invoke the validator.

The repository intentionally does **not** claim runtime JSON Schema validation: a third-party validator is not included. Schema syntax and structural fixture assumptions are checked now; strict validator integration may be added later with a documented development dependency.

Future executable or rule-driven Skills must ship focused fixtures and tests, including normal, malformed, and inconclusive evidence cases. Protocol/domain Skills must prove evidence-level handling and preserve source provenance.

## Golden Capture Differential Benchmark

The repository includes an empirical differential validation framework located in `benchmarks/golden-captures/`. This infrastructure exists outside the Skill architecture layers and evaluates automated Skill pipeline outputs against independent, standards-based packet baselines across public 5GC captures.

The benchmark enforces strict governance and privacy policies:
- **No binary captures in Git**: Binary capture formats (`.pcap`, `.pcapng`, `.cap`) are prohibited from being tracked in the repository.
- **External execution workspace**: Capture processing and raw event extraction execute exclusively in external temporary directories.
- **Hash-frozen independent baselines**: Standards-based human baselines are authored and hashed before running automated pipelines.
- **Evidence-pipeline safety**: comparison eligibility is evaluated across six independent layers (baseline support, capture sufficiency, relevant Protocol extraction, relevant Domain reconstruction, Orchestration availability, semantic boundary comparison), and success at one layer never substitutes for missing evidence at the next. A healthy exact match requires a relevant Domain instance to have been produced and consumed with zero deviations; Protocol success with zero relevant Domain instances is reported as `DOMAIN_MODEL_GAP`, and a missing boundary caused by protocol extraction failure is reported as `PROTOCOL_COVERAGE_GAP`. Neither is an exact match.
- **Per-layer execution evidence**: sanitized summaries carry `domain_status` (per-Domain execution status, output presence, instance and deviation counts, bounded path-free first-stop reason) and a separate `orchestration_status`, so "produced by Domain" and "consumed by Orchestration" are never conflated in one counter.
- **Precise Protocol statuses**: `MISSING_MESSAGE_TYPE` means a record the Protocol Skill itself reports as supported exposed no message identity. Procedures a bounded Skill intentionally does not own yield `SUCCESS_WITH_UNSUPPORTED_SEMANTICS`, and security-protected payloads yield `SUCCESS_WITH_PROTECTED_PAYLOAD`; neither is an extractor failure.
- **Strict discrepancy attribution**: Failures are attributed to the lowest responsible layer (Protocol, Correlation, Domain, Orchestration, Capture, Out of Scope) rather than falsely penalizing higher layers.

The benchmark is validated via:
```bash
python scripts/validate-golden-captures.py
python -m unittest discover -s benchmarks/golden-captures/tests -p 'test_*.py' -v
```
