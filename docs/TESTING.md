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
- **Strict discrepancy attribution**: Failures are attributed to the lowest responsible layer (Protocol, Correlation, Domain, Orchestration, Capture, Out of Scope) rather than falsely penalizing higher layers.

The benchmark is validated via:
```bash
python scripts/validate-golden-captures.py
python -m unittest discover -s benchmarks/golden-captures/tests -p 'test_*.py' -v
```
