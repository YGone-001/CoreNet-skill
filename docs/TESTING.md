# Testing Policy

The repository foundation uses Python standard library validation only. The repository validator checks layout, required documentation, JSON syntax, placeholder Skill shape, naming, and accidental generated files. The tests parse schemas and fixture examples, verify the template layout, and invoke the validator.

The repository intentionally does **not** claim runtime JSON Schema validation: a third-party validator is not included. Schema syntax and structural fixture assumptions are checked now; strict validator integration may be added later with a documented development dependency.

Future executable or rule-driven Skills must ship focused fixtures and tests, including normal, malformed, and inconclusive evidence cases. Protocol/domain Skills must prove evidence-level handling and preserve source provenance.
