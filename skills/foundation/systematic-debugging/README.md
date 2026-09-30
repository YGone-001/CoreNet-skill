# Systematic Debugging

An independently usable Foundation Skill for evidence-driven debugging and failure-boundary identification. It exists to prevent guess-and-change behavior without defining domain-specific truth.

Use it for reproductions, evidence collection, hypothesis tests, and distinguishing mitigation from confirmed repair. Do not use it to assert a component caused a failure without adequate evidence.

The complete standalone package includes the CoreNet wrapper, manifest, provenance records, integrity record, and immutable `upstream/` material. It has no repository-root runtime dependency.

The telecom/core-network Foundation extension is implemented for investigation context only; protocol and domain semantics remain out of scope. Upstream remains unchanged and the package remains standalone.
