# Skill Index

Planned and implemented Skills are grouped by layer so each may remain independently downloadable:

- `foundation/` — reusable evidence investigation methods;
- `protocol/` — protocol-local encoding and correlation;
- `correlation/` — provenance-key joins of already-extracted protocol evidence;
- `domain/` — EPC, IMS, and 5GC procedure composition;
- `orchestration/` — confidence-aware analysis orchestration locating the first abnormal evidence boundary.

Implementation is not a CoreNet Skill layer: implementation-specific source analysis is an external activity performed only when users provide implementation evidence, and the repository owns no implementation Skills.

Add a future real Skill under the appropriate layer, using the contract in `../docs/SKILL-SPEC.md`. The legacy `new-skill.sh` helper remains available for generic standalone Skill creation; maintainers must then complete the required manifest, README, and tests when applicable.
