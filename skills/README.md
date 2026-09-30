# Skill Index

The repository foundation implements no real Skills. Planned Skills are grouped by layer so each may remain independently downloadable:

- `foundation/` — reusable engineering investigation methods;
- `protocol/` — protocol-local encoding and correlation;
- `domain/` — EPC, IMS, and 5GC procedure composition;
- `implementation/` — explicit mappings to concrete implementations;
- `orchestration/` — evidence-safe end-to-end reasoning.

Add a future real Skill under the appropriate layer, using the contract in `../docs/SKILL-SPEC.md`. The legacy `new-skill.sh` helper remains available for generic standalone Skill creation; maintainers must then complete the required manifest, README, and tests when applicable.
