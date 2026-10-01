# Skill Specification

Every future Skill is independently downloadable and must state a bounded responsibility. A Skill cannot silently assume the whole repository is installed; any dependency must be named in its manifest and documented with a usable fallback or failure response.

## Required identity and contract

Each Skill defines: (1) identity, (2) responsibility, (3) scope, (4) non-goals, (5) dependencies, (6) accepted inputs, (7) outputs, (8) evidence requirements, (9) failure behavior, (10) testing requirements, (11) versioning, (12) upstream provenance, and (13) standalone-download expectations.

Use this standard layout:

```text
<skill-name>/
├── SKILL.md
├── README.md
├── manifest.yaml
├── references/{procedure.md,message-map.md,field-reference.md,failure-cases.md}
├── rules/{detection-rules.yaml,correlation-rules.yaml}
├── scripts/
├── filters/
├── examples/{normal/,failure/}
└── tests/
```

`SKILL.md`, `README.md`, and `manifest.yaml` are mandatory. Executable or rule-driven Skills require `tests/`. Telecom protocol and domain Skills require `references/`. Directories not needed by a bounded Skill may be omitted only when its README explains why.

## Categories

Valid manifest categories are `foundation`, `protocol`, `correlation`, `domain`, `implementation`, and `orchestration`, matching the frozen layer order. A Skill's category must equal the layer directory it lives under.

Correlation Skills carry additional contract expectations:

- Inputs must already be semantically extracted evidence; a Correlation Skill does not decode captures or protocol payloads.
- Provenance must be preserved from the producing Skills through every join.
- The correlation basis must be explicit in outputs (for example, shared capture provenance or a documented bounded window).
- Correlation strength (STRONG/MEDIUM/WEAK) classifies evidence grouping, not causal confidence; it must never be presented as proof of cause.
- A Correlation Skill owns no protocol semantics unless separately authorized and owns no Domain verdicts such as procedure success, failure, or root cause.

Correlation Skills use the same package format as every other category; no separate or incompatible Skill structure exists.

## Content rules

`SKILL.md` supplies agent-facing workflow instructions. `README.md` explains human-facing intent, installation, inputs, outputs, and limitations. `manifest.yaml` conforms conceptually to `shared/schemas/skill-manifest.schema.json`. Manifests use semantic versions; a breaking contract change increments the major version. Inputs and outputs must identify formats and optionality, and outputs must distinguish observations, derived facts, inferences, and hypotheses.

Every Skill must preserve evidence provenance, reject unsupported input explicitly, and state what additional capture, log, configuration, or source evidence would resolve an inconclusive result. Upstream-derived material must include `UPSTREAM.md` as defined in [UPSTREAM.md](UPSTREAM.md). Local extensions belong in clearly separated files or directories.
