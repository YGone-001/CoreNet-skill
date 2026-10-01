# CoreNet Skill

`CoreNet-skill` is a modular, evidence-first repository for future AI-agent Skills that investigate mobile core-network signaling. Its intended technology scope includes EPC, IMS, 5GC, NGAP, NAS, S1AP, GTPv2-C, GTP-U, PFCP, SIP, SDP, RTP, Diameter, SBI/HTTP2, and Core network service function development.

## Current status

**Implemented:** accepted repository foundation, agent governance, audited
upstream snapshots, six CoreNet Foundation Skills, telecom core-network
Foundation extensions, GitHub Actions validation, the `core-network-pcap`
capture normalization layer, the bounded `ngap` Protocol Skill
(UE-context signaling subset over N2), the bounded `nas-5gs` Protocol
Skill (5GMM registration/identity/authentication/security-mode/service/status
subset over N1 with security-envelope classification, privacy defaults, and
5GSM recognition deferred), and the `cross-protocol-evidence` Correlation
Skill (provenance-key joins of extracted protocol events into a unified
observed-evidence timeline; no protocol ownership, no verdicts). The
extensions provide investigation context only.
**Not yet implemented:** 5GSM PDU session semantics, complete 5G Registration
Domain logic, full NGAP coverage (handover, path switch, NG setup, PDU session
resource semantics, later-Release extensions), remaining protocol Skills
(NAS-EPS, S1AP, GTP, PFCP, SIP, Diameter, SBI), EPC/IMS/5GC Domain procedures,
implementation-specific mappings, or end-to-end orchestration.

## Why modular Skills

Each future Skill is designed to be downloaded and used independently. It must document its bounded responsibility, inputs, outputs, dependencies, evidence behavior, test coverage, and upstream provenance. This keeps reusable protocol expertise separate from domain procedures and implementation-specific knowledge.

```text
Foundation → Protocol → Correlation → Domain / Procedure → Implementation → Orchestration
```

| Layer | Purpose |
| --- | --- |
| Foundation | Teach an agent how to investigate: Wireshark use, reverse engineering, systematic debugging, Linux, and C-oriented methods. |
| Protocol | Teach protocol-local encoding and correlation: NAS, NGAP, S1AP, GTP, PFCP, SIP, SDP/RTP, Diameter, and SBI. |
| Correlation | Join already-extracted protocol evidence into deterministic groups and a unified observed-evidence timeline by shared capture provenance. |
| Domain / procedure | Compose protocols into EPC, IMS, and 5GC procedures. |
| Implementation | Map supported procedure/protocol behavior to evidence from Core network service function development. |
| Orchestration | Combine independently valid Skills to establish an evidence-safe end-to-end failure boundary. |

Dependencies only point left, and a Skill may depend on the same layer when ownership remains acyclic and semantically correct. Lower layers never own higher-layer procedures, which prevents circular architecture and preserves reuse. Correlation is optional infrastructure for Domain Skills, not a mandatory wrapper around every Protocol Skill.

## EPC, IMS, 5GC, and Diameter

Future EPC procedures will reuse NAS-EPS, S1AP, GTPv2/GTP-U, and Diameter EPC. IMS procedures will reuse SIP, SDP/RTP, Diameter IMS, and Diameter Charging. 5GC procedures will reuse NAS-5GS, NGAP, PFCP, GTP-U, and SBI/HTTP2.

Diameter is explicitly cross-domain—not an IMS-owned protocol. `diameter-core` will own base-protocol behavior; `diameter-epc`, `diameter-ims`, and `diameter-charging` will own their bounded applications and shared credit-control semantics. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Evidence first

All future troubleshooting output must separate observations, deterministic derivations, inferences, hypotheses, and confirmed results. A visible network action is not proof of a cause. The formal evidence levels and safe-language rule are in [docs/EVIDENCE-SCHEMA.md](docs/EVIDENCE-SCHEMA.md); normalized events and diagnostic results are schema-defined in `shared/schemas/`.

## Repository structure

```text
├── docs/                 # frozen architecture, contracts, rules, roadmap
├── shared/               # schemas and documented future shared assets
├── skills/               # Foundation wrappers; later-layer Skills remain planned
├── templates/skill-template/  # reusable contract-complete Skill skeleton
├── scripts/              # validation and original generic helper scripts
└── tests/                # schema, structure, and fixture checks
```

The original generic workflow is retained: `scripts/new-skill.sh` creates a simple standalone Skill skeleton and `scripts/link-skills.sh` links Skills into a local discovery directory. A repository-compliant Skill must additionally follow [docs/SKILL-SPEC.md](docs/SKILL-SPEC.md) and use `templates/skill-template/`.

## Validate

```bash
python scripts/validate-repository.py
python -m unittest discover -s tests -p "test_*.py"
```

Python's standard library is sufficient for the repository foundation. The checks parse JSON schemas and fixture documents, but do not claim full runtime JSON Schema validation; [docs/TESTING.md](docs/TESTING.md) explains the deliberate limitation.

## Contribution expectations

Keep Scope and Non-Goals explicit, use lowercase kebab-case names, preserve artifact provenance, attach evidence levels to claims, and add focused fixtures/tests for executable or rule-driven work. Do not add protocol expertise until its planned milestone is authorized. Review [docs/NAMING.md](docs/NAMING.md), [docs/UPSTREAM.md](docs/UPSTREAM.md), and [docs/ROADMAP.md](docs/ROADMAP.md) before proposing a Skill.

## Roadmap

The repository foundation and six accepted Foundation Skills establish the
stable investigation-method baseline; GitHub Actions reproduces repository
validation remotely.
Future milestones are Packet and Protocol Core, Diameter, IMS, EPC, 5GC Core
Procedures, Advanced 5GC Interfaces, Implementation Awareness, and End-to-End
Root Cause Analysis. Each milestone's gates and dependencies are frozen in
[docs/ROADMAP.md](docs/ROADMAP.md).
