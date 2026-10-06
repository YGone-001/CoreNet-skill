# CoreNet Skill

`CoreNet-skill` is a modular, evidence-first repository for future AI-agent Skills that investigate mobile core-network signaling. Its intended technology scope includes EPC, IMS, 5GC, NGAP, NAS, S1AP, GTPv2-C, GTP-U, PFCP, SIP, SDP, RTP, Diameter, SBI/HTTP2, and Core network service function development.

## Current status

**Implemented:** accepted repository foundation, agent governance, audited
upstream snapshots, six CoreNet Foundation Skills, telecom core-network
Foundation extensions, GitHub Actions validation, the `core-network-pcap`
capture normalization layer, the bounded `ngap` Protocol Skill
(bounded UE-context signaling, PDU Session Resource
setup/modify/release subset over N2, including resources embedded in
Initial Context Setup, and the bounded N2 handover/path-switch mobility
subset: HandoverRequired/HandoverCommand/HandoverPreparationFailure,
HandoverRequest/HandoverRequestAcknowledge/HandoverFailure, HandoverNotify,
HandoverCancel/HandoverCancelAcknowledge, and
PathSwitchRequest/PathSwitchRequestAcknowledge/PathSwitchRequestFailure
with bounded mobility metadata and item-scoped resource-list roles), the bounded `nas-5gs` Protocol
Skill (bounded 5GMM
registration/identity/authentication/security-mode/service/status and
bounded 5GSM PDU session establishment/modification/release/status
subsets over N1 with security-envelope classification, bounded
session-management normalization, privacy defaults, and 5GSM cause
preservation), the bounded `pfcp` Protocol Skill
(bounded N4 session-control subset: Heartbeat, Association Setup, Session
Establishment/Modification/Deletion, header SEID and CP/UP F-SEID evidence,
bounded PDR/FAR/QER/URR rule groups, PFCP Cause, and endpoint-scoped
transaction correlation), the bounded `gtpu` Protocol Skill
(bounded N3 user-plane observation: G-PDU, Echo, Error Indication, End
Marker and Supported Extension Headers Notification, with TEID evidence
scoped by directed outer endpoints, bounded PDU Session Container / QFI
evidence, bounded inner packet metadata, and observed packet/byte stream
summaries), the bounded `sbi-http2` Protocol Skill
(bounded N11 Nsmf_PDUSession and Namf_Communication N1/N2 delivery observation:
Create SM Context, Update SM Context, Release SM Context, Namf N1N2MessageTransfer,
and N1N2Transfer Failure Notification, with HTTP/2 stream isolation scoped by
connection context, transfer reference tracking, URI path privacy sanitization,
Content-ID multipart binding, subscriber privacy redaction, bounded ProblemDetails,
HTTP/2 transport errors, and deterministic callback correlation), and the `cross-protocol-evidence` Correlation
Skill (provenance-key joins of extracted protocol events into a unified
observed-evidence timeline; no protocol ownership, no verdicts), and the
`procedure-evidence` Domain framework (generic stage and evidence model
with missing-evidence visibility), the bounded `5gc-registration-mobility`
Domain Skill (N1/N2 registration and access procedure-stage evidence, conditional
branches, missing-evidence visibility, and lower-layer field findings; no end-to-end
diagnosis), and the bounded `5gc-pdu-session` Domain Skill (v0.3.0, bounded
5GC PDU Session Establishment, repeated Modification, and Release lifecycle
analysis across N1/N2/N3/N4/N11 composing already-extracted NAS, NGAP, PFCP,
GTP-U, and SBI evidence, with lifecycle generation handling so the same UE
context re-using the same numeric PDU Session ID after an evidence-supported
release boundary forms a distinct lifecycle generation; no root-cause verdicts,
no implementation mapping), and the bounded `5gc-handover-mobility` Domain Skill
(v0.1.0, bounded 5GC N2 handover and Path Switch procedure analysis from
already-extracted NGAP/PFCP/GTP-U/SBI evidence: separate `handover_attempts` and
`path_switch_attempts` families with evidence-bounded source/target association,
branch-aware conditional stages, item-scoped PDU Session resource outcomes,
bounded N11/N4/N3 supporting evidence, and procedure-local deviations with
structured evidence_refs; no success/failure verdicts, no root-cause output),
and the `5gc-failure-boundary` Analysis Orchestration
Skill (v0.1.0, evidence-safe first abnormal boundary localization across the
supported 5GC Domain analyses: diagnostic groups linked by exact common context,
candidates drawn only from Domain-emitted deviations and their machine-readable
evidence_refs (Domain contracts 5gc-registration-mobility >=0.2.0 and
5gc-pdu-session >=0.4.0), provenance-based ordering with no severity ranking, and no root-cause or blame output). The extensions
provide investigation context only.
**Not yet implemented:** deep NGAP transfer-container decoding, the remaining
NGAP mobility-adjacent procedures (RAN Status Transfer and similar), broader
5GC mobility beyond the bounded handover/path-switch Domain analysis (UPF
relocation, inter-system and 5GS-EPS mobility, RAN Status Transfer Domain
semantics), handover/path-switch consumption by Analysis Orchestration, remaining
5GC SBI services, GTP-U on N9/S1-U/S5-S8-U, remaining protocol Skills (NAS-EPS,
S1AP, GTPv2, SIP, SDP/RTP, Diameter), EPC/IMS Domain procedures,
implementation-specific mappings, or root-cause hypothesis reasoning and deeper
diagnosis orchestration.

## Why modular Skills

Each future Skill is designed to be downloaded and used independently. It must document its bounded responsibility, inputs, outputs, dependencies, evidence behavior, test coverage, and upstream provenance. This keeps reusable protocol expertise separate from domain procedures and implementation-specific knowledge.

```text
Foundation → Protocol → Correlation → Domain / Procedure → Analysis Orchestration
```

| Layer | Purpose |
| --- | --- |
| Foundation | Teach an agent how to investigate and grade evidence: Wireshark use, reverse engineering, systematic debugging, Linux, and C-oriented methods. |
| Protocol | Teach protocol-local encoding and correlation: NAS, NGAP, S1AP, GTP, PFCP, SIP, SDP/RTP, Diameter, and SBI. |
| Correlation | Join already-extracted protocol evidence into deterministic groups and a unified observed-evidence timeline by shared capture provenance. |
| Domain / procedure | Compose protocol evidence and correlation output into procedure-stage analysis for EPC, IMS, and 5GC procedures. Domain Skills consume protocol evidence and correlation output; they do not replace protocol decoding or correlation. |
| Analysis Orchestration | Combine protocol evidence into investigation reports that localize the first abnormal evidence boundary with confidence-aware diagnosis. |

Dependencies only point left, and a Skill may depend on the same layer when ownership remains acyclic and semantically correct. Lower layers never own higher-layer capabilities, which prevents circular architecture and preserves reuse. Correlation is optional infrastructure for Domain Skills, not a mandatory wrapper around every Protocol Skill.

CoreNet Skill focuses on network signaling evidence analysis rather than implementation-specific source ownership. Implementation is not a Skill layer: when users provide implementation-specific logs, source code, or configuration, agents may analyze them as external evidence, but the repository never owns Skills for implementation-specific telecom software, third-party implementations, or vendor-specific network functions.

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
Future milestones are Packet and Protocol Core (continuing), Diameter, IMS,
EPC, 5GC Core Procedures, Advanced 5GC Interfaces, and End-to-End Root Cause
Analysis. Implementation-specific Skills are not planned: external
implementation analysis is performed only when users provide implementation
evidence. Each milestone's gates and dependencies are frozen in
[docs/ROADMAP.md](docs/ROADMAP.md).
