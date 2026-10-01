# CoreNet Skill Agent Operating Contract

This file is the durable repository-level instruction set for AI coding agents working in **CoreNet Skill** (CoreNet-skill). It governs future work across all milestones; it is not a task plan or a substitute for the repository's authoritative contracts.

## Instruction Precedence and Conflict Handling

Apply instructions in this order:

1. Explicit user instruction for the current task.
2. Current task or milestone prompt.
3. This repository AGENTS.md.
4. Frozen repository documentation and schemas.
5. Local implementation conventions.
6. Agent defaults.

A lower-level instruction must never silently override a higher-level one. Destructive Git actions always require explicit user authorization. Ambiguous instructions do not authorize a violation of frozen architecture. If requirements conflict, stop and report the conflict rather than guessing.

## Repository Identity and Current Capability

CoreNet Skill is a modular, evidence-first AI Skill repository for mobile core-network signaling analysis, troubleshooting, protocol reasoning, implementation mapping, and future end-to-end fault isolation.

Describe repository capabilities only as they are actually implemented. The current repository provides architecture, contracts, schemas, a reusable Skill template, and lightweight validation. It does **not** yet implement protocol decoders, packet-field extraction, procedure logic, source-code mappings, packet analysis, or end-to-end troubleshooting. Planned functionality must never be presented as implemented functionality.

## Authoritative Documentation

Read the relevant contract before editing. Do not duplicate it unnecessarily.

| Topic | Authoritative source |
| --- | --- |
| Architecture and ownership | docs/ARCHITECTURE.md |
| Skill contract | docs/SKILL-SPEC.md and templates/skill-template/ |
| Trace output | docs/TRACE-SCHEMA.md and shared/schemas/trace-event.schema.json |
| Evidence semantics | docs/EVIDENCE-SCHEMA.md and shared/schemas/evidence.schema.json |
| Diagnostic results | shared/schemas/diagnostic-result.schema.json |
| Testing policy | docs/TESTING.md |
| External material | docs/UPSTREAM.md |
| Naming | docs/NAMING.md |
| Planned work | docs/ROADMAP.md |

Repository documentation and code-facing documentation remain English unless a future task explicitly authorizes another language. Preserve conventional technical protocol names and acronyms.

## Frozen Architecture

The only permitted conceptual dependency direction is:

    Foundation -> Protocol -> Domain / Procedure -> Implementation -> Orchestration

Equivalently, higher layers may depend on lower layers:

    Foundation <- Protocol <- Domain <- Implementation <- Orchestration

Reverse ownership and circular dependencies are prohibited. Do not bypass these boundaries merely to reduce the number of files.

### Layer Responsibilities

| Layer | Primary question | Responsibility |
| --- | --- | --- |
| Foundation | How should the problem be investigated? | Reusable investigation and engineering methods; it does not own telecom procedure semantics. |
| Protocol | What does this protocol message mean? | Protocol-local encoding, fields, messages, identifiers, transactions, state, and correlation reusable by several domains. |
| Domain / Procedure | How does the telecom procedure work across network functions? | Cross-network-function telecom procedures, such as EPC, IMS, and 5GC. |
| Implementation | How is behavior implemented in a particular network function? | Maps standardized behavior to source trees, modules, state machines, functions, configuration, and logs. |
| Orchestration | Where did the end-to-end procedure first become abnormal? | Combines validated lower-layer results without duplicating their full knowledge bases. |

Examples of valid dependencies:

    ims-registration -> sip -> diameter-ims
    epc-procedures -> nas-eps -> s1ap -> gtpv2 -> diameter-epc
    5gc-pdu-session -> nas-5gs -> ngap -> pfcp -> sbi-http2

Examples of invalid dependencies:

    sip -> ims-registration
    diameter-core -> diameter-ims
    ngap -> 5gc-registration-mobility

### Diameter Is Cross-Domain

Diameter is not an IMS-owned protocol. Preserve this ownership model:

    diameter-core
    ├── diameter-epc
    ├── diameter-ims
    └── diameter-charging

diameter-core owns the base header, command metadata, AVP structure, identifiers, Vendor-ID, Application-ID, result semantics, and base protocol behavior. diameter-epc owns EPC-context applications; diameter-ims owns IMS-context applications; diameter-charging owns reusable charging and credit-control semantics. Do not duplicate the base parser or common Diameter semantics inside the domain-specific Skills.

### 5GC Functional Interface Grouping

Do not automatically create one Skill per 5GC N-interface. Prefer functional grouping, and introduce an interface-specific Skill only with clear technical justification and without duplicating an existing functional Skill.

| Interfaces | Functional ownership |
| --- | --- |
| N1/N2 | Access signaling and mobility |
| N3/N9 | GTP-U user plane |
| N4 | PFCP |
| N5/N7/N15 | Policy control |
| N6 | Data-network user plane and IP networking |
| N8/N10/N11/N12/N13/N14 | SBI interactions |
| N22/N24/N26/N27 | Selection, policy, and interworking |
| N32/N33 | Roaming, security edge, and exposure |

## Skill Modularity and Naming

Every real Skill must be independently understandable and, where practical, independently downloadable. Never assume the whole repository is installed. Follow docs/SKILL-SPEC.md and templates/skill-template/; do not invent an incompatible structure without explicit approval.

Each Skill must clearly define:

- purpose, scope, and non-goals;
- dependencies and standalone expectations;
- inputs and outputs;
- evidence behavior and failure behavior;
- testing; and
- provenance.

Follow docs/NAMING.md: Skill directories use lowercase kebab-case and the Skill name matches its directory. Make protocol and domain ownership semantically accurate; avoid misleading names. Canonical files may retain established uppercase names such as README.md, SKILL.md, AGENTS.md, UPSTREAM.md, and LICENSE. Do not casually rename established Skills once other Skills depend on them.

## Evidence-First Investigation

All diagnostic and troubleshooting work must separate evidence from interpretation, hypotheses, and confirmation. Use the frozen vocabulary:

| Level | Meaning |
| --- | --- |
| OBSERVED | Directly visible in a primary artifact such as a capture, log, configuration, source file, or command output. |
| DERIVED | Deterministically calculated or correlated from observed evidence. |
| INFERRED | Strongly suggested by behavior but not directly proven. |
| HYPOTHESIS | A plausible root-cause candidate needing additional evidence. |
| CONFIRMED | Proven by sufficient independent evidence, reproduction, implementation verification, or controlled validation. |

Never turn a visible action into unsupported causation. A captured RAN-side release message supports that the observed RAN-side signaling path initiated a release; it does not by itself prove that the RAN caused a registration failure. Label causation as inference or hypothesis until it is confirmed.

For troubleshooting, follow this sequence:

1. Establish the expected procedure.
2. Identify the last known-good event.
3. Identify the first abnormal or missing event.
4. Locate the failure boundary.
5. Collect evidence around that boundary.
6. Generate candidate hypotheses.
7. Test hypotheses.
8. Confirm root cause only when sufficient evidence exists.

Prefer reporting a supported failure boundary to claiming an unsupported root cause. If evidence is insufficient, say so explicitly. A diagnostic report should separate Observed Evidence, Derived Facts, Failure Boundary, Inferences, Hypotheses, Confirmed Root Cause, and Next Checks. Confidence must reflect evidence strength.

### Protocol and Packet Discipline

Keep transport, protocol, procedure, and implementation behavior distinct:

- SCTP transport failure is not automatically an NGAP procedure failure.
- HTTP/2 transport behavior is not automatically 5GC SBI service logic.
- UDP reachability on port 8805 is not PFCP Session Establishment semantic correctness.
- SIP transport reachability is not IMS registration or call-state correctness.

When packet-analysis functionality is authorized and implemented, prefer reproducible extraction over visual guesswork. Wireshark, tshark, and tcpdump may support workflows, but never state a field was observed unless the capture or extracted output contains it. Prefer stable correlation identifiers—subscriber, session, transaction, tunnel, dialog, or stream IDs—over timestamp-only correlation when stronger identifiers exist.

### Source-Code Analysis Discipline

Implementation-specific source analysis does not redefine protocol truth. Use this reasoning direction:

    observed protocol behavior
    -> procedure interpretation
    -> implementation mapping
    -> source file
    -> state machine / handler / function
    -> candidate defect
    -> validation

Do not start by changing source code merely because a network procedure failed. Establish the failure boundary first.

## External Source Governance

Follow docs/UPSTREAM.md. Do not hard-code external candidate repositories unless the current task authorizes them. Before importing or adapting external material:

- review the license first;
- record an immutable source commit when practical;
- preserve attribution and source path;
- document local changes;
- separate local extensions from upstream snapshots where practical; and
- never fabricate license information, remove required attribution, or present imported material as original repository work.

If licensing is unclear, stop; do not import the material.

For imported Skills, prefer this traceable shape where it is compatible with the actual Skill specification:

    <skill>/
    ├── SKILL.md
    ├── README.md
    ├── manifest.yaml
    ├── UPSTREAM.md
    ├── upstream/
    ├── extensions/
    └── tests/

Prefer an original upstream snapshot plus local wrapper, extension, and tests over rewriting upstream source. Document any direct upstream modification.

## Scope, Schema, and Tooling Discipline

Obey the current task's explicit STOP boundary. Do not implement later work because it is related, convenient, or small. Foundation authorization does not authorize Protocol work; Protocol authorization does not authorize Domain procedure logic; authorization for one Skill does not authorize unrelated Skills.

When a schema defines an output contract, do not silently add incompatible fields, remove required semantics, or change field meaning. Prefer backward-compatible extension. A schema-breaking change needs explicit task authorization and migration consideration.

Prefer the simplest reproducible tooling. Python standard library is preferred when sufficient; dependencies must be justified. Do not commit generated artifacts accidentally. Scripts must provide meaningful exit codes and fail loudly on contract violations.

## Documentation and Commit Wording

Repository-authored content must not contain numbered lifecycle markers: commit messages, documentation, code, fixtures, and other project files must not include wording such as "Phase 1", "phase2", "PHASE 3", "Milestone B1", or similar stage labels, in any letter case and with or without a separator. Capability status is described directly; stage and milestone numbering belongs to task coordination outside the repository. Frozen upstream snapshots (the `third_party/` tree and package-local `upstream/` directories) are exempt from this rule. Package validators enforce the marker ban over CoreNet-authored files.

## Security and Fixture Hygiene

Never commit credentials, tokens, passwords, private keys, subscriber production secrets, real authentication vectors, confidential production packet captures, or personally identifying subscriber data unless explicitly sanitized and authorized. Use synthetic or sanitized fixtures. Illustrative telecom identifiers may include 001010000000001, 10000000001, internet, and ims; label them as illustrative.

## Working-Tree and Git Safety

Before editing, run git status --short and inspect staged or unstaged work. Never overwrite unexplained user changes. Preserve unrelated modifications; do not silently normalize, reformat, rename, or delete unrelated files. If safe isolation is impossible, stop and report the conflict.

Never use these commands without explicit user authorization:

    git reset --hard
    git clean -fd
    git clean -fdx
    git push --force
    git push --force-with-lease

Do not rewrite history, replace the root commit, amend historical commits only to fix wording or formatting, arbitrarily create or delete branches, change repository visibility, or replace origin without explicit instruction. Normal focused forward commits are preferred. Use the current HEAD as the working baseline; do not assume an old SHA remains current.

Before committing:

1. Inspect git status --short.
2. Inspect the complete diff.
3. Run applicable validation.
4. Confirm temporary files are not tracked.
5. Confirm unrelated changes are not included.

Use focused, descriptive conventional-style commit messages where appropriate. Do not bundle unrelated cleanup into feature commits.

## Validation and Completion Reporting

Before claiming completion, run repository-level validation appropriate to the change. While they remain authoritative, the baseline checks are:

    python3 scripts/validate-repository.py
    python3 -m unittest discover -s tests -p 'test_*.py' -v
    python3 -m compileall scripts
    git diff --check

Also run any Skill-specific tests introduced by the task. Never call a check PASS unless it ran. If a tool or dependency prevents a check, report NOT RUN and the exact reason. Tests for executable or rule-driven Skills should use small deterministic fixtures and cover normal behavior, malformed or missing input, boundary cases, evidence classification, correlation where applicable, and expected failure handling. Avoid large opaque packet captures unless justified.

For non-trivial repository changes, the final report includes the inspected baseline, files changed, behavior added or changed, scope intentionally not implemented, tests and validation results, commit SHA if committed, push status if pushed, and blockers. Report failed validation; do not claim remote success without verification.
