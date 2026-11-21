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

CoreNet Skill is a modular, evidence-first AI Skill repository for mobile core-network signaling analysis, troubleshooting, protocol reasoning, cross-protocol correlation, procedure-level diagnosis, failure-boundary localization, and future end-to-end fault isolation. It focuses on network signaling evidence analysis rather than implementation-specific source ownership.

Describe repository capabilities only as they are actually implemented. The current repository provides architecture, contracts, schemas, a reusable Skill template, lightweight validation, Foundation Skills, bounded Protocol Skills including capture-scoped RTP source-stream and sequence-integrity reconstruction, the `cross-protocol-evidence` and `sdp-rtp-transport` Correlation Skills, Domain and Procedure Skills for the EPC, 5GC, IMS registration, IMS session-signaling, IMS SDP media-signaling and branch-scoped IMS media-transport evidence families, boundedly scoped Analysis Orchestration for failure-boundary localization, and an application-level unified PCAP workflow that integrates the accepted 5GC, EPC and IMS components, including an opt-in offline `--with-media` IMS SDP/RTP media composition. The `ims-media-signaling` Domain is a standalone analysis over accepted SIP, IMS Session and SDP artifacts; it is not executed by the unified workflow in this phase. It does **not** implement implementation-specific source-code mappings or end-to-end fault isolation. Planned functionality must never be presented as implemented functionality.


## Development Priority and Real-Capture Policy

These rules are permanent and apply to every future task:

1. Functional completeness and real operational usefulness take priority over unnecessary fragmentation. Directly related integration defects are fixed within the same authorized task.
2. Reuse existing Foundation, Protocol, Correlation and Domain Skills before creating a new Skill. The unified workflow is application-level orchestration; it owns no duplicate protocol or procedure semantics.
3. Use real, legitimately sourced PCAP captures for functional acceptance whenever available and appropriate. Record source provenance, capture SHA-256, license and visibility limits.
4. Public capture acquisition is a separate, explicitly authorized one-time operation. Subsequent analysis uses the pinned local copy and never silently re-downloads or replaces it.
5. PCAP analysis must not depend on internet search, remote AI inference, cloud packet-analysis APIs, online protocol analyzers, remote telemetry or online diagnosis. The `--offline` mode asserts this application boundary.
6. TShark remains permitted only as the existing local dissector dependency. Packet fields, dissector structures and frame provenance may come from TShark; all interpretation, association, evidence classification and conclusions belong to CoreNet-skill.
7. Every major capability must demonstrate real input, actual output and reproducible evidence. Synthetic unit tests alone do not establish real-capture operational acceptance.
8. CI passing on sanitized synthetic fixtures alone does not establish real-capture operational acceptance.
9. Private capture data, raw public-capture content, extracted SIP/SDP bodies, subscriber identities, RTP payloads, endpoint keys and real-capture working directories remain outside Git.
10. Never upload raw captures, derived plaintext bodies or endpoint keys to GitHub Actions or to any remote analysis service.

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

    Foundation -> Protocol -> Correlation -> Domain / Procedure -> Analysis Orchestration

Equivalently, higher layers may depend on lower layers:

    Foundation <- Protocol <- Correlation <- Domain <- Analysis Orchestration

Implementation is deliberately not a CoreNet Skill layer: implementation source analysis is an external, optional activity performed only when a user provides implementation evidence. Reverse ownership and circular dependencies are prohibited. A Skill may depend on a lower layer or on the same layer when ownership remains acyclic and semantically correct; it must not depend on a higher layer. Do not bypass these boundaries merely to reduce the number of files.

### Layer Responsibilities

| Layer | Primary question | Responsibility |
| --- | --- | --- |
| Foundation | How should evidence be investigated? | Reusable investigation and engineering methods, evidence grading, and Linux/network troubleshooting methodology; it does not own telecom procedure semantics. |
| Protocol | What does the message and field mean? | Protocol-local encoding, fields, messages, identifiers, transactions, state, and correlation reusable by several domains. |
| Correlation | Which observations belong together? | Provenance-key joins, deterministic cross-protocol evidence grouping, cross-protocol ordering, correlation-strength classification, and missing-evidence visibility; it does not own protocol decoding, procedure verdicts, or root cause. |
| Domain / Procedure | How should the telecom procedure operate? | Cross-network-function telecom procedures, such as registration, session establishment, mobility, IMS registration, and voice call procedures; consumes Protocol and Correlation outputs. |
| Analysis Orchestration | Where is the first abnormal evidence boundary? | Combines protocol evidence, produces investigation reports, and delivers confidence-aware diagnosis without duplicating lower-layer knowledge bases. |

Correlation is optional infrastructure: a Domain Skill may consume Correlation outputs, but no Domain Skill is required to wrap every Protocol Skill through Correlation. CoreNet Skill focuses on network signaling evidence analysis rather than implementation-specific source ownership.

Examples of valid dependencies:

    ims-registration -> sip -> diameter-ims
    ims-session -> sip
    ims-media-signaling -> sip -> sdp-rtp -> ims-session
    epc-procedures -> nas-eps -> s1ap -> gtpv2 -> diameter-epc
    5gc-pdu-session -> nas-5gs -> ngap -> pfcp -> sbi-http2
    cross-protocol-evidence -> ngap -> nas-5gs -> core-network-pcap
    sdp-rtp-transport -> sdp-rtp
    rtp-stream -> sdp-rtp
    ims-media-session -> ims-session, ims-media-signaling, sdp-rtp, sdp-rtp-transport
    5gc-registration-mobility -> cross-protocol-evidence -> ngap -> nas-5gs (future)
    diameter-ims -> diameter-core (same-layer Protocol composition)

Examples of invalid dependencies:

    sip -> ims-registration
    diameter-core -> diameter-ims
    ngap -> 5gc-registration-mobility
    ngap -> cross-protocol-evidence
    cross-protocol-evidence -> 5gc-registration-mobility

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
- A protocol-local transaction correlator is not cross-protocol Correlation and not Domain procedure analysis; SIP transaction correlation alone does not establish an IMS outcome. The SIP Protocol Skill additionally provides a separate bounded Dialog evidence producer. SIP Dialog evidence is protocol-local, and a confirmed Dialog does not establish IMS registration, RTP delivery, two-way audio or call success.
- A passive capture cannot establish a SIP client/server stack role or RFC timer state; an observed 487 INVITE plus 200 CANCEL is evidence of a response sequence, never proof of `TERMINATED`.
- RFC 3261 magic-cookie and legacy SIP Via matching are distinct algorithms; a non-cookie branch must not silently use the modern branch-only identity.
- A SIP dialog is a signaling construct identified by Call-ID plus local and remote tags; a confirmed dialog never proves RTP delivery, two-way audio, IMS registration, authentication or call success, and forked branches must not be collapsed into one selected call.
- Encrypted transports (for example SIP over TLS or DTLS) are never decrypted or presented as plaintext protocol evidence; absence of decrypted evidence is reported as encrypted or unavailable, never as absence of traffic.
- RFC 3261 wildcard Contact removal requires exactly one sole `Contact: *` together with `Expires: 0`; wildcard presence alone, a nonzero `Expires`, a wildcard mixed with another Contact value, duplicate wildcard values, a malformed wildcard token, malformed expiration evidence or an unresolved raw Contact boundary must not be promoted to a valid all-bindings or Contact-scoped removal.
- Raw Contact values are recognised only at provable top-level boundaries; commas inside an angle-bracketed URI or quoted display name are not boundaries, and an unprovable boundary must fail closed as unresolved instead of being split naively.
- A REGISTER with `Expires: 0` and no Contact does not change the binding list and must not be published as an established de-registration; a supplied Contact is only Contact-scoped, and a Contact-specific `expires` parameter overrides the default `Expires` header for that Contact.
- A binding-removal outcome must bind to the removal request's own REGISTER transaction and final response; an unrelated transaction's 2xx must never establish removal success.
- A SIP authentication Challenge→Retry association requires a later authorized REGISTER after the observed challenge with a compatible CSeq; authorization present before the challenge must not be reported as a retry of it. The observed challenge response must precede the retry request in capture-local evidence order.
- RTP padding, extension and marker are mandatory one-bit observations; a missing RTP flag must be reported as incomplete evidence and must never be silently converted to false. RTP and RTCP versions occupy a two-bit field: other representable versions are unsupported, while values outside 0-3 are invalid.
- RTP source-stream reconstruction is a Protocol-local capability: grouping uses capture plus UDP stream plus capture-scoped SSRC reference, probation and sequence tracking follow RFC 3550 Appendix A.1, and unobserved sequence numbers never become confirmed packet loss. RTCP components are never associated with an RTP stream, and no jitter, MOS, QoS, media-delivery or call verdict is produced.
- Compound RTCP packets must retain every decoder-visible component; a single collapsed component must never be treated as the whole compound packet. Receiver-reported values retain `measurement_origin = RECEIVER_REPORTED`; a millisecond jitter conversion requires a proven unique RTP clock rate and source association.
- Per-call and per-branch media evidence must never be promoted from capture-wide or cross-attempt endpoint correlation. Each attempt and branch retains its own evidence-coverage status; shared RTP streams and competing SDP references remain explicit ambiguity.
- RTP duplicate identity requires the complete RTP packet bytes compared through a capture-scoped keyed HMAC, not an RTP header tuple. A multi-vantage classification requires matching packet bytes plus differing capture-view or encapsulation evidence; a header-tuple match alone is `RTP_HEADER_SIGNATURE_MATCH`, and sequence-number equality alone stays unresolved. Byte-identical observations still do not prove the physical cause of duplication or retransmission.
- Temporal association uses SIP observation boundaries and never claims true RTP start or end. A packet observed after BYE is not automatically an error, and a missing packet after 2xx is not automatically a media failure.
- RTCP report counts and source counts are type-specific: SR/RR use report counts, SDES/BYE use source counts, and missing hierarchy or declared/observed mismatch must fail closed rather than be marked observed. A zero-source BYE is valid per RFC 3550 but conveys no source identifier.
- Structured capture file provenance must be a privacy-safe basename; absolute workstation paths and path separators are rejected rather than published.
- An IMS session attempt is anchored to one initial INVITE transaction; separate initial INVITE transactions must never merge merely because they share a Call-ID or nearby frames.
- A logical IMS call group requires capture-scoped HMAC identity references for Call-ID, From-tag and To-tag, a confirmed INVITE and matching CSeq method, a valid CSeq number, and a single coherent nested Via-hop stack for multi-hop grouping. Call-ID equality alone never merges attempts, a differing To-tag keeps Dialog/fork branches separate, and a B2BUA Call-ID change without an independent identity bridge remains unresolved. Differing CSeq initial INVITEs merge only through an accepted Dialog bridge; two competing Via chains never form one proven chain. Logical-call media ownership never replaces attempt-level or branch-level evidence status.
- SIP identity references are scoped by the capture SHA-256 when it is available, not by the capture basename alone. A reused key and identical filename across different capture contents must not produce shared published identities; raw Call-ID, tags, Via values and keys are never published.
- Logical-call media ownership requires an accepted ESTABLISHED IMS Media Signaling Exchange, offer/answer references inside the accepted logical-call context, a matched transport correlation, uniquely owned RTP source streams, accepted Dialog branch identity where branch ownership is claimed, and no competing owner or unbound same-dialog SDP observation. An observed Offer in one place and an Answer in another is insufficient.
- RTCP sender-to-RTP-source association, report-block reportee association and RTCP-to-logical-call ownership are three separate relationships. A unique sender or reportee source never proves call ownership; jitter milliseconds remain unavailable without a unique proven RTP clock rate and source association. A nonempty RTCP association list containing only ambiguous or insufficient source relationships never yields a positive logical-call RTCP association.
- `MULTI_VANTAGE_SUPPORTED` requires byte-identical RTP packets in the same source stream with a compatible inner transport path and differing capture-view evidence. Byte-identical packets in independent streams keep their byte identity but are never collapsed into one physical observation, and no retransmission, packet loss or capture topology is inferred.
- SIP final responses are classified as observed procedure outcomes before any diagnostic boundary. A 4xx, 5xx or 6xx response is a negative SIP outcome, not a protocol violation and not a network-function root cause. A matching CANCEL transaction with its own 200 response and an INVITE 487 is normal INVITE termination processing. A 401 or 407 is an authentication challenge, not an authentication failure. Forked Dialog branches keep independent outcomes; a rejected or cancelled branch never turns an accepted branch into a failed logical call. A protocol violation requires explicit contradictory protocol evidence, and a procedure contradiction requires conflicting final responses for one proven transaction or branch.
- Per-call diagnostics keep `OBSERVED_PROTOCOL_VIOLATION`, `OBSERVED_SIP_PROCEDURE_CONTRADICTION`, `OBSERVED_NEGATIVE_SIP_OUTCOME`, `OBSERVED_CANCELLED_SIP_OUTCOME`, `OBSERVED_MIXED_SIP_OUTCOMES`, `MISSING_OBSERVATION`, `CAPTURE_VISIBILITY_LIMITATION`, `UNSUPPORTED_PROCEDURE`, `EXTRACTION_FAILURE`, `IDENTITY_AMBIGUITY` and `NO_ABNORMAL_EVIDENCE_OBSERVED` distinct. A missing SDP Answer or RTP observation is never automatically a network or media failure, and an absent response is never a locally inferred timeout.
- A 2xx INVITE response and its Confirmed Dialog are signaling evidence only; a missing 2xx ACK must not erase the observed response or dialog, and no result may claim call success, two-way audio or media delivery.
- A later accepted BYE/2xx that moves a Confirmed Dialog to `TERMINATED` must not erase an earlier established SDP Offer/Answer association. Historical confirmation must be proven by the branch-owned accepted 2xx INVITE response and matching branch and attempt termination evidence for that exact Dialog; the `TERMINATED` label alone never proves confirmation.
- SDP-to-RTP transport correlation uses only capture-scoped keyed HMAC endpoint references; raw IP addresses, raw UDP endpoint tuples and key material are never published, and exact endpoint equality never proves IMS session identity, media delivery, two-way audio or call success.
- An IMS media-session association joins one accepted Correlation record to IMS Session attempts and Dialog Branches; a capture-wide endpoint match never implies temporal association with the INVITE-to-BYE lifetime, and a later BYE never proves RTP teardown, media-resource release or media-session success.
- Forked Early and Confirmed Dialog branches remain independent; a CANCEL 200 OK, an INVITE 487, and a BYE 2xx are separate transaction/dialog observations and never by themselves prove RFC transaction termination, RTP teardown or end-to-end release.
- SIP observation makes bounded IMS analysis eligible for automatic workflow execution but never upgrades IMS technology attribution from `SUSPECTED` to `CONFIRMED`; SDP/RTP-only or Diameter-only evidence does not establish IMS identity.
- The unified workflow composes accepted IMS components and must preserve independent SIP, Diameter Cx/Dx, Registration and Session inventories; one component failure must not discard another component's valid evidence or be collapsed into a single `FAILED` verdict.
- A SIP-to-Diameter procedure association requires a privacy-safe cross-protocol subscriber identity bridge; without one, Domain evidence must remain `NOT_ESTABLISHED` or `INSUFFICIENT_EVIDENCE` and must never be inferred from filenames, timestamps, frame proximity, addresses, counts or matching protocol success.

When packet-analysis functionality is authorized and implemented, prefer reproducible extraction over visual guesswork. Wireshark, tshark, and tcpdump may support workflows, but never state a field was observed unless the capture or extracted output contains it. Prefer stable correlation identifiers—subscriber, session, transaction, tunnel, dialog, or stream IDs—over timestamp-only correlation when stronger identifiers exist.

Protocol cause tables must be keyed by the exact normative cause number and kept namespace-separate where the protocol defines more than one cause space. Never shift, re-index, or merge cause dictionaries to fit a neighbouring value; unlisted values retain their numeric code and an unavailable name.

### Source-Code Analysis Discipline

Implementation-specific source analysis does not redefine protocol truth, and implementation internals are not CoreNet Skill ownership. When a user supplies implementation logs, source code, or configuration, an agent may analyze them as external evidence for the observed failure; the repository itself never owns implementation Skills for specific products. Use this reasoning direction:

    observed protocol behavior
    -> procedure interpretation
    -> implementation mapping
    -> source file
    -> state machine / handler / function
    -> candidate defect
    -> validation

Do not start by changing source code merely because a network procedure failed. Establish the failure boundary first.

### Standards-Based, Implementation-Neutral Vocabulary

Repository-owned telecom semantics are standards-based: they derive from 3GPP specifications, directly applicable protocol standards, reviewed protocol dissector contracts where required for extraction, and observable evidence. Repository Skills model protocols, interfaces, network functions, messages, information elements, procedures, evidence, correlation, and diagnostic boundaries — never named implementations.

Durable rules for all repository content (documentation, code, validators, tests, schemas, fixtures, examples, comments, and tracked filenames):

- Repository-owned semantics must remain implementation-neutral; telecom Skills are built from standardized protocol and procedure semantics, not from named implementation-project expertise.
- Named implementation-project expertise must not become Skill ownership; do not create Skills, source models, log-format knowledge bases, configuration mappings, or project-specific behavior contracts for specific telecom software products.
- Project-specific source/log/config mappings are prohibited in repository-owned content; describe such material generically as implementation-specific logs, source code, or configuration.
- When generic wording is genuinely needed, prefer neutral terminology such as "implementation-specific project", "third-party implementation", "vendor-specific implementation", or "implementation mapping"; prefer standards terminology (AMF, SMF, UPF, gNB, and standardized interfaces) wherever technically appropriate.
- Legitimate normative references (3GPP, ETSI, IETF, RFC, Wireshark/TShark) remain exempt from this rule: it targets implementation-project coupling, not standards orientation or the protocol extraction toolchain.
- The whole-tree case-insensitive prohibition is enforced by the repository validator; the policy's complete-token set is defined in `scripts/implementation_policy.py` without storing the tokens literally anywhere in the repository.

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

Obey the current task's explicit STOP boundary. Do not implement later work because it is related, convenient, or small. Foundation authorization does not authorize Protocol work; Protocol authorization does not authorize Correlation work; Correlation authorization does not authorize Domain procedure logic; authorization for one Skill does not authorize unrelated Skills.

When a schema defines an output contract, do not silently add incompatible fields, remove required semantics, or change field meaning. Prefer backward-compatible extension. A schema-breaking change needs explicit task authorization and migration consideration.

Prefer the simplest reproducible tooling. Python standard library is preferred when sufficient; dependencies must be justified. Do not commit generated artifacts accidentally. Scripts must provide meaningful exit codes and fail loudly on contract violations.

## Documentation and Commit Wording

Repository-authored content must not contain numbered lifecycle markers: commit messages, documentation, code, fixtures, and other project files must not include wording such as "Phase 1", "phase2", "PHASE 3", "Phase1", "Phase 2", "phasexxx", "P1", "P2-1", "Stage1", "Stage 2", "Milestone B1", or similar stage labels, in any letter case and with any combination of spaces, hyphens, or other separators (or none at all). The ban covers both spelled-out stage words and their abbreviated or numeric shorthand forms, so "stage 3", "Stage3", "S3", "phase-4", and "P4.2" are equally prohibited. Capability status is described directly; stage and milestone numbering belongs to task coordination outside the repository. Frozen upstream snapshots (the `third_party/` tree and package-local `upstream/` directories) are exempt from this rule. Package validators enforce the marker ban over CoreNet-authored files.

A commit message states the change in one sentence: a single conventional-style subject line, ideally under 72 characters, with no multi-paragraph body, no bulleted change lists, and no restatement of the diff. Detail that does not fit in that sentence belongs in the task report, a design document, or an issue, not in Git history. This wording rule applies forward; already-pushed commits are never rewritten to satisfy it.

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

Use focused, descriptive conventional-style commit messages where appropriate, each a single sentence as required in Documentation and Commit Wording. Do not bundle unrelated cleanup into feature commits.

## Validation and Completion Reporting

Before claiming completion, run repository-level validation appropriate to the change. While they remain authoritative, the baseline checks are:

    python3 scripts/validate-repository.py
    python3 -m unittest discover -s tests -p 'test_*.py' -v
    python3 -m compileall scripts
    git diff --check

For IMS Registration changes, also run `python3 scripts/validate-ims-registration.py`.
For IMS Session changes, also run `python3 scripts/validate-ims-session.py`.
For IMS Media Signaling changes, also run `python3 scripts/validate-ims-media-signaling.py`.
For SDP changes, also run `python3 scripts/validate-sdp-rtp.py`.
For RTP/RTCP changes, also run `python3 scripts/validate-rtp-rtcp.py`.
For RTP source-stream changes, also run `python3 scripts/validate-rtp-stream.py`.
For offline IMS media workflow changes, also run `python3 -m unittest discover -s tests -p 'test_ims_media_pipeline.py'`.

For EPC Evidence Review navigation changes, also run:

    python3 scripts/validate-epc-review-navigation.py
    python3 scripts/validate-epc-evidence-review.py
    python3 scripts/validate-epc-dedicated-bearer-timeline.py
    python3 scripts/validate-epc-dedicated-bearer-attribution.py

Real-capture acceptance is a local-only operational check: run `scripts/corenet-analyze.py` with `--with-media --offline` against the pinned local public corpus. Raw captures are never committed or uploaded to CI; synthetic CI success is reported separately from real-capture acceptance.
Also run any Skill-specific tests introduced by the task. Never call a check PASS unless it ran. If a tool or dependency prevents a check, report NOT RUN and the exact reason. Tests for executable or rule-driven Skills should use small deterministic fixtures and cover normal behavior, malformed or missing input, boundary cases, evidence classification, correlation where applicable, and expected failure handling. Avoid large opaque packet captures unless justified.

For non-trivial repository changes, the final report includes the inspected baseline, files changed, behavior added or changed, scope intentionally not implemented, tests and validation results, commit SHA if committed, push status if pushed, and blockers. Report failed validation; do not claim remote success without verification.

## Local Final Report Delivery Policy

Every completed development milestone must leave an actual UTF-8 Markdown Final Report inside the current project's root `reports/` directory, named `<PHASE-ID>-FINAL-REPORT.md`.

- `reports/` is local-only. It must never be staged, committed, pushed, published as repository content, or included in CI artifacts. Do not place reports inside tracked documentation directories, and never write a report only to standard output.
- Create `reports/` when absent and protect it through local Git metadata, preferring `.git/info/exclude` over modifying tracked `.gitignore`. Do not commit `.git/info/exclude`, and never use `git add -f` for reports.
- Generate the report after the authorized commit, the normal push, and CI success on the exact final SHA. The report must cite that final SHA and the CI run for it. Never fabricate a CI result; record a failed or blocked gate explicitly.
- Before each commit and push, verify that no report path is staged (`git diff --cached --name-only`) and that `reports/` remains ignored and untracked (`git check-ignore -v`, `git ls-files -- reports/`).
- The report distinguishes verified-in-code, verified-in-CI, verified-by-real-capture-replay, not-executed, and not-independently-verified results. Real-capture replay is claimed only when the capture was actually replayed.
- Fail closed: when required evidence or a gate is missing, the report records the actual blocked status rather than a speculative success.
- Generating the local report never requires an additional commit, and no commit may be created solely to publish it.
