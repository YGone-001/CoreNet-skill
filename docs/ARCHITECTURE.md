# Architecture

## Purpose and dependency direction

This repository is a modular collection of independently downloadable Skills for core-network signaling evidence analysis: protocol decoding knowledge, cross-protocol correlation, procedure-level diagnosis, and failure-boundary localization from observable evidence. CoreNet Skill focuses on network signaling evidence analysis rather than implementation-specific source ownership.

```text
Foundation Skills → Protocol Skills → Correlation Skills → Domain / Procedure Skills → Analysis Orchestration Skills
```

Dependencies flow only to the left. A higher layer may compose lower-layer contracts, but a lower layer must never import, own, or depend on a higher-layer capability. A Skill may depend on the same layer when ownership remains acyclic and semantically correct (for example, `diameter-ims` depending on `diameter-core`). Circular ownership is prohibited.

Implementation is deliberately not a CoreNet Skill layer. The system answers "What happened in the network signaling?"; it does not primarily answer "Which source-code function in an implementation caused it?" Implementation source analysis remains an external optional activity, never repository ownership.

## Layers

| Layer | Responsibility | May depend on |
| --- | --- | --- |
| Foundation | Reusable evidence investigation methods and grading. | External standard tooling only |
| Protocol | Message encoding, fields, and protocol-local correlation. | Foundation |
| Correlation | Provenance-key joins, deterministic cross-protocol evidence grouping, cross-protocol ordering, correlation-strength classification, and missing-evidence visibility. | Foundation, Protocol |
| Domain / procedure | Cross-network-function telecom procedures; consumes Protocol and Correlation outputs. | Foundation, Protocol, Correlation |
| Analysis Orchestration | Combining protocol evidence, producing investigation reports, and confidence-aware diagnosis that locates the first abnormal evidence boundary. | All lower layers |

Examples of permitted ownership: `ims-registration` depends on `sip` and `diameter-ims`; `epc-procedures` depends on `nas-eps`, `s1ap`, and `diameter-epc`; `5gc-pdu-session` depends on `nas-5gs`, `ngap`, `pfcp`, `gtpu`, and `sbi-http2`; `cross-protocol-evidence` depends on the `ngap` and `nas-5gs` event contracts; `5gc-registration-mobility` depends on `cross-protocol-evidence`, `ngap`, and `nas-5gs`; `diameter-ims` depends on same-layer `diameter-core`.

Examples of prohibited ownership: `sip` must not depend on `ims-registration`; `diameter-core` must not depend on `diameter-ims`; `ngap` must not depend on `5gc-registration-mobility` or on `cross-protocol-evidence`; `cross-protocol-evidence` must not depend on `5gc-registration-mobility`.

## Correlation boundary

Correlation answers: **Which observations belong together?**

An allowed Correlation conclusion: "NGAP frame evidence and NAS-5GS evidence share capture_file X and frame_number 42 and therefore form a STRONG provenance join."

Not allowed Correlation conclusions: "5G Registration succeeded." or "Registration failed at Authentication." Those require Domain semantics. The Correlation layer does not decode protocols, does not own procedure success or failure, does not own subscriber or session semantics unless explicitly supplied by a lower contract, and does not own root cause.

Correlation is optional infrastructure for Domain Skills, not a mandatory wrapper: a Domain Skill may consume Correlation outputs, and no Domain Skill is required to route every Protocol Skill through Correlation.

## Implementation ownership boundary

CoreNet Skill does not own implementation-specific Skills. It must not create dedicated Skills for implementation-specific telecom software, third-party implementations, or vendor-specific network functions, and it holds no source models, log-format knowledge bases, configuration mappings, or project-specific behavior contracts for them. Repository-owned telecom knowledge is based on standardized protocol and procedure semantics.

External implementation context remains welcome as evidence. If a user provides AMF or SMF logs, implementation-specific logs, source code, or configuration files, an agent may analyze them as external evidence for the observed failure. Allowed: "Given implementation-specific AMF source and this failure PCAP, analyze possible implementation behavior." Not allowed: "CoreNet-skill contains an implementation-specific AMF Skill." Implementation findings stay user-scoped analysis, never repository-owned expertise.

## Implemented catalog

Implemented Protocol Skills: `core-network-pcap` (capture ingestion, dissector classification, protocol-neutral trace-event normalization), `ngap` (bounded UE-context signaling semantics over N2, including the PDU Session Resource setup/modify/release subset, resources embedded in Initial Context Setup, and the bounded N2 handover/path-switch mobility subset with bounded mobility metadata and item-scoped resource-list roles), `nas-5gs` (bounded 5GMM registration/identity/authentication/security-mode/service/status semantics and bounded 5GSM PDU session establishment/modification/release/status semantics over N1), `pfcp` (bounded N4 session-control semantics: Heartbeat, Association Setup, and Session Establishment/Modification/Deletion with header SEID and CP/UP F-SEID evidence, bounded PDR/FAR/QER/URR rule groups, PFCP Cause, and endpoint-scoped transaction correlation), `gtpu` (bounded N3 user-plane observation semantics: G-PDU, Echo, Error Indication, End Marker with TEID evidence scoped by directed outer endpoints and bounded PDU Session Container/QFI evidence), and `sbi-http2` (bounded N11 Nsmf_PDUSession and Namf_Communication semantics with HTTP/2 stream isolation scoped by connection context, transfer reference tracking, and deterministic callback correlation).

Implemented Correlation Skills: `cross-protocol-evidence` joins already-extracted protocol detailed events into deterministic evidence groups and a unified observed-evidence timeline by shared capture provenance. It is optional infrastructure for Domain Skills, not a mandatory wrapper.

Planned protocol work remains: `nas-eps`, `s1ap`, `gtpv2`, `sip`, `sdp-rtp`, `diameter-core`, `diameter-epc`, `diameter-ims`, and `diameter-charging`; broader SBI service semantics beyond the bounded Nsmf_PDUSession and Namf_Communication subset; the remaining NGAP mobility-adjacent procedures (RAN Status Transfer and similar); and GTP-U on N9/S1-U/S5-S8-U. These names are plans, not implementations.

Implemented Domain capabilities: `procedure-evidence` defines the common evidence model (expected observation points, generic stage representation, observed and missing evidence, evidence confidence); `5gc-registration-mobility` provides bounded N1/N2 registration and access procedure-stage analysis from already-extracted NGAP/NAS evidence, identifying conditional branches, protocol-defined outcomes, missing evidence, and procedure-local deviations; and `5gc-pdu-session` (v0.3.0) provides bounded 5GC PDU Session Establishment, repeated Modification, and Release lifecycle analysis across N1/N2/N3/N4/N11, composing already-extracted NAS-5GS, NGAP, PFCP, GTP-U, and SBI-HTTP2 evidence with lifecycle generation handling: the same UE context re-using the same numeric PDU Session ID after an evidence-supported release boundary forms a distinct lifecycle generation, and reuse without a proven boundary is preserved as `LIFECYCLE_AMBIGUITY` rather than silently merged or split. Domain Skills do not decode lower-layer protocols and do not produce root-cause conclusions. `5gc-handover-mobility` (v0.1.0) provides bounded 5GC N2 handover and Path Switch Domain analysis from already-extracted NGAP (>=0.3.0 mobility evidence), PFCP, GTP-U, and SBI evidence: separate `handover_attempts` and `path_switch_attempts` families (neither mandatory for the other), evidence-bounded source/target association scoped by capture and AMF-UE-NGAP-ID context with STRONG/SUPPORTED/AMBIGUOUS/UNBOUND strengths and reuse safety, branch-aware conditional stages with missing-evidence visibility, item-scoped PDU Session resource outcomes, bounded N11/N4/N3 supporting evidence associated only through safe session and tunnel context, procedure-local deviations with structured evidence_refs, and bounded HandoverType scope (inter-system types preserved with an explicit scope limitation).

Domain candidates remain broader 5GC mobility (UPF relocation, inter-system and 5GS-EPS mobility semantics, and RAN Status Transfer Domain use), `epc-procedures`; `ims-registration`, `ims-session`, and `ims-media-qos`; plus `5gc-sbi`, `5gc-user-plane`, `5gc-policy`, `5gc-interworking`, and `5gc-roaming-exposure`. These names are plans, not implementations. Domain Skills consume protocol evidence and correlation output; they do not replace protocol decoding or correlation.

Implemented Analysis Orchestration Skills: `5gc-failure-boundary` (v0.2.0) composes already-produced `5gc-registration-mobility`, `5gc-pdu-session`, and `5gc-handover-mobility` Domain analysis JSON into evidence-safe diagnostic groups and identifies the earliest safely orderable abnormal evidence boundary per group. It forms groups only on exact common context, builds candidates only from Domain-emitted deviations and their machine-readable evidence_refs (older Domain output versions without structured provenance are rejected loudly), keeps handover and Path Switch attempts separately addressable, consumes a handover source/target context bridge only when the Handover Domain itself authorized the association as STRONG or SUPPORTED (bridged subject links stay SUPPORTED with structured bridge provenance; association candidates are ambiguity evidence and never join), orders by evidence provenance (never severity; Mobility stage array positions are never treated as chronology), preserves PDU Session lifecycle generations and multi-UE isolation, and carries no root-cause, culprit, vendor, or implementation fields. Deeper diagnosis, root-cause hypothesis reasoning, UPF relocation, and inter-system mobility remain future Orchestration work.

Diameter is deliberately cross-domain: `diameter-core` owns base headers, AVP structure, Vendor-ID, Application-ID, Command-Code, identifiers, and result semantics. `diameter-epc` will own S6a/Gx and EPC-context Gy; `diameter-ims` will own Cx/Dx/Sh/Rx; and `diameter-charging` will own Ro/Gy credit-control semantics shared by EPC and IMS. Diameter is not owned by IMS.

## 5GC interface ownership plan

Implemented Skills appear without annotation; skills marked *(planned)* are not yet implemented.

| Interfaces | Functional grouping | Owners |
| --- | --- | --- |
| N1, N2 | Access signaling and mobility | `nas-5gs`, `ngap`, `5gc-registration-mobility` |
| N3 | RAN-to-UPF user plane | `gtpu`; session-side ownership by `5gc-pdu-session` |
| N4 | SMF-to-UPF control | `pfcp`, `5gc-pdu-session` |
| N5, N7, N15 | Policy control | `5gc-policy` (planned), SBI support |
| N6 | Data-network IP user plane | `5gc-user-plane` (planned) and IP-networking foundation |
| N8, N10, N11, N12, N13, N14 | SBI service interactions | `sbi-http2`; `5gc-sbi` (planned), registration/mobility or session domains |
| N9 | UPF-to-UPF user plane | `gtpu` on N9 (planned expansion); `5gc-user-plane` (planned) |
| N22, N24, N26, N27 | Selection, policy, and interworking | `5gc-policy` (planned), `5gc-interworking` (planned) |
| N32, N33 | Roaming, SEPP, NEF, and exposure | `5gc-roaming-exposure` (planned) |

This grouping deliberately avoids a one-Skill-per-interface model. Specific interface ownership may be refined only without violating the layer direction above.
