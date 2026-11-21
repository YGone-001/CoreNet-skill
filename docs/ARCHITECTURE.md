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

Examples of permitted ownership: `ims-registration` depends on `sip` and `diameter-ims`; `ims-session` depends on `sip`; `ims-media-signaling` depends on `sip` and `sdp-rtp` with a same-layer `ims-session` dependency; `sdp-rtp-transport` depends on `sdp-rtp`; same-layer `rtp-stream` depends on `sdp-rtp`; `ims-media-session` depends on `ims-session`, `ims-media-signaling`, `sdp-rtp` and `sdp-rtp-transport`; `epc-procedures` depends on `nas-eps`, `s1ap`, `gtpv2`, and `diameter-epc`, and `epc-failure-boundary` depends on `epc-procedures`; `5gc-pdu-session` depends on `nas-5gs`, `ngap`, `pfcp`, `gtpu`, and `sbi-http2`; `cross-protocol-evidence` depends on the `ngap` and `nas-5gs` event contracts; `5gc-registration-mobility` depends on `cross-protocol-evidence`, `ngap`, and `nas-5gs`; `diameter-ims` depends on same-layer `diameter-core`.

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

Implemented Protocol Skills: `core-network-pcap` (capture ingestion, dissector classification, protocol-neutral trace-event normalization), `diameter-core` (bounded Diameter base-protocol header, AVP, result-namespace and protocol-local Request/Answer evidence over TCP and SCTP, with privacy-safe sensitive-AVP handling and no application procedure semantics), `diameter-epc` (bounded S6a/S6d AIR/AIA authentication-information presence and ULR/ULA message/result evidence over accepted `diameter-core` outputs, without EPS Attach or UE-authentication verdicts), `diameter-ims` (bounded Cx/Dx UAR/UAA, SAR/SAA, LIR/LIA, MAR/MAA, RTR/RTA and PPR/PPA application-message evidence over accepted `diameter-core` outputs, with reviewed AVP presence and decoder-proven grouped structure, separate base and 3GPP experimental result namespaces, and `UNPROVED` Cx/Dx interface identity, without IMS registration or authentication verdicts), `sdp-rtp` (bounded RFC 8866 SDP structural parsing of explicitly supplied bodies, with GTP-encapsulated RTP/RTCP inner UDP endpoint extraction when the decoder exposes exactly one unambiguous non-GTP-U transport pair, with optional capture-scoped keyed HMAC endpoint references for SDP media transport endpoints and, in the RTP/RTCP producer, for observed UDP source/destination endpoints when a local key is supplied: session/media scopes, origin/name/connection/timing/media structure, rtpmap/fmtp/direction/mid/rtcp/rtcp-mux/BUNDLE evidence, unknown-attribute preservation, privacy-safe address and sensitive-attribute classification, deterministic fail-closed parsing; plus bounded RFC 3550 RTP version 2 and RTCP SR/RR/SDES/BYE packet evidence from structured JSONL or an authorized TShark capture, with tri-state mandatory RTP flags (missing is not false), two-bit version validation, type-specific SR/RR report counts and SDES/BYE source counts, compound component ordering, nested receiver-report blocks, signed cumulative loss, privacy-safe capture basenames and payload/identity redaction, but no stream reconstruction, local loss/jitter, MOS, Offer/Answer, SIP association or IMS media verdict), `sip` (bounded SIP request/response message extraction and protocol-local RFC 3261 transaction correlation over UDP and TCP, plus capture-scoped dialog identity and Early and Confirmed Dialog evidence with forking isolation, 2xx ACK association, in-dialog request association, direction-specific CSeq observation and BYE lifecycle signaling, including IPv4/IPv6, decoder-delivered TCP reassembly metadata, reviewed header presence/length, completeness and truncation classification, CANCEL and ACK roles, and privacy-safe redaction of identities, URIs, tags, credentials and bodies, without IMS procedure semantics), `ngap` (bounded UE-context signaling semantics over N2, including the PDU Session Resource setup/modify/release subset, resources embedded in Initial Context Setup, and the bounded N2 handover/path-switch mobility subset with bounded mobility metadata and item-scoped resource-list roles), `nas-5gs` (bounded 5GMM registration/identity/authentication/security-mode/service/status semantics and bounded 5GSM PDU session establishment/modification/release/status semantics over N1), `pfcp` (bounded N4 session-control semantics: Heartbeat, Association Setup, and Session Establishment/Modification/Deletion with header SEID and CP/UP F-SEID evidence, bounded PDR/FAR/QER/URR rule groups, PFCP Cause, and endpoint-scoped transaction correlation), `gtpu` (bounded user-plane observation semantics: G-PDU, Echo, Error Indication, End Marker with TEID evidence scoped by directed outer endpoints, bounded PDU Session Container/QFI evidence, and caller-declared N3/S1-U/S5-S8-U/N9 applicability that is never inferred from a UDP port), and `sbi-http2` (bounded N11 Nsmf_PDUSession and Namf_Communication semantics with HTTP/2 stream isolation scoped by connection context, transfer reference tracking, and deterministic callback correlation), and `rtp-stream` (bounded RTP source-stream reconstruction and RFC 3550 Appendix A.1 sequence-integrity evidence over accepted `rtp-rtcp` artifacts: capture-scoped UDP-stream and SSRC grouping, probation and validated sequence state, epoch-local extended sequence numbers, wrap, duplicate, out-of-order, unobserved sequence-number slot and restart-pattern evidence, complete assigned/unassigned packet accounting, optional pseudonymous endpoint preservation, and RTCP counts with no stream association, packet-loss, jitter, MOS, QoS, media-delivery or call verdict).

Implemented Correlation Skills: `cross-protocol-evidence` joins already-extracted protocol detailed events into deterministic evidence groups and a unified observed-evidence timeline by shared capture provenance. `sdp-rtp-transport` (v0.1.0) joins accepted SDP media transport endpoints with observed RTP UDP streams by exact capture-scoped HMAC endpoint equality, preserving source/destination match direction, resolved BUNDLE shared transport, bidirectional mirror-pair matching, conflict-stream exclusion, mixed endpoint-coverage limitations, multiple-candidate ambiguity and missing-evidence visibility without decoding SDP, RTP, PCAP, SIP or IMS sessions. Correlation is optional infrastructure for Domain Skills, not a mandatory wrapper; the intended future direction is `SDP/RTP Protocol -> SDP/RTP Transport Correlation -> Future IMS Media Session Domain` with no reverse dependency.

## RTP source-stream evidence

```text
RTP/RTCP Packet Extraction
          |
       sdp-rtp
          |
      rtp-stream
          |
  RTP Source Stream Evidence
          |
  Future Correlation / Domain
```

This is a Protocol-layer composition. `sdp-rtp` owns packet extraction;
`rtp-stream` owns deterministic source-stream grouping, RFC 3550 Appendix A.1
sequence validation and sequence-integrity evidence. It publishes no network
packet-loss, jitter, MOS, QoS, media-delivery, call or IMS verdict, and the
existing `sdp-rtp` packet extraction contract remains unchanged. SDP-to-RTP and
RTCP-to-RTP association remain outside this boundary.

## Offline IMS media workflow

```text
SIP Events -> SIP Transactions/Dialogs -> IMS Session
             -> private SDP extraction adapter -> SDP Analysis
             -> IMS Media Signaling
             -> RTP/RTCP Analysis -> RTP Source Streams
             -> SDP/RTP Transport Correlation
             -> IMS Media Session
             -> unified machine-readable and text reports
```

`scripts/corenet-analyze.py --with-media --offline` is an application-level
composition outside the Skill layers. It owns no protocol or Domain semantics; it
executes the accepted Skills in dependency order and keeps every stage independent.
A failed RTP stage never erases valid SIP or SDP evidence, and a failed association
never erases independent SDP and RTP results. Overall `COMPLETED` is never published
when a requested media stage was skipped; the media result is reported separately as
`SUCCESS`, `PARTIAL`, `INSUFFICIENT_EVIDENCE`, `UNSUPPORTED` or `FAILED`.

The private SDP extraction adapter reuses the accepted SIP decoder and SDP parser.
It retains raw bodies only in memory, binds each SDP message to the exact accepted SIP
Event source reference, capture identity, frame and occurrence, and publishes only
SDP Analysis. Raw SIP/SDP bodies are never written as reusable artifacts or included
in reports. One capture-scoped owner-only HMAC key is provided by the orchestration
layer to both SDP and RTP processing, so endpoint references are comparable without
exposing key material.

The public real-capture corpus provenance is retained in the local acceptance
artifacts; raw captures remain in a private local directory and are never uploaded to
CI. The offline mode asserts that interpretation needs no
external network service. TShark remains only the local dissector.


Planned protocol work remains: RTP media QoS analysis, `diameter-charging`, and the Diameter IMS Sh/Rx applications; broader SBI service semantics beyond the bounded Nsmf_PDUSession and Namf_Communication subset; and the remaining NGAP mobility-adjacent procedures (RAN Status Transfer and similar). These names are plans, not implementations.

The unified EPC entry point integrates the accepted dedicated-bearer control-plane
Domain producer when the correlated GTPv2-C transactions contain Create, Update or
Delete Bearer procedures. The producer remains the owner of transaction and item
semantics; the entry point publishes only a bounded summary, gates execution on
relevant transactions, reports `NOT_OBSERVED_IN_CAPTURE` when none exist, and
propagates producer failure to the domain execution status. The EPC Evidence Review
Pack consumes the same artifact as an optional bounded source, preserving its hash,
completeness and original references without recomputing outcomes. Both consumers
validate the complete accepted Domain artifact contract before publication and keep
producer-declared totals, producer-published counts and Review-display counts
separate; neither layer infers end-to-end dedicated-bearer activation or an EPC
lifecycle conclusion. The Review Pack's navigation index registers real source
objects from the accepted EPC artifacts, including narrative subjects, narrative
groups and nested bearer endpoints, and resolves Audit Subject references only by
capture-scoped source ownership and explicit object identity. Relationship
mentions, missing objects, source omission, missing optional artifacts,
cross-capture collisions and accounting labels remain explicit classifications.
The cross-layer timeline consumes the accepted control artifact plus optional NAS-EPS
and S1AP events and publishes frame-anchored control entries with bounded NAS-ESM
and S1AP E-RAB references. Associations require capture-scoped shared UE-context
evidence; a control-plane Cause, a bearer identity, an E-RAB identifier or temporal
proximity never establishes UE acceptance, radio setup or user-plane delivery. An
S1AP relationship requires a matching valid E-RAB item identity and a complete
request/completion pair. The overall three-plane status requires both NAS and S1AP
layers; a single proven layer remains explicitly partial. Upstream source
completeness is preserved and mixed-capture control artifacts are rejected. The
optional attribution artifact applies the accepted receiver-scoped control-plane
rule to established hop-local contexts, verifies NAS ownership only through an
observed S1AP enclosure with an embedded NAS-PDU, and reports bearer endpoint
equality as correspondence only. It never converts TEID, EBI/E-RAB ID, QCI, timing
or a single observed UE context into a UE identity bridge.

Implemented Domain capabilities: `procedure-evidence` defines the common evidence model (expected observation points, generic stage representation, observed and missing evidence, evidence confidence); `5gc-registration-mobility` provides bounded N1/N2 registration and access procedure-stage analysis from already-extracted NGAP/NAS evidence, identifying conditional branches, protocol-defined outcomes, missing evidence, and procedure-local deviations; and `5gc-pdu-session` (v0.4.0) provides bounded 5GC PDU Session Establishment, repeated Modification, and Release lifecycle analysis across N1/N2/N3/N4/N11, composing already-extracted NAS-5GS, NGAP, PFCP, GTP-U, and SBI-HTTP2 evidence with lifecycle generation handling: the same UE context re-using the same numeric PDU Session ID after an evidence-supported release boundary forms a distinct lifecycle generation, and reuse without a proven boundary is preserved as `LIFECYCLE_AMBIGUITY` rather than silently merged or split. Domain Skills do not decode lower-layer protocols and do not produce root-cause conclusions. `5gc-handover-mobility` (v0.1.0) provides bounded 5GC N2 handover and Path Switch Domain analysis from already-extracted NGAP (>=0.3.0 mobility evidence), PFCP, GTP-U, and SBI evidence: separate `handover_attempts` and `path_switch_attempts` families (neither mandatory for the other), evidence-bounded source/target association scoped by capture and AMF-UE-NGAP-ID context with STRONG/SUPPORTED/AMBIGUOUS/UNBOUND strengths and reuse safety, branch-aware conditional stages with missing-evidence visibility, item-scoped PDU Session resource outcomes, bounded N11/N4/N3 supporting evidence associated only through safe session and tunnel context, procedure-local deviations with structured evidence_refs, and bounded HandoverType scope (inter-system types preserved with an explicit scope limitation). `epc-procedures` (v0.1.0) provides bounded EPS Attach procedure evidence from already-extracted S1AP and NAS-EPS events: frame-anchored NAS-to-S1AP UE association, conditional attach, identity, authentication, security mode control, decision, completion, S1 context setup and context release stages, procedure-local deviations with machine-readable evidence references, and explicit protected-envelope and partial-capture limitations. Version 0.2.0 adds bounded EPC session-control analysis over already-extracted GTPv2-C events and transactions: protocol outcomes kept separate from correlation status, message-scope and bearer-scope Cause separation, item-scoped bearer context and F-TEID evidence, evidence-based S11 and S5/S8 hop resolution, control-plane TEID continuity grouping with generation handling, and explicit `NOT_ESTABLISHED` cross-interface and Attach associations. Version 0.3.0 adds bounded EPS default-bearer signalling evidence from already-extracted NAS-EPS ESM messages, S1AP E-RAB items and GTPv2-C S1-U tunnel endpoints: PDN connectivity, ESM information exchange, default bearer activation and S1 E-RAB setup stages with `UNAVAILABLE_PROTECTED` handling, typed and frame-anchored ESM negative deviations, and evidence-safe cross-interface links. It produces no bearer, PDN or service verdict, and no global EPC first-abnormal boundary; per-subject EPC boundary selection is provided by `epc-failure-boundary`, which consumes the Attach and session-control analyses. `ims-registration` (v0.1.0) provides bounded IMS registration procedure evidence from already-extracted SIP REGISTER transactions and optional independent Diameter IMS Cx/Dx observations: evidence-gated registration-attempt grouping over capture-local Call-ID, Request-URI, From identity and CSeq evidence, 401/407 challenge and authorized-retry observation, initial/re-registration/refresh and de-registration classification, Expires/Contact expiry/wildcard evidence, negative SIP outcome classification without timeout inference, multi-hop candidates with unproved forwarding, independent Cx/Dx inventory, fail-closed cross-protocol association without a subscriber identity bridge, and a capture-scoped timeline. It produces no IMS session, media, authentication-verification, registration-persistence or root-cause verdict. `ims-session` (v0.1.0) provides bounded IMS session establishment and release signaling evidence over accepted SIP Event, Transaction and Dialog artifacts: initial INVITE attempt anchoring, 100/180/183/final response stages, independent Early and Confirmed Dialog branches with fork isolation, separate 2xx and non-2xx ACK evidence, CANCEL request/response/association and INVITE final-response observations, BYE release signaling, bounded unbound and in-dialog observations, and fail-closed missing or contradictory evidence. It produces no call-success, media-delivery, RTP, QoS or session-modification verdict. The application-level `scripts/corenet-analyze.py` workflow composes the accepted 5GC, EPC and IMS components; its IMS adapter executes the accepted SIP extractor, optional Diameter Core/Cx-Dx path, IMS Registration and IMS Session analysis without acquiring protocol or procedure semantics, and keeps those evidence inventories independent. `ims-media-signaling` (v0.3.0) provides bounded IMS SDP Offer/Answer signaling evidence by associating accepted SIP session attempts and independent dialog branches with independently parsed SDP messages: exact capture-scoped SIP Event source-reference equality with frame and message-occurrence checks, internal SDP provenance validation, initial SDP state separation between proven absence and unusable evidence, accepted Dialog and branch identity gating, historical Offer/Answer evidence preserved when an accepted BYE/2xx terminates a previously confirmed Dialog, initial INVITE offer evidence, branch-scoped final 2xx answer evidence, forked-branch isolation, bounded RFC 3261 late-offer and 2xx ACK answer evidence, provisional SDP preserved as uninterpreted with an unresolved final-answer role, SIP response-role and INVITE CSeq validation, PRACK/re-INVITE/UPDATE/INFO SDP preserved as out of scope, and conservation-checked unbound, incomplete and ambiguous observations. It decodes no SIP, re-parses no SDP, evaluates no negotiation compatibility, and produces no media-delivery, QoS or call-success verdict. It is a standalone Domain over accepted artifacts and is not executed by the unified workflow in this phase. `ims-media-session` (v0.1.0) composes accepted IMS Session, IMS Media Signaling, SDP Analysis and SDP/RTP Transport Correlation artifacts into branch-scoped media transport evidence: strict four-artifact provenance and SHA-256 verification, attempt and independent forked Dialog Branch ownership, shared attempt-level initial-offer evidence published once, branch-scoped Offer/Answer observation references, exact SDP message plus media-section binding with MID and media metadata, preservation of original correlation status/strength/type and source/destination direction, indivisible Correlation records with multi-owner ambiguity preservation, resolved BUNDLE shared transport without MID demultiplexing, unmatched RTP stream and unbound signaling inventories, historical Dialog termination context, and mandatory `NOT_EVALUATED` temporal association. It decodes no SIP/RTP, parses no SDP, reads no capture or key, and produces no media-delivery, QoS, codec or call-success verdict. The intended composition direction is `IMS Session -> IMS Media Signaling -> SDP/RTP Protocol -> SDP/RTP Transport Correlation -> IMS Media Session -> Future Analysis`, with no reverse dependency.

Domain candidates remain broader 5GC mobility (UPF relocation, inter-system and 5GS-EPS mobility semantics, and RAN Status Transfer Domain use); `ims-media-qos`; plus `5gc-sbi`, `5gc-user-plane`, `5gc-policy`, `5gc-interworking`, and `5gc-roaming-exposure`. These names are plans, not implementations. Domain Skills consume protocol evidence and correlation output; they do not replace protocol decoding or correlation.

Implemented Analysis Orchestration Skills: `5gc-failure-boundary` (v0.2.0) composes already-produced `5gc-registration-mobility`, `5gc-pdu-session`, and `5gc-handover-mobility` Domain analysis JSON into evidence-safe diagnostic groups and identifies the earliest safely orderable abnormal evidence boundary per group. It forms groups only on exact common context, builds candidates only from Domain-emitted deviations and their machine-readable evidence_refs (older Domain output versions without structured provenance are rejected loudly), keeps handover and Path Switch attempts separately addressable, consumes a handover source/target context bridge only when the Handover Domain itself authorized the association as STRONG or SUPPORTED (bridged subject links stay SUPPORTED with structured bridge provenance; association candidates are ambiguity evidence and never join), orders by evidence provenance (never severity; Mobility stage array positions are never treated as chronology), preserves PDU Session lifecycle generations and multi-UE isolation, and carries no root-cause, culprit, vendor, or implementation fields. Deeper diagnosis, root-cause hypothesis reasoning, UPF relocation, and inter-system mobility remain future Orchestration work.

The application-level `scripts/ims_call_diagnostics.py` layer is not a Skill and owns no protocol or procedure semantics. It consumes accepted SIP, IMS Session, IMS Media Signaling, SDP, RTP/RTCP, RTP source-stream and SDP/RTP transport-correlation artifacts. It groups initial INVITE attempts only through capture-SHA-scoped SIP identity references, a confirmed INVITE and CSeq method, valid CSeq, a single coherent nested Via stack and, for differing CSeq values, an accepted Dialog bridge. It claims `LOGICAL_CALL_MEDIA_OWNED` only through an accepted ESTABLISHED Offer/Answer Exchange, references inside the accepted logical-call context, a matched transport correlation and uniquely owned source streams. RTCP call ownership is a separate fail-closed gate, and `MULTI_VANTAGE_SUPPORTED` requires byte-identical packets in the same source stream with a compatible inner transport path and differing capture views. Each logical call publishes an ordered evidence review that keeps SIP negative outcomes, normal cancellation, authentication challenges, forked-branch outcomes, procedure contradictions, protocol violations, missing observations, capture-visibility limitations, unsupported procedures, extraction failures, identity ambiguity and no-abnormality boundaries distinct. A negative SIP response is never relabelled as a protocol violation or network-function failure, and an absent response is never a locally inferred timeout. The layer also exposes a bounded REGISTER challenge/retry review from the accepted Registration Domain and an explicit SIP-only versus IMS-attribution status. It produces no call-success, media-delivery, packet-loss, QoS, MOS or root-cause verdict.

Diameter is deliberately cross-domain: `diameter-core` owns base headers, AVP structure, Vendor-ID, Application-ID, Command-Code, identifiers, and result semantics. `diameter-epc` owns S6a/S6d application evidence; `diameter-ims` owns Cx/Dx application evidence, with Sh and Rx applications remaining planned; and `diameter-charging` will own Ro/Gy credit-control semantics shared by EPC and IMS. Diameter is not owned by IMS.

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
| N9 | UPF-to-UPF user plane | `gtpu` with a declared N9 label; `5gc-user-plane` (planned) |
| N22, N24, N26, N27 | Selection, policy, and interworking | `5gc-policy` (planned), `5gc-interworking` (planned) |
| N32, N33 | Roaming, SEPP, NEF, and exposure | `5gc-roaming-exposure` (planned) |

This grouping deliberately avoids a one-Skill-per-interface model. Specific interface ownership may be refined only without violating the layer direction above.
