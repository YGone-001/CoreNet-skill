# Roadmap

| Milestone | Objective and expected Skills | Dependencies | Entry gate | Exit gate |
| --- | --- | --- | --- | --- |
| Repository Foundation | Freeze architecture, contracts, schemas, template, and validation. | None | Repository baseline inspected. | All acceptance gates pass. |
| Foundation Skills | Accepted reusable investigation-method Skills. | Foundation contracts and source review. | Repository foundation complete. | Six standalone Foundation Skills are accepted and tested. |
| Packet and Protocol Core | `core-network-pcap` capture normalization, a bounded `ngap` UE-context, PDU Session resource, and N2 handover/path-switch mobility semantic Skill, a bounded `nas-5gs` 5GMM and 5GSM semantic Skill, a bounded `pfcp` N4 session-control semantic Skill, a bounded `gtpu` N3 user-plane observation Skill, a bounded `sbi-http2` N11 Nsmf_PDUSession and Namf_Communication N1/N2 delivery observation Skill, a bounded `s1ap` S1-MME semantic Skill, a bounded `nas-eps` EPS NAS semantic Skill, and a bounded `gtpv2` S11/S5-S8 session-control semantic Skill are implemented; remaining protocol semantics (GTP, SIP, RTP, remaining 5GC SBI services, the remaining NGAP mobility-adjacent procedures such as RAN Status Transfer, GTP-U on N9/S1-U/S5-S8-U) remain planned. | Foundation methods. | Approved protocol scope and fixtures. | Protocol-local contracts and evidence tests pass. |
| Correlation Infrastructure | `cross-protocol-evidence` provenance-key correlation is implemented as supporting infrastructure between Protocol evidence and future Domain procedures; Domain Skills may consume it but are never required to route Protocol Skills through it. | Protocol Skills. | Correlation scope and provenance model reviewed. | Correlation-only contract tests pass with no protocol or Domain ownership. |
| Diameter | `diameter-core`, `diameter-epc`, `diameter-ims`, `diameter-charging`. | Protocol conventions. | Cross-domain ownership reviewed. | No IMS ownership leakage; tests pass. |
| IMS | IMS registration, session, and media/QoS domains. | SIP/SDP/RTP and Diameter IMS/charging. | Diameter work complete. | Procedure Skills satisfy evidence contract. |
| EPC | `epc-procedures` v0.5.0 provides bounded EPS Attach procedure evidence from already-extracted S1AP and NAS-EPS events and bounded EPC session-control evidence from already-extracted GTPv2-C events and transactions: frame-anchored UE association, conditional attach stages, bounded S1 context setup and release observations, procedure-local deviations with exact evidence references, protocol outcomes kept separate from correlation status, message and bearer Cause separation, item-scoped bearer and F-TEID evidence, evidence-based S11/S5-S8 hop resolution, and control-plane TEID continuity grouping with generation handling. S11 to S5/S8 and Attach-to-session associations stay `NOT_ESTABLISHED`. Version 0.3.0 adds bounded EPS default-bearer signalling evidence over already-extracted NAS-EPS ESM, S1AP E-RAB and GTPv2-C tunnel-endpoint evidence: PDN connectivity, ESM information exchange, default bearer activation and S1 E-RAB setup stages with explicit `UNAVAILABLE_PROTECTED` handling, typed and frame-anchored ESM negative deviations, and evidence-safe cross-interface links (`ESTABLISHED`/`SUPPORTED`/`AMBIGUOUS`/`NOT_ESTABLISHED`) that never equate an E-RAB identity with an EPS bearer identity. Version 0.4.0 adds bounded S1-U GTP-U packet observation over already-extracted GTP-U events and stream summaries: directed stream evidence, receiving-endpoint matching on outer destination address plus header TEID, `SUPPORTED`/`AMBIGUOUS`/`NOT_ESTABLISHED` association, and observed G-PDU and payload-octet counts without any delivery verdict. Version 0.5.0 adds bounded EPC bearer lifecycle-generation evidence over the accepted GTPv2-C transaction correlation: advertisement-family classification of repeated S1-U F-TEID advertisements, scoped pseudonymous generation references, release boundaries proved only by an accepted release that names the released endpoint, endpoint-reuse observations across a proved boundary, and frame-level GTP-U attribution with conserved packet and octet accounting. Version 0.6.0 adds bounded EPC S11<->S5/S8 session-identity bridge and release-binding evidence: hop-local session contexts joined only by receiver-scoped control-plane F-TEID addressing with its GTP-C path peer, cross-interface endpoint correspondence kept separate from session identity, session identity established only by a relayed PGW S5/S8 control-plane F-TEID that is equal and unique on both hops, release-to-session bindings with separately classified outcomes, and reviewed session-context generation closure consumed by the lifecycle capability through a documented input contract. Complete ESM semantics, dedicated-bearer and PDN-disconnect lifecycle, Diameter EPC and end-to-end delivery verification remain planned. | NAS-EPS, S1AP, GTPv2, GTP-U (implemented); Diameter EPC (planned). | Required dependencies complete. | Reusable protocol dependencies remain independent. |
| Analysis Orchestration | `epc-failure-boundary` v0.2.0 provides per-subject EPC abnormal-boundary selection over accepted EPS Attach, EPC session-control and EPS default-bearer Domain evidence (reviewed ESM rejections only, evidence-quality deviations stay non-selectable): machine-readable candidates from explicit negative deviations, exact-frame ordering, explicit ambiguity and insufficiency, and downstream observations that are ordered but not attributed. It never merges independent Attach, S11 and S5/S8 subjects. `5gc-failure-boundary` provides evidence-safe first abnormal boundary localization across the implemented `5gc-registration-mobility`, `5gc-pdu-session`, and `5gc-handover-mobility` Domain analyses: diagnostic groups linked by exact common context, separately addressable handover and Path Switch attempts with Domain-authorized source/target context bridges, candidates drawn only from Domain-emitted deviations, provenance-based ordering (never severity), and bounded selection statuses. Domain deviations expose machine-readable evidence_refs so Orchestration never parses prose; root-cause reasoning, UPF relocation, inter-system mobility, and deeper diagnosis remain planned. | 5GC Core Procedures. | Domain output contracts reviewed. | Orchestration contract tests pass with no Domain or protocol ownership. |
| 5GC Core Procedures | `5gc-registration-mobility` provides bounded N1/N2 registration and access procedure analysis; `5gc-pdu-session` provides bounded PDU Session Establishment, Modification, and Release lifecycle analysis across N1/N2/N3/N4/N11, including lifecycle generation handling for PDU Session ID reuse after an evidence-supported release boundary; `5gc-handover-mobility` provides bounded N2 handover and Path Switch Domain analysis with separate attempt families, evidence-bounded source/target association, branch-aware stages, and structured deviation provenance; broader mobility work (UPF relocation, inter-system mobility, RAN Status Transfer, Orchestration consumption) remains planned. | NAS-5GS, NGAP, PFCP, GTP-U, SBI; the implemented `cross-protocol-evidence` Correlation Skill provides supporting infrastructure that Domain Skills consume. | Required contracts reviewed. | N1/N2/N3/N4/N11 coverage has tests. |
| Advanced 5GC Interfaces | SBI, policy, interworking, roaming/exposure. | 5GC Core Procedures. | Functional grouping agreed. | Planned N5–N33 ownership is tested. |
| End-to-End Root Cause Analysis | Evidence-safe analysis orchestration. | All applicable lower layers. | Diagnostic-result contract proven. | Failure boundaries and confidence are validated. |

The repository foundation and Foundation Skills are accepted. The
`core-network-pcap` entry capability, the bounded `ngap` UE-context, PDU
Session resource, and N2 handover/path-switch mobility semantic Skill, the bounded `nas-5gs` 5GMM and 5GSM
semantic Skill, the bounded `pfcp` N4 session-control semantic Skill, the
bounded `gtpu` N3 user-plane observation Skill, the bounded `sbi-http2`
N11 Nsmf_PDUSession and Namf_Communication N1/N2 delivery observation Skill, and the
`cross-protocol-evidence` Correlation Skill are implemented as supporting
infrastructure between Protocol evidence and future Domain procedures. The
`procedure-evidence` Domain framework (generic stage and evidence model), the
bounded `5gc-registration-mobility` N1/N2 procedure analysis Skill, and the
bounded `5gc-pdu-session` Establishment, Modification, and Release analysis Skill are implemented.
All five primary evidence planes (N1, N2, N3, N4, N11) required for
PDU Session domain analysis are composed by `5gc-pdu-session` for
bounded PDU Session Establishment, repeated Modification, and Release lifecycle analysis;
the bounded `5gc-handover-mobility` N2 handover and Path Switch Domain analysis Skill is implemented;
`5gc-failure-boundary` v0.2.0 composes the implemented Registration, PDU Session,
and Handover/Path Switch Mobility Domain outputs;
the remaining NGAP mobility-adjacent procedures, UPF relocation, inter-system
mobility, GTP-U on further interfaces, and every later capability remain future work.
GTP-U v0.1.0 proves packet observations at the capture point only, never
end-to-end user-plane validation. The bounded `s1ap`, `nas-eps` and `gtpv2` Protocol Skills
extract S1-MME, EPS NAS and GTPv2-C session-control message evidence from LTE captures,
and the bounded `epc-procedures` Domain Skill analyzes observed EPS Attach procedure
stages and bounded GTPv2-C session-control transactions through the unified
workflow, and the `epc-failure-boundary` Orchestration Skill selects the earliest supported
abnormal observation per EPC diagnostic subject; complete ESM semantics, dedicated-bearer and
PDN-disconnect lifecycle, safe general-purpose Attach/S11/S5-C identity linking, Diameter EPC
and EPC user-plane verification remain future work. Implementation-specific Skills are not
planned: external implementation analysis is performed only when users provide
implementation evidence. The empirical Golden Capture Differential Benchmark
(`benchmarks/golden-captures/`) is implemented outside the Skill architecture,
providing empirical evaluation across public 5GC signaling captures without
claiming full procedure coverage or end-to-end root-cause isolation. Public
capture differential framework implemented; the frozen corpus run reports
healthy relevant Protocol extraction on all thirteen captures and localizes the
remaining gaps to the Domain layer, whose input contract rejects NGAP records
for procedures outside bounded NGAP ownership, and to procedure families no
implemented Domain owns. One capture exercises the complete Protocol,
Correlation, Domain and Orchestration chain. The unified
`scripts/corenet-analyze.py` analysis workflow is implemented as an
application-level entry point outside the Skill layers: it executes that accepted
5GC chain for a capture, executes the bounded EPC EPS Attach path over the accepted
S1AP and NAS-EPS Protocol Skills, and reports IMS as an unsupported capability until
its Protocol and Domain Skills exist.
