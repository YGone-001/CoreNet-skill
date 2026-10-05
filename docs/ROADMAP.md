# Roadmap

| Milestone | Objective and expected Skills | Dependencies | Entry gate | Exit gate |
| --- | --- | --- | --- | --- |
| Repository Foundation | Freeze architecture, contracts, schemas, template, and validation. | None | Repository baseline inspected. | All acceptance gates pass. |
| Foundation Skills | Accepted reusable investigation-method Skills. | Foundation contracts and source review. | Repository foundation complete. | Six standalone Foundation Skills are accepted and tested. |
| Packet and Protocol Core | `core-network-pcap` capture normalization, a bounded `ngap` UE-context, PDU Session resource, and N2 handover/path-switch mobility semantic Skill, a bounded `nas-5gs` 5GMM and 5GSM semantic Skill, a bounded `pfcp` N4 session-control semantic Skill, a bounded `gtpu` N3 user-plane observation Skill, and a bounded `sbi-http2` N11 Nsmf_PDUSession and Namf_Communication N1/N2 delivery observation Skill are implemented; remaining protocol semantics (NAS-EPS, S1AP, GTP, SIP, RTP, remaining 5GC SBI services, the remaining NGAP mobility-adjacent procedures such as RAN Status Transfer, GTP-U on N9/S1-U/S5-S8-U) remain planned. | Foundation methods. | Approved protocol scope and fixtures. | Protocol-local contracts and evidence tests pass. |
| Correlation Infrastructure | `cross-protocol-evidence` provenance-key correlation is implemented as supporting infrastructure between Protocol evidence and future Domain procedures; Domain Skills may consume it but are never required to route Protocol Skills through it. | Protocol Skills. | Correlation scope and provenance model reviewed. | Correlation-only contract tests pass with no protocol or Domain ownership. |
| Diameter | `diameter-core`, `diameter-epc`, `diameter-ims`, `diameter-charging`. | Protocol conventions. | Cross-domain ownership reviewed. | No IMS ownership leakage; tests pass. |
| IMS | IMS registration, session, and media/QoS domains. | SIP/SDP/RTP and Diameter IMS/charging. | Diameter work complete. | Procedure Skills satisfy evidence contract. |
| EPC | `epc-procedures` and related domain work. | NAS-EPS, S1AP, GTPv2, Diameter EPC. | Required dependencies complete. | Reusable protocol dependencies remain independent. |
| Analysis Orchestration | `5gc-failure-boundary` provides evidence-safe first abnormal boundary localization across the implemented `5gc-registration-mobility` and `5gc-pdu-session` Domain analyses: diagnostic groups linked by exact common context, candidates drawn only from Domain-emitted deviations, provenance-based ordering (never severity), and bounded selection statuses. Domain deviations expose machine-readable evidence_refs so Orchestration never parses prose; root-cause reasoning, additional Domain coverage, and deeper diagnosis remain planned. | 5GC Core Procedures. | Domain output contracts reviewed. | Orchestration contract tests pass with no Domain or protocol ownership. |
| 5GC Core Procedures | `5gc-registration-mobility` provides bounded N1/N2 registration and access procedure analysis; `5gc-pdu-session` provides bounded PDU Session Establishment, Modification, and Release lifecycle analysis across N1/N2/N3/N4/N11, including lifecycle generation handling for PDU Session ID reuse after an evidence-supported release boundary; broader mobility work (handover, path switch, UPF relocation) remains planned. | NAS-5GS, NGAP, PFCP, GTP-U, SBI; the implemented `cross-protocol-evidence` Correlation Skill provides supporting infrastructure that Domain Skills consume. | Required contracts reviewed. | N1/N2/N3/N4/N11 coverage has tests. |
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
the remaining NGAP mobility-adjacent procedures, a Handover/Path-Switch
Domain Skill, GTP-U on further interfaces, and every later capability remain future work.
GTP-U v0.1.0 proves packet observations at the capture point only, never
end-to-end user-plane validation. Implementation-specific Skills are not
planned: external implementation analysis is performed only when users provide
implementation evidence.
