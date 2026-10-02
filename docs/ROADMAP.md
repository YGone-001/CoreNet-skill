# Roadmap

| Milestone | Objective and expected Skills | Dependencies | Entry gate | Exit gate |
| --- | --- | --- | --- | --- |
| Repository Foundation | Freeze architecture, contracts, schemas, template, and validation. | None | Repository baseline inspected. | All acceptance gates pass. |
| Foundation Skills | Accepted reusable investigation-method Skills. | Foundation contracts and source review. | Repository foundation complete. | Six standalone Foundation Skills are accepted and tested. |
| Packet and Protocol Core | `core-network-pcap` capture normalization, a bounded `ngap` UE-context and PDU Session resource semantic Skill, a bounded `nas-5gs` 5GMM and 5GSM semantic Skill, and a bounded `pfcp` N4 session-control semantic Skill are implemented; remaining protocol semantics (NAS-EPS, S1AP, GTP, SIP, RTP, SBI, NGAP handover and path-switch coverage) remain planned. | Foundation methods. | Approved protocol scope and fixtures. | Protocol-local contracts and evidence tests pass. |
| Correlation Infrastructure | `cross-protocol-evidence` provenance-key correlation is implemented as supporting infrastructure between Protocol evidence and future Domain procedures; Domain Skills may consume it but are never required to route Protocol Skills through it. | Protocol Skills. | Correlation scope and provenance model reviewed. | Correlation-only contract tests pass with no protocol or Domain ownership. |
| Diameter | `diameter-core`, `diameter-epc`, `diameter-ims`, `diameter-charging`. | Protocol conventions. | Cross-domain ownership reviewed. | No IMS ownership leakage; tests pass. |
| IMS | IMS registration, session, and media/QoS domains. | SIP/SDP/RTP and Diameter IMS/charging. | Diameter work complete. | Procedure Skills satisfy evidence contract. |
| EPC | `epc-procedures` and related domain work. | NAS-EPS, S1AP, GTPv2, Diameter EPC. | Required dependencies complete. | Reusable protocol dependencies remain independent. |
| 5GC Core Procedures | `5gc-registration-mobility` provides bounded N1/N2 registration and access procedure analysis; PDU session and broader mobility work remain planned. | NAS-5GS, NGAP, PFCP, GTP-U, SBI; the implemented `cross-protocol-evidence` Correlation Skill provides supporting infrastructure that the bounded registration/mobility Skill consumes. | Required contracts reviewed. | N1/N2/N3/N4/N11 coverage has tests. |
| Advanced 5GC Interfaces | SBI, policy, interworking, roaming/exposure. | 5GC Core Procedures. | Functional grouping agreed. | Planned N5–N33 ownership is tested. |
| End-to-End Root Cause Analysis | Evidence-safe analysis orchestration. | All applicable lower layers. | Diagnostic-result contract proven. | Failure boundaries and confidence are validated. |

The repository foundation and Foundation Skills are accepted. The
`core-network-pcap` entry capability, the bounded `ngap` UE-context and PDU
Session resource semantic Skill, the bounded `nas-5gs` 5GMM and 5GSM
semantic Skill, the bounded `pfcp` N4 session-control semantic Skill, and
the `cross-protocol-evidence` Correlation Skill are implemented as
supporting infrastructure between Protocol evidence and future Domain
procedures. The `procedure-evidence` Domain framework (generic stage and
evidence model) and the bounded `5gc-registration-mobility` N1/N2
procedure analysis Skill are implemented. Bounded N1 session-management
evidence, bounded N2 PDU Session resource evidence, and bounded N4 PFCP
session-control evidence now exist, but composing them into an end-to-end
PDU Session view still requires GTP-U/N3 and SBI/N11 evidence, so
`5gc-pdu-session` and complete PDU session analysis remain future work, as
do full NGAP mobility, the handover and path-switch procedures, and every
later capability. Implementation-specific Skills are not planned: external
implementation analysis is performed only when users provide implementation
evidence.
