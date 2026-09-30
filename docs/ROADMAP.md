# Roadmap

| Milestone | Objective and expected Skills | Dependencies | Entry gate | Exit gate |
| --- | --- | --- | --- | --- |
| Repository Foundation | Freeze architecture, contracts, schemas, template, and validation. | None | Repository baseline inspected. | All acceptance gates pass. |
| Foundation Skills | Create reusable investigation-method Skills. | Foundation contracts and source review. | Repository foundation complete. | Each foundation Skill is standalone and tested. |
| Packet and Protocol Core | `core-network-pcap`, NAS, S1AP, NGAP, GTP, PFCP, SIP, RTP, and SBI foundations. | Foundation methods. | Approved protocol scope and fixtures. | Protocol-local contracts and evidence tests pass. |
| Diameter | `diameter-core`, `diameter-epc`, `diameter-ims`, `diameter-charging`. | Protocol conventions. | Cross-domain ownership reviewed. | No IMS ownership leakage; tests pass. |
| IMS | IMS registration, session, and media/QoS domains. | SIP/SDP/RTP and Diameter IMS/charging. | Diameter work complete. | Procedure Skills satisfy evidence contract. |
| EPC | `epc-procedures` and related domain work. | NAS-EPS, S1AP, GTPv2, Diameter EPC. | Required dependencies complete. | Reusable protocol dependencies remain independent. |
| 5GC Core Procedures | Registration/mobility and PDU session Skills. | NAS-5GS, NGAP, PFCP, GTP-U, SBI. | Required contracts reviewed. | N1/N2/N3/N4/N11 coverage has tests. |
| Advanced 5GC Interfaces | SBI, policy, interworking, roaming/exposure. | 5GC Core Procedures. | Functional grouping agreed. | Planned N5–N33 ownership is tested. |
| Implementation Awareness | Core network service function development mappings. | Stable protocol and domain Skills. | Implementation provenance approved. | Mappings cite exact supported versions/source evidence. |
| End-to-End Root Cause Analysis | Evidence-safe orchestration. | All applicable lower layers. | Diagnostic-result contract proven. | Failure boundaries and confidence are validated. |

Only the repository foundation is implemented by this repository state.
