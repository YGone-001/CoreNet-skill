# Architecture

## Purpose and dependency direction

This repository is a modular collection of independently downloadable Skills for core-network investigation. The repository foundation freezes its boundaries; protocol Skills implement bounded protocol-local semantics, and the Correlation layer joins already-extracted protocol evidence.

```text
Foundation Skills → Protocol Skills → Correlation Skills → Domain / Procedure Skills → Implementation Skills → Orchestration Skills
```

Dependencies flow only to the left. A higher layer may compose lower-layer contracts, but a lower layer must never import, own, or depend on a higher-layer procedure. A Skill may depend on the same layer when ownership remains acyclic and semantically correct (for example, `diameter-ims` depending on `diameter-core`). Circular ownership is prohibited.

## Layers

| Layer | Responsibility | May depend on |
| --- | --- | --- |
| Foundation | Reusable engineering investigation methods. | External standard tooling only |
| Protocol | Message encoding, fields, and protocol-local correlation. | Foundation |
| Correlation | Provenance-key joins, deterministic cross-protocol evidence grouping, cross-protocol ordering, correlation-strength classification, and missing-evidence visibility. | Foundation, Protocol |
| Domain / procedure | Cross-network-function telecom procedures; consumes Protocol and Correlation outputs. | Foundation, Protocol, Correlation |
| Implementation | Maps behavior to a named implementation. | Foundation, Protocol, Correlation, Domain |
| Orchestration | Locates an end-to-end failure boundary. | All lower layers |

Examples of permitted ownership: `ims-registration` depends on `sip` and `diameter-ims`; `epc-procedures` depends on `nas-eps`, `s1ap`, and `diameter-epc`; `5gc-pdu-session` depends on `nas-5gs`, `ngap`, `pfcp`, and `sbi-http2`; `cross-protocol-evidence` depends on the `ngap` and `nas-5gs` event contracts; the future `5gc-registration-mobility` depends on `cross-protocol-evidence`, `ngap`, and `nas-5gs`; `diameter-ims` depends on same-layer `diameter-core`.

Examples of prohibited ownership: `sip` must not depend on `ims-registration`; `diameter-core` must not depend on `diameter-ims`; `ngap` must not depend on `5gc-registration-mobility` or on `cross-protocol-evidence`; `cross-protocol-evidence` must not depend on `5gc-registration-mobility`.

## Correlation boundary

Correlation answers: **Which already-extracted evidence items belong to the same observed context or evidence window?**

An allowed Correlation conclusion: "NGAP frame evidence and NAS-5GS evidence share capture_file X and frame_number 42 and therefore form a STRONG provenance join."

Not allowed Correlation conclusions: "5G Registration succeeded." or "Registration failed at Authentication." Those require Domain semantics. The Correlation layer does not decode protocols, does not own procedure success or failure, does not own subscriber or session semantics unless explicitly supplied by a lower contract, and does not own root cause.

Correlation is optional infrastructure for Domain Skills, not a mandatory wrapper: a Domain Skill may consume Correlation outputs, and no Domain Skill is required to route every Protocol Skill through Correlation.

## Implemented catalog

Implemented Protocol Skills: `core-network-pcap` (capture ingestion, dissector classification, protocol-neutral trace-event normalization), `ngap` (bounded UE-context signaling semantics over N2), and `nas-5gs` (bounded 5GMM semantics over N1).

Implemented Correlation Skills: `cross-protocol-evidence` joins already-extracted NGAP and NAS-5GS detailed events into deterministic evidence groups and a unified observed-evidence timeline by shared capture provenance.

Protocol candidates remain `nas-eps`, `s1ap`, `gtpv2`, `gtpu`, `pfcp`, `sip`, `sdp-rtp`, `diameter-core`, `diameter-epc`, `diameter-ims`, `diameter-charging`, and `sbi-http2`. These names are plans, not implementations.

Domain candidates include `epc-procedures`; `ims-registration`, `ims-session`, and `ims-media-qos`; plus `5gc-registration-mobility`, `5gc-pdu-session`, `5gc-sbi`, `5gc-user-plane`, `5gc-policy`, `5gc-interworking`, and `5gc-roaming-exposure`. These names are plans, not implementations.

Diameter is deliberately cross-domain: `diameter-core` owns base headers, AVP structure, Vendor-ID, Application-ID, Command-Code, identifiers, and result semantics. `diameter-epc` will own S6a/Gx and EPC-context Gy; `diameter-ims` will own Cx/Dx/Sh/Rx; and `diameter-charging` will own Ro/Gy credit-control semantics shared by EPC and IMS. Diameter is not owned by IMS.

## 5GC interface ownership plan

| Interfaces | Planned functional grouping | Future owners |
| --- | --- | --- |
| N1, N2 | Access signaling and mobility | `nas-5gs`, `ngap`, `5gc-registration-mobility` |
| N3 | RAN-to-UPF user plane | `gtpu`, `5gc-user-plane` |
| N4 | SMF-to-UPF control | `pfcp`, `5gc-pdu-session` |
| N5, N7, N15 | Policy control | `5gc-policy`, SBI support |
| N6 | Data-network IP user plane | `5gc-user-plane` and IP-networking foundation |
| N8, N10, N11, N12, N13, N14 | SBI service interactions | `sbi-http2`, `5gc-sbi`, registration/mobility or session domains |
| N9 | UPF-to-UPF user plane | `gtpu`, `5gc-user-plane` |
| N22, N24, N26, N27 | Selection, policy, and interworking | `5gc-policy`, `5gc-interworking` |
| N32, N33 | Roaming, SEPP, NEF, and exposure | `5gc-roaming-exposure` |

This grouping deliberately avoids a one-Skill-per-interface model. Specific interface ownership may be refined only without violating the layer direction above.
