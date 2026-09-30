# Architecture

## Purpose and dependency direction

This repository is a modular collection of independently downloadable Skills for future core-network investigation. The repository foundation freezes its boundaries; it implements no protocol analysis or troubleshooting logic.

```text
Foundation Skills → Protocol Skills → Domain / Procedure Skills → Implementation Skills → Orchestration Skills
```

Dependencies flow only to the left. A higher layer may compose lower-layer contracts, but a lower layer must never import, own, or depend on a higher-layer procedure. Circular ownership is prohibited.

## Layers

| Layer | Responsibility | May depend on |
| --- | --- | --- |
| Foundation | Reusable engineering investigation methods. | External standard tooling only |
| Protocol | Message encoding, fields, and protocol-local correlation. | Foundation |
| Domain / procedure | Cross-network-function procedures. | Foundation, Protocol |
| Implementation | Maps behavior to a named implementation. | Foundation, Protocol, Domain |
| Orchestration | Locates an end-to-end failure boundary. | All lower layers |

Examples of permitted ownership: `ims-registration` depends on `sip` and `diameter-ims`; `epc-procedures` depends on `nas-eps`, `s1ap`, and `diameter-epc`; `5gc-pdu-session` depends on `nas-5gs`, `ngap`, `pfcp`, and `sbi-http2`.

Examples of prohibited ownership: `sip` must not depend on `ims-registration`; `diameter-core` must not depend on `diameter-ims`; and `ngap` must not depend on `5gc-registration-mobility`.

## Planned catalog

Foundation candidates are `wireshark-analysis`, `protocol-reverse-engineering`, `network-engineer`, `systematic-debugging`, `linux-troubleshooting`, and `c-pro`. Protocol candidates are `core-network-pcap`, `nas-eps`, `nas-5gs`, `s1ap`, `ngap`, `gtpv2`, `gtpu`, `pfcp`, `sip`, `sdp-rtp`, `diameter-core`, `diameter-epc`, `diameter-ims`, `diameter-charging`, and `sbi-http2`.

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
