# Protocol Skills

Implemented: `core-network-pcap`, a common capture-ingestion, metadata
classification, and protocol-neutral trace-event normalization package. It does
not implement protocol message semantics or procedure diagnosis.

Implemented: `ngap`, the first telecom signaling-semantic Protocol Skill.
Version 0.1.0 supports a bounded UE-context subset of NGAP over N2:
InitialUEMessage, UplinkNASTransport, DownlinkNASTransport,
InitialContextSetup (request/response/failure), UEContextReleaseRequest,
UEContextRelease (command/complete), and Paging, plus identity-only
handling of ErrorIndication and NASNonDeliveryIndication. It extracts
RAN-UE-NGAP-ID and AMF-UE-NGAP-ID, preserves NGAP Cause category/value,
correlates frames into UE contexts scoped by capture and SCTP association,
and projects detailed events into the shared trace-event schema. It does
not decode NAS, does not model 5GC registration, and does not claim
full-Release NGAP coverage.

Implemented: `nas-5gs`, the first user-plane-of-trust Protocol Skill on
N1. Version 0.2.0 implements a bounded 5GMM subset and a bounded 5GSM
subset of TS 24.501 (Release 19, verified against the NAS-5GS dissector
of Wireshark/TShark 4.7.1; extended protocol discriminator per TS 24.007).
The 5GMM subset covers Registration request/accept/complete/reject,
Identity request/response, Authentication
request/response/reject/failure/result, Security mode
command/complete/reject, Service request/accept/reject, and 5GMM status.
The 5GSM subset covers PDU session establishment
request/accept/reject, PDU session modification
request/reject/command/complete/command reject, PDU session release
request/reject/command/complete, and 5GSM status, with bounded
session-management fields (PDU session identity, procedure transaction
identity, request type, PDU session type, SSC mode, DNN, S-NSSAI, PDU
address, bounded QoS presence and QFI/5QI, always-on, EPCO presence).
Both families share security-envelope classification (plain, integrity
protected, ciphered, new context), bounded IE normalization, identity
privacy defaults (presence and type only; raw values require an explicit
opt-in), detailed NAS-5GS events, and shared trace-event projection. It
does not determine PDU session or registration outcomes, does not decode
NGAP PDU session resources, PFCP, GTP-U, or SBI, does not perform NAS
cryptography, and does not claim full-Release NAS coverage.

Planned: `nas-eps`, `s1ap`, `gtpv2`, `gtpu`, `pfcp`, `sip`, `sdp-rtp`,
`diameter-core` and its domain layers, and `sbi-http2`.
