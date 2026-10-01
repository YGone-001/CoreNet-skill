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
N1. Version 0.1.0 implements a bounded 5GMM subset of TS 24.501
(Release 19 lineage, verified against the NAS-5GS dissector of
Wireshark/TShark 4.7.1): Registration request/accept/complete/reject,
Identity request/response, Authentication
request/response/reject/failure/result, Security mode
command/complete/reject, Service request/accept/reject, and 5GMM status,
with security-envelope classification (plain, integrity protected,
ciphered, new context), bounded IE normalization (registration type,
follow-on request, ngKSI, identity type, 5GMM cause, selected NAS
algorithms, service type), 5GSM recognition marked DEFERRED, identity
privacy defaults (presence and type only; raw values require an explicit
opt-in), detailed NAS-5GS events, and shared trace-event projection. It
does not decode 5GSM PDU session semantics, does not perform NAS
cryptography, does not model registration state, and does not claim
full-Release NAS coverage.

Planned: `nas-eps`, `s1ap`, `gtpv2`, `gtpu`, `pfcp`, `sip`, `sdp-rtp`,
`diameter-core` and its domain layers, and `sbi-http2`.
