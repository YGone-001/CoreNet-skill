# Protocol Skills

Implemented: `core-network-pcap`, a common capture-ingestion, metadata
classification, and protocol-neutral trace-event normalization package. It does
not implement protocol message semantics or procedure diagnosis.

Implemented: `ngap`, the first telecom signaling-semantic Protocol Skill.
Version 0.2.0 supports a bounded UE-context subset of NGAP over N2:
InitialUEMessage, UplinkNASTransport, DownlinkNASTransport,
InitialContextSetup (request/response/failure), UEContextReleaseRequest,
UEContextRelease (command/complete), and Paging, plus identity-only
handling of ErrorIndication and NASNonDeliveryIndication. It extracts
RAN-UE-NGAP-ID and AMF-UE-NGAP-ID, preserves NGAP Cause category/value,
correlates frames into UE contexts scoped by capture and SCTP association,
and projects detailed events into the shared trace-event schema. Version
0.2.0 adds bounded PDU Session resource evidence: PDU Session Resource
Setup (request/response), Modify (request/response), Release
(command/response), and PDU Session resources embedded in Initial Context
Setup, modelled as an array of resource items with PDU Session ID, list
role, S-NSSAI, NAS-PDU presence, transfer presence/type, bound QFI values,
item Cause, and an explicit binding basis; unsafely bound nested values are
preserved as unbound evidence. It does not decode NAS, does not parse
transfer containers, does not own PFCP/GTP-U/SBI semantics, does not model
PDU Session or registration procedure state, and does not claim
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

Implemented: `pfcp`, the N4 session-control Protocol Skill. Version 0.1.0
supports a bounded PFCP subset of TS 29.244 (Release 19): Heartbeat,
Association Setup, and Session Establishment, Modification and Deletion
request/response, with PFCP header preservation (version, S flag, MP flag,
message type, message length, SEID, sequence number, priority), header
SEID / CP F-SEID / UP F-SEID kept as distinct evidence, bounded PDR/FAR/QER/
URR rule groups with explicit CREATE/UPDATE/REMOVE operations, bounded
F-TEID and Outer Header Creation provisioning metadata, Network Instance,
UE IP Address and QFI evidence, PFCP Cause preservation, and
endpoint-scoped request/response transaction correlation. It does not parse
raw PFCP bytes, does not inspect GTP-U traffic, does not interpret SBI,
does not map a PFCP SEID to a NAS or NGAP PDU Session ID, and does not
determine PDU session or user-plane success.

Implemented: `gtpu`, the N3 user-plane observation Protocol Skill. Version
0.1.0 supports a bounded GTP-U subset of TS 29.281 (Release 19) with the
PDU Session Container content reviewed against TS 38.415 (Release 19):
G-PDU, Echo Request, Echo Response, Error Indication, End Marker and
Supported Extension Headers Notification, with GTP-U header preservation
(version, PT, E/S/PN flags, message type, length, TEID, sequence number,
N-PDU number, next extension header), TEID evidence scoped by directed
outer endpoints, bounded PDU Session Container evidence (PDU type, QFI,
RQI, PPI), extension header arrays, bounded inner packet metadata, and
observed packet/byte stream summaries. It proves only what was observed at
one capture point: it does not claim UE or application delivery, does not
infer packet loss from sequence numbers, does not decode application
payloads, and does not correlate GTP-U TEIDs to PFCP, NGAP or NAS.

Planned: `nas-eps`, `s1ap`, `gtpv2`, `sip`, `sdp-rtp`,
`diameter-core` and its domain layers, and `sbi-http2`.
