# Protocol Skills

Implemented: `core-network-pcap`, a common capture-ingestion, metadata
classification, and protocol-neutral trace-event normalization package. It does
not implement protocol message semantics or procedure diagnosis.

Implemented: `ngap`, the first telecom signaling-semantic Protocol Skill.
Version 0.3.0 supports a bounded UE-context subset of NGAP over N2:
InitialUEMessage, UplinkNASTransport, DownlinkNASTransport,
InitialContextSetup (request/response/failure), UEContextReleaseRequest,
UEContextRelease (command/complete), and Paging, plus identity-only
handling of ErrorIndication and NASNonDeliveryIndication. It extracts
RAN-UE-NGAP-ID and AMF-UE-NGAP-ID, preserves NGAP Cause category/value,
correlates frames into UE contexts scoped by capture and SCTP association,
and projects detailed events into the shared trace-event schema. It
supports bounded PDU Session resource evidence: PDU Session Resource
Setup (request/response), Modify (request/response), Release
(command/response), and PDU Session resources embedded in Initial Context
Setup, modelled as an array of resource items with PDU Session ID, list
role, S-NSSAI, NAS-PDU presence, transfer presence/type, bound QFI values,
item Cause, and an explicit binding basis; unsafely bound nested values are
preserved as unbound evidence. Version 0.3.0 adds bounded N2
handover/path-switch mobility evidence: HandoverRequired, HandoverCommand,
and HandoverPreparationFailure (Handover Preparation), HandoverRequest,
HandoverRequestAcknowledge, and HandoverFailure (Handover Resource
Allocation), HandoverNotify (Handover Notification), HandoverCancel and
HandoverCancelAcknowledge (Handover Cancel), and PathSwitchRequest,
PathSwitchRequestAcknowledge, and PathSwitchRequestFailure (Path Switch
Request), with exact reviewed message identities, a bounded `mobility`
metadata object (procedure family, observed HandoverType value with its
reviewed symbolic name, TargetID presence with its reviewed choice
alternative, transparent-container presence and octet length), and
item-scoped mobility resource-list roles (REQUIRED, HANDOVER, TO_RELEASE,
ADMITTED, TO_BE_SWITCHED, SWITCHED, RELEASED, FAILED) so that
admitted/switched and failed/released items in one message stay
independent observations. Source and target NG-RAN associations are never
merged, and no handover/path-switch procedure outcome, N3 tunnel identity,
or Domain procedure state is produced. It does not decode NAS, does not
parse transfer or transparent containers, does not own PFCP/GTP-U/SBI
semantics, does not model PDU Session or registration procedure state, and
does not claim full-Release NGAP coverage.

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

Implemented: `sbi-http2`, the N11 SBI/HTTP2 Protocol Skill. Version 0.2.0
supports a bounded Nsmf_PDUSession subset of TS 29.502 (Release 19) and
Namf_Communication N1/N2 delivery subset of TS 29.518 (Release 19) over
HTTP/2 per RFC 9113 / RFC 9110: Create SM Context, Update SM Context,
Release SM Context, Namf N1N2MessageTransfer, and N1N2Transfer Failure
Notification, with HTTP/2 stream isolation scoped by connection
context (stream ID alone never identifies a transaction), transfer
resource reference tracking, URI path privacy sanitization, Content-ID
multipart binding for N1 SM and N2 SM information parts, subscriber privacy
defaults (SUPI, GPSI, PEI redacted by default), Authorization header
stripping, bounded 3GPP ProblemDetails and service-error preservation,
HTTP/2 transport error handling (RST_STREAM, GOAWAY), and deterministic
callback correlation. It does not decode NAS or NGAP binaries, does not
own PFCP or GTP-U semantics, does not perform TLS decryption, does not join
cross-interface session state, and does not determine PDU session or SMF/AMF
verdicts.

Implemented: `s1ap`, the S1-MME signaling Protocol Skill. Version 0.2.0
implements a bounded subset of TS 36.413 (S1AP), verified against the S1AP
dissector of Wireshark/TShark 4.7.1: S1 setup (request/response/failure),
InitialUEMessage, UplinkNASTransport, DownlinkNASTransport, Initial Context
Setup (request/response/failure), UEContextReleaseRequest, and UE context
release (command/complete). It resolves the S1AP PDU category with its
resolution basis, keeps eNB-UE-S1AP-ID and MME-UE-S1AP-ID strictly separate,
preserves Cause group and value, reports NAS-PDU presence and length only,
publishes item-scoped E-RAB evidence for Initial Context Setup (E-RAB identity,
QCI, ARP presence, transport layer address and GTP-TEID bound to their own item
from a PDML dissection, with flat field input published as explicitly unbound),
and correlates
frames into UE contexts scoped by capture file and SCTP association with
explicit STRONG/SUPPORTED/AMBIGUOUS/UNBOUND strength. It does not decode NAS,
does not model LTE Attach state, does not select abnormal boundaries, and does
not attribute root cause.

Implemented: `nas-eps`, the EPS NAS Protocol Skill. Version 0.2.0 implements a
bounded subset of TS 24.301, verified against the NAS-EPS dissector of
Wireshark/TShark 4.7.1: EPS attach (request/accept/complete/reject), Identity
request/response, Authentication request/response/failure/reject, and NAS
Security Mode Command/Complete/Reject, with security-header-type and protection
classification, EMM cause preservation, bounded attach-type and identity-type
values, ESM container presence and length, and explicit
PROTECTED_INNER_MESSAGE_UNAVAILABLE classification. Authentication and NAS
security mode control stay distinct procedures. Version 0.2.0 adds a bounded ESM
subset — PDN connectivity request/reject, activate default EPS bearer context
request/accept/reject, ESM information request/response and ESM status — read from
a PDML dissection so each message keeps its ESM container and enclosing NAS
message, with the EPS bearer identity and the procedure transaction identity kept
as separate fields, ESM cause preservation, and APN presence/length, PDN address
presence/family and QoS/PCO presence published without any value. It never
publishes subscriber identities, authentication parameters or payload bytes, and
it does not model bearer state or determine Attach outcomes.

Implemented: `gtpv2`, the GTPv2-C session-control Protocol Skill. Version 0.1.0
implements a bounded subset of TS 29.274 on S11 and S5/S8, verified against the
GTPv2 dissector of Wireshark/TShark 4.7.1: Echo request/response, Create
Session request/response, Modify Bearer request/response, Delete Session
request/response, and Release Access Bearers request/response, with header
semantics that keep ABSENT, ZERO and PRESENT header TEID states distinct,
message-scope and bearer-scope Cause preservation, message-scope and item-scoped
F-TEID evidence with reviewed interface types, EBI, APN presence and length
only, PDN type, PAA address family, RAT type, AMBR presence, and protocol-local
transaction correlation with MATCHED, OPEN_REQUEST, RESPONSE_ONLY and AMBIGUOUS
classifications. Grouped Bearer Context binding is published only when the
dissector tree proves the item boundary; flat field input is reported as
explicitly unbound. It never publishes subscriber identities, APN names, PAA
addresses or raw IE bytes, and it does not model session, PDN-connection or
bearer lifecycle state.

Planned: `sip`, `sdp-rtp`,
`diameter-core` and its domain layers, and remaining 5GC SBI services.
