# N11 / N4 / N3 Supporting Evidence

Supporting-plane evidence is bounded and never a mobility verdict. All
association rules are context-based; timestamp proximity alone never
associates anything. Every supporting event is evaluated globally against
ALL mobility attempts (handover and Path Switch) before ownership is
assigned, and resolves to exactly one of BOUND, AMBIGUOUS, or UNBOUND. One
supporting event belongs to at most one attempt — a runtime invariant, not
a convention — and ambiguous events are preserved under
`unbound_mobility_evidence` with reason, candidate attempt ids, and
association strength. Sequential attempts in the same scoped UE context
bound each other's supporting candidate windows; when no safe upper
boundary exists, none is invented and identity keys carry the association.

## N11 (SBI-HTTP2)

A PDU Session ID identifies a PDU Session context; it does NOT identify a
handover or Path Switch attempt. Nsmf_PDUSession UpdateSMContext events
therefore bind to a mobility attempt only when the event carries a
reviewed mobility-specific N2 SM Information Type from the lower SBI
contract (for a Handover Required / Handover Request Acknowledge /
Path Switch Request class of transfer). The sbi-http2 contract passes
n2SmInfoType through verbatim and exposes no reviewed mobility vocabulary,
so the Domain's reviewed set is empty and UpdateSMContext evidence stays
UNBOUND in this version: PSI + capture + a later timestamp is never
sufficient, and an unrelated session modification for the same PDU Session
must stay unbound as well. The HTTP status, SM Context reference, N2 SM
Info type, and ProblemDetails remain preserved as observed evidence. An
HTTP 2xx response never becomes handover or Path Switch success, and
missing N11 evidence never becomes mobility failure — N11 may simply be
outside the capture vantage.

## N4 (PFCP)

PFCP Session Modification Request/Response events carry no UE identity,
and a modification may belong to any PDU Session change. PFCP session
identity is endpoint scoped: (capture, order-normalized endpoint pair,
header SEID). The same numeric SEID under a different endpoint pair is a
different PFCP session and never cross-binds; when the same (capture,
SEID) appears under several endpoint pairs, the groups stay apart and only
a group whose FAR outer-header F-TEID matches the PDU Session Domain
context's F-TEID may become the candidate group. The bridge to a mobility
attempt remains the optional PDU Session Domain context binding that SEID
to a PDU Session instance whose window overlaps the attempt and whose PDU
Session ID is in the attempt's resource set. Without such context, PFCP
modification evidence stays unbound, and a modification whose mobility
attribution is not unique stays AMBIGUOUS or UNBOUND rather than being
attached by time. PFCP Cause is preserved; a negative cause (reviewed TS 29.244
rejection range) on a safely associated response produces
PROTOCOL_NEGATIVE_OUTCOME_OBSERVED at USER_PLANE_CONTROL_UPDATE and
never becomes UPF, SMF, or handover blame. PFCP acceptance never becomes
mobility success.

## N3 (GTP-U)

GTP-U binding is direction sensitive. Tunnels are derived only from
attempt-owned (BOUND) PFCP events whose FAR Outer Header Creation names
the encapsulation DESTINATION: the matching packet must carry that TEID
toward that address. A packet with the same TEID whose source is that
address is the reverse direction and never binds through the same tunnel
rule, and the same TEID with a different endpoint pair never binds. TEID
alone is never sufficient. Tunnel contexts that expose TEID + address
without a safe direction role (for example the PDU Session Domain context
F-TEID entries) never confer ownership. Bound tunnels carry neutral
labels (TUNNEL_A, TUNNEL_B, ...): an OLD_PATH/NEW_PATH role requires
reviewed tunnel lifecycle context this version does not establish. NGAP
opaque transfer bytes are never parsed for TEIDs, and an Error Indication
matches through its affected-TEID (never the zero header TEID) under the
same endpoint/session/attempt scoping.

Observation semantics: a bound G-PDU proves only a capture-point packet
observation; no G-PDU is reported as NOT_OBSERVED, never as user-plane
failure. End Marker is an optional observation; its absence produces no
deviation. An Error Indication is preserved as a field finding and never
becomes a handover, UPF, or radio verdict.
