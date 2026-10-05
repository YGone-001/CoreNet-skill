# N11 / N4 / N3 Supporting Evidence

Supporting-plane evidence is bounded and never a mobility verdict. All
association rules are context-based; timestamp proximity alone never
associates anything.

## N11 (SBI-HTTP2)

Nsmf_PDUSession UpdateSMContext events associate with an attempt when
the same capture, a directly supplied PDU Session ID in the attempt's
resource set, and a timestamp at or after the attempt start all hold.
Events without a usable PDU Session ID (for example privacy-redacted
exports) stay UNBOUND and are preserved in
`unbound_mobility_evidence`. The HTTP status, SM Context reference, N2 SM
Info type, and ProblemDetails are preserved as observed evidence. An HTTP
2xx response never becomes handover or Path Switch success, and missing
N11 evidence never becomes mobility failure — N11 may simply be outside
the capture vantage.

## N4 (PFCP)

PFCP Session Modification Request/Response events carry no UE identity,
and a modification may belong to any PDU Session change. The only safe
association path is through the optional PDU Session Domain context: when
that context binds a PFCP header SEID (same capture) to a PDU Session
instance whose window overlaps the attempt and whose PDU Session ID is in
the attempt's resource set, the modification is associated via that SEID
continuity. Without such context, PFCP modification evidence stays
unbound. PFCP Cause is preserved; a negative cause (reviewed TS 29.244
rejection range) on a safely associated response produces
PROTOCOL_NEGATIVE_OUTCOME_OBSERVED at USER_PLANE_CONTROL_UPDATE and
never becomes UPF, SMF, or handover blame. PFCP acceptance never becomes
mobility success.

## N3 (GTP-U)

G-PDU, End Marker, and Error Indication events bind to an attempt only
through TEID equality plus compatible directed endpoint context — from a
safely associated PFCP FAR outer-header creation F-TEID or from the PDU
Session Domain context N4/N3 bindings. TEID alone is never sufficient,
and the same TEID on a different endpoint pair never binds. Bound tunnels
carry neutral labels (TUNNEL_A, TUNNEL_B, ...): an OLD_PATH/NEW_PATH role
requires reviewed tunnel lifecycle context this version does not
establish. NGAP opaque transfer bytes are never parsed for TEIDs.

Observation semantics: a bound G-PDU proves only a capture-point packet
observation; no G-PDU is reported as NOT_OBSERVED, never as user-plane
failure. End Marker is an optional observation; its absence produces no
deviation. An Error Indication is preserved as a field finding and never
becomes a handover, UPF, or radio verdict.
