# PDU Session Association Model

## Procedure Instance Formation and Identity

In 3GPP 5GC signaling, **PDU Session ID alone is NOT a globally unique procedure identifier**. A UE assigns PDU Session IDs locally in the range 1–255; different UEs concurrently allocate the same PDU Session ID (e.g. UE A uses PSI=1, UE B uses PSI=1).

A procedure instance is anchored by:
```
capture_file + NGAP UE Context (ran_ue_ngap_id, amf_ue_ngap_id, sctp_association) + pdu_session_id
```
The derived internal instance key is constructed as:
```
5gc-pdu-session:<capture_file>:ran<ran_id>-amf<amf_id>:psi<pdu_session_id>
```
This identifier is marked `DERIVED`. It is never represented as a standardized 3GPP protocol field.

## Multi-UE Isolation Rule

When multiple UEs execute PDU Session Establishment or Modification with identical PDU Session IDs and overlapping timestamps in the same capture:
- They **MUST** remain separate procedure instances.
- Timestamp proximity alone **MUST NEVER** merge them into a single procedure instance.

## Association Strength Classification

Each plane binding is classified by an explicit procedure-local association strength:

| Strength | Criteria | Example |
| --- | --- | --- |
| `STRONG` | Deterministic wire-level provenance, identical frame transport, or exact combined identifier matches. | NAS embedded in NGAP transport frame; PFCP F-TEID (TEID + IP) matching GTP-U outer destination IP and TEID. |
| `SUPPORTED` | Exact match on directly observed semantic attributes with unique candidate context in the capture window. | Exact match between NAS accepted PDU Address and PFCP allocated UE IP address. Single candidate UE matching SBI PDU Session ID and DNN. |
| `AMBIGUOUS` | Plausible correlation candidate exists, but multiple candidates match the same identifier, preventing deterministic assignment. | SBI event observed with PSI=10 when two active UE instances both establish PSI=10. |
| `UNBOUND` | Evidence observed on an interface cannot be tied to any candidate procedure instance due to missing identifiers or context. | GTP-U packet observed with a TEID not allocated in any PFCP session; SBI notification without transfer ref. |

> [!IMPORTANT]
> **Association strength is distinct from evidence confidence.**
> Association strength measures the certainty of linking multi-plane records together.
> Evidence confidence measures the reliability of stage observations based on capture completeness and visibility.

---

## Modification Attempt Association

PDU Session Modification introduces repeated attempt modeling within an established PDU Session instance.

### 1. NAS Procedure Transaction Identity (PTI)
- **Role**: Disambiguates concurrent or sequential transactions initiated by the UE or network.
- **Strict UE-Context Scoping**: NAS PTI is scoped strictly to its UE context and PDU Session ID. A PTI value of `5` on UE 1 and a PTI value of `5` on UE 2 are independent transactions and never collide or merge.
- **Value 0**: PTI value 0 represents an unassigned transaction (e.g. network-initiated commands or legacy procedures).

### 2. Continuity with Established Context
- **PFCP Continuity**: PFCP Session Modification requests must use the CP/UP SEID established during Session Establishment.
- **SM Context Continuity**: N11 UpdateSMContext requests must target the `sm_context_ref` URI returned in the 201 Created response of CreateSMContext.
- **F-TEID Continuity and Update**: User-plane control modifications may update existing F-TEIDs or provision new F-TEIDs. GTP-U packets following modification are matched against the active F-TEID.

### 3. Concurrent and Ambiguous Attempts
- If multiple modification requests appear for the same PDU Session with distinct PTIs, they are tracked as concurrent distinct attempts.
- If overlapping modification requests appear without distinct PTIs or clear separation, they are classified with `association_strength: "AMBIGUOUS"` and `CORRELATION_AMBIGUITY`.

---

## Plane-to-Plane Evidence Bridges

### 1. N1 <-> N2 (NAS <-> NGAP) Bridge
- **Anchor**: NAS-5GS messages are transported over N2 within NGAP signaling (`InitialUEMessage`, `UplinkNASTransport`, `DownlinkNASTransport`, `InitialContextSetupRequest`, `PDUSessionResourceModifyRequest`).
- **Mechanism**: Same-frame provenance (`frame_number`) establishes the link between the NAS message and the NGAP UE context (`ran_ue_ngap_id`, `amf_ue_ngap_id`, `sctp_association`). When only one NGAP context exists in the capture, NAS messages on that capture safely associate with it.
- **Strength**: `STRONG`.

### 2. N1 <-> N4 (NAS <-> PFCP) Bridge
- **Standardized Direct Equivalence**: NONE. PDU Session ID is not a PFCP identifier.
- **Supporting Bridge**: Exact observed **NAS accepted PDU Address** <-> **PFCP allocated UE IP Address**, and established SEID continuity.
- **Strength**: `SUPPORTED`, marked with basis `ue_ip_address_exact_match` or `pfcp_session_seid_continuity`.

### 3. N4 <-> N3 (PFCP <-> GTP-U) Bridge
- **Mechanism**: PFCP `SessionEstablishmentResponse` or `SessionModificationResponse` allocates an uplink or downlink `F-TEID` (containing both `TEID` and `IPv4/IPv6 address`).
- **Verification Rule**: Matching GTP-U traffic requires BOTH:
  1. Outer GTP-U destination/source IP matches the F-TEID IP address.
  2. GTP-U header TEID matches the F-TEID TEID.
- **Isolation Rule**: TEID reuse across different IP endpoints prevents false cross-endpoint binding.
