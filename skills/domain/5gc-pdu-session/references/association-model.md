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

When multiple UEs execute PDU Session Establishment with identical PDU Session IDs and overlapping timestamps in the same capture:
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

## Plane-to-Plane Evidence Bridges

### 1. N1 <-> N2 (NAS <-> NGAP) Bridge
- **Anchor**: NAS-5GS messages are transported over N2 within NGAP signaling (`InitialUEMessage`, `UplinkNASTransport`, `DownlinkNASTransport`, `InitialContextSetupRequest`).
- **Mechanism**: Same-frame provenance (`frame_number`) establishes the link between the NAS PDU Session Establishment message and the NGAP UE context (`ran_ue_ngap_id`, `amf_ue_ngap_id`, `sctp_association`).
- **Strength**: `STRONG`.

### 2. N1 <-> N4 (NAS <-> PFCP) Bridge
- **Standardized Direct Equivalence**: NONE. PDU Session ID is not a PFCP identifier.
- **Supporting Bridge**: Exact observed **NAS accepted PDU Address** <-> **PFCP allocated UE IP Address**.
  - Must be directly observed on both planes (not inferred).
  - Address family (IPv4 / IPv6) and address value must match byte-for-byte.
  - Candidate match must be unique within the capture context.
- **Strength**: `SUPPORTED`, marked with basis `ue_ip_address_exact_match`.

### 3. N4 <-> N3 (PFCP <-> GTP-U) Bridge
- **Mechanism**: PFCP `SessionEstablishmentResponse` allocates an uplink or downlink `F-TEID` (containing both `TEID` and `IPv4/IPv6 address`).
- **Verification Rule**: Matching GTP-U traffic requires BOTH:
  1. Outer GTP-U destination/source IP matches the F-TEID IP address.
  2. GTP-U header TEID matches the F-TEID TEID.
- **TEID Reuse Protection**: Matching on TEID alone is strictly prohibited. If two different UPF endpoints use the same numeric TEID, only the stream matching the provisioned endpoint IP is associated.
- **Strength**: `STRONG`, marked with basis `f_teid_endpoint_and_teid_match`.

### 4. N1 <-> N11 (NAS <-> SBI-HTTP2) Bridge
- **Privacy Constraint**: `sbi-http2` sanitizes subscriber identities (`supi`, `pei`, `imsi`).
- **Single Candidate Rule**: If exactly ONE active UE instance in the capture context matches the SBI `pdu_session_id`, `dnn`, and `s_nssai`, and timing aligns, a candidate association is recorded with strength `SUPPORTED`.
- **Ambiguity Rule**: If TWO OR MORE candidate UE instances have the same `pdu_session_id`, the SBI event **MUST NOT** be assigned to either instance. It is placed in `unbound_evidence.unbound_n11` with limitation `CORRELATION_AMBIGUITY`.

### 5. N2 <-> N3 (NGAP <-> GTP-U) Bridge
- If NGAP does not expose clear GTP-U tunnel transport identifiers, no direct NGAP <-> GTP-U bridge is fabricated. The user plane connects to control plane strictly through the PFCP F-TEID bridge.

---

## Unbound Evidence Preservation

Any protocol event that cannot be safely bound to a procedure instance is preserved in `unbound_evidence`:
- `unbound_n1`: Unbound NAS 5GSM messages.
- `unbound_n2`: Unbound NGAP PDU session resources.
- `unbound_n3`: Unbound GTP-U streams (unknown TEID or endpoint mismatch).
- `unbound_n4`: Unbound PFCP sessions (no matching UE IP or context).
- `unbound_n11`: Unbound SBI HTTP/2 transactions (ambiguous PSI or missing transfer ref).
- `ambiguous_events`: Events with multiple conflicting candidate associations.
