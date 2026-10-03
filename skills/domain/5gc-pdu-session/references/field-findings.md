# PDU Session Field Findings and Conflict Handling

## Field Findings Across Planes

The Domain Skill exposes procedure-relevant protocol fields from already-extracted lower-layer events without modifying wire interpretations:

### N1 Plane (NAS-5GS)
- `pdu_session_id`: Session identity (1–255).
- `pti`: Procedure Transaction Identity.
- `request_type`: Initial, existing, or emergency request.
- `pdu_session_type`: IPV4, IPV6, IPV4V6, Unstructured, Ethernet.
- `ssc_mode`: SSC Mode 1, 2, or 3.
- `dnn`: Data Network Name.
- `snssai`: Single Network Slice Selection Assistance Information (`sst`, `sd`).
- `pdu_address`: Accepted UE IP address.
- `cause`: 5GSM reject cause (e.g. Cause 27 `MISSING_OR_UNKNOWN_DNN`, Cause 28 `UNKNOWN_PDU_SESSION_TYPE`, Cause 31 `REQUEST_REJECTED_UNSPECIFIED`, Cause 43 `INVALID_PDU_SESSION_IDENTITY`).
- `qfi`: Quality of Service Flow Identifier.
- `qos_flow_descriptions`: Authorized QoS flow descriptions, flow operations, parameters.

### N2 Plane (NGAP)
- `pdu_session_id`: Target resource identifier.
- `resource_outcome`: `REQUESTED`, `SUCCEEDED`, or `FAILED`.
- `cause`: NGAP Cause group and value (e.g. `radioNetwork: resources-not-available`).
- `qfi_list`: List of QoS flow identifiers configured for the session.
- `snssai`: Associated slice parameters.
- `pdu_session_resource_modify`: Resource modify items and failed-to-modify items.

### N4 Plane (PFCP)
- `cause`: PFCP Cause (e.g. 1 = `Request accepted`, 64 = `Context not found`, 69 = `Rule creation/modification failure`).
- `header_seid`, `cp_fseid`, `up_fseid`: Session endpoint identifiers.
- `ue_ip_address`: Allocated UE IP address.
- `network_instance`: Target network instance string.
- `f_teid`: Fully Qualified Tunnel Endpoint Identifier (`teid` and `ip_address`).
- `qfi`: QFI assigned to PDRs/QERs.
- `rule_operations`: Explicit rule operations across PDRs, FARs, URRs, and QERs (create, update, remove).

### N3 Plane (GTP-U)
- `teid`: Tunnel Endpoint Identifier on user plane.
- `qfi`: Observed PDU Session Container QFI.
- `packet_count`, `byte_count`: Aggregated traffic volume in window.
- `error_indication`: Observed Error Indication with TEID and peer address.
- `end_marker`: Observed End Marker packets signaling path switch or tunnel transition.

### N11 Plane (3GPP-SBI)
- `status`: HTTP status code (200, 201, 202, 400, 403, 404, 500).
- `sm_context_ref`: SM Context resource reference assigned by SMF.
- `n1n2_transfer_ref`: N1/N2 message transfer resource reference.
- `transfer_cause`: `N1_N2_TRANSFER_INITIATED`, `WAITING_FOR_ASYNCHRONOUS_TRANSFER`, `ATTEMPTING_TO_REACH_UE`.
- `failure_cause`: `UE_NOT_RESPONDING`, `AN_NOT_RESPONDING`.
- `problem_details`: 3GPP ProblemDetails `cause`, `title`, `invalid_params`.

---

## Field Conflict Handling (`FIELD_CONFLICT`)

When multiple planes are safely associated, the Domain Skill compares semantic attributes. If conflicting values are observed, **both values are preserved** and recorded as a field finding with interpretation `FIELD_CONFLICT`:

1. **UE IP Address Mismatch**:
   - NAS accepted `pdu_address` is `198.51.100.1`.
   - PFCP allocated `ue_ip_address` is `198.51.100.2`.
   - Finding: Preserves both values; flags `FIELD_CONFLICT` and `CORRELATION_CONFLICT`.
2. **QFI Mismatch**:
   - NAS accepted default `qfi` is `1`.
   - NGAP configured `qfi` is `5`.
   - PFCP provisioned `qfi` is `9`.
   - Finding: Preserves conflicting values across N1, N2, and N4; flags `FIELD_CONFLICT`.
3. **F-TEID / Tunnel Update Mismatch**:
   - Updated F-TEID in PFCP / NGAP allocates new TEID `6001`.
   - User plane continues observing old TEID `5001` or traffic without matching tunnel.
   - Finding: Reports old vs new tunnel observation neutrally without assuming fault.
