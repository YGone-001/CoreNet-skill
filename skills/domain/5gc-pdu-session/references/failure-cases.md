# PDU Session Procedure Failure Cases and Diagnostic Boundaries

This reference catalog documents the protocol deviations, terminal rejections, and failure boundaries evaluated by `5gc-pdu-session`.

## 1. NAS Establishment Reject
- **Observation**: Terminal signaling frame on N1 contains `PduSessionEstablishmentReject`.
- **Fields**: 5GSM Cause (e.g. 27 `MISSING_OR_UNKNOWN_DNN`, 28 `UNKNOWN_PDU_SESSION_TYPE`, 32 `SERVICE_OPTION_NOT_SUPPORTED`, 38 `NETWORK_FAILURE`).
- **Terminal Observation**: `ESTABLISHMENT_REJECT_OBSERVED`.
- **Deviation**: `PROTOCOL_REJECT_OBSERVED` at stage `session_decision`.
- **Boundary**: Confirms the 5G core network rejected the session establishment over N1 with the observed cause. Does not prove whether the SMF, UDM, or PCF initiated the rejection.

## 2. N11 Create SM Context Error (ProblemDetails)
- **Observation**: SMF responds with HTTP 4xx/5xx containing `application/problem+json` (`ProblemDetails`).
- **Fields**: HTTP status (e.g. 400, 403, 404, 500), `cause` (e.g. `DNN_NOT_SUPPORTED`, `INSUFFICIENT_UP_RESOURCES`, `USER_UNKNOWN`).
- **Deviation**: `PROTOCOL_NEGATIVE_OUTCOME_OBSERVED` at stage `sm_context_control`.
- **Boundary**: Protocol failure at the AMF <-> SMF SBI interface.

## 3. PFCP Session Establishment Negative Cause
- **Observation**: UPF responds with PFCP `SessionEstablishmentResponse` containing non-accepted Cause value.
- **Fields**: Cause value (e.g. 64 `Context not found`, 69 `Rule creation/modification failure`, 72 `No established PFCP association`).
- **Deviation**: `PROTOCOL_NEGATIVE_OUTCOME_OBSERVED` at stage `user_plane_control`.
- **Boundary**: N4 control plane rejection by the UPF.

## 4. NGAP Resource Setup Failed Item
- **Observation**: gNB responds to `PDUSessionResourceSetupRequest` with `PDUSessionResourceSetupListSUFail` containing the target PDU Session ID.
- **Fields**: NGAP Cause (e.g. `radioNetwork: resources-not-available`, `radioNetwork: multiple-PDU-session-ID-instances`, `transport: transport-resource-unavailable`).
- **Deviation**: `RESOURCE_FAILED_ITEM_OBSERVED` at stage `access_resource_control`.
- **Boundary**: RAN-side access resource setup failure.

## 5. Mixed NGAP Resource Outcomes
- **Observation**: Single NGAP response carries multiple PDU session resource items:
  - Session 10: Reported in `PDUSessionResourceSetupListSURes` (Success).
  - Session 11: Reported in `PDUSessionResourceSetupListSUFail` (Failure).
- **Rule**: Instance for Session 10 has NO resource deviation; Instance for Session 11 records `RESOURCE_FAILED_ITEM_OBSERVED`.
- **Boundary**: Outcomes are evaluated per item; messages are never treated as all-or-nothing.

## 6. Namf Asynchronous Transfer Pending (HTTP 202)
- **Observation**: AMF responds to `N1N2MessageTransfer` with HTTP 202 Accepted and `cause: ATTEMPTING_TO_REACH_UE` or `WAITING_FOR_ASYNCHRONOUS_TRANSFER`.
- **Terminal Status**: Pending (`N1N2_TRANSFER_PENDING_OBSERVED`).
- **Rule**: Must not be converted to delivery success.

## 7. Namf N1N2Transfer Failure Notification
- **Observation**: AMF sends POST callback with `cause: UE_NOT_RESPONDING` or `AN_NOT_RESPONDING`.
- **Deviation**: `DELIVERY_FAILURE_NOTIFICATION_OBSERVED` at stage `n1_n2_delivery`.
- **Boundary**: Direct protocol proof that AMF could not deliver N1/N2 signaling to the UE/RAN. Does not prove whether radio coverage, UE power, or paging failure was the root cause.

## 8. Absence of GTP-U User-Plane Traffic
- **Observation**: PFCP session accepted and F-TEID allocated, but no matching G-PDU observed.
- **Result**: `user_plane_observation` reports "no matching N3 G-PDU evidence observed within the available capture window".
- **Rule**: Never emitted as `USER_PLANE_FAILED`.

## 9. Correlation Ambiguity (Multi-UE Same PDU Session ID)
- **Observation**: Two active UEs allocate PSI=10. An SBI event arrives for PSI=10 without unredacted subscriber identity.
- **Result**: SBI event preserved in `unbound_evidence.unbound_n11` with `CORRELATION_AMBIGUITY`. Neither UE instance is falsely bound.

## 10. NAS Modification Reject
- **Observation**: Terminal signaling on N1 contains `PduSessionModificationReject`.
- **Fields**: 5GSM Cause (e.g. Cause 43 `INVALID_PDU_SESSION_IDENTITY`, Cause 59 `UNSUPPORTED_QOS_PARAMETER`).
- **Terminal Observation**: `MODIFICATION_REJECT_OBSERVED`.
- **Deviation**: `PROTOCOL_REJECT_OBSERVED` at stage `modification_completion`.
- **Boundary**: Core network rejected UE-requested modification over N1.

## 11. NAS Modification Command Reject
- **Observation**: UE responds to network command with `PduSessionModificationCommandReject`.
- **Fields**: 5GSM Cause (e.g. Cause 43 `INVALID_PDU_SESSION_IDENTITY`).
- **Terminal Observation**: `MODIFICATION_COMMAND_REJECT_OBSERVED`.
- **Deviation**: `PROTOCOL_REJECT_OBSERVED` at stage `modification_completion`.
- **Boundary**: UE rejected network-requested modification command over N1.

## 12. N11 Update SM Context Error
- **Observation**: SMF responds to `UpdateSMContext` with HTTP 4xx/5xx ProblemDetails.
- **Deviation**: `PROTOCOL_NEGATIVE_OUTCOME_OBSERVED` at stage `sm_context_update`.
- **Boundary**: SMF rejected modification at the SBI layer.

## 13. PFCP Session Modification Negative Cause
- **Observation**: UPF responds with PFCP `SessionModificationResponse` containing negative cause (e.g. Cause 69 `Rule creation/modification failure`).
- **Deviation**: `PROTOCOL_NEGATIVE_OUTCOME_OBSERVED` at stage `user_plane_control_update`.
- **Boundary**: UPF rejected modification of user-plane control rules.

## 14. NGAP Resource Modify Failed Item
- **Observation**: gNB responds to `PDUSessionResourceModifyRequest` with `PDUSessionResourceFailedToModifyListModRes` containing target PDU Session ID.
- **Deviation**: `RESOURCE_FAILED_ITEM_OBSERVED` at stage `access_resource_update`.
- **Boundary**: RAN rejected resource modification for the specific session.

## 15. Cross-Plane QFI / F-TEID Conflict
- **Observation**: NAS authorized QFI differs from PFCP provisioned QFI or NGAP configured QFI.
- **Deviation**: `FIELD_CONFLICT` recorded at relevant modification stage.
- **Boundary**: Signaling mismatch across core network planes.
