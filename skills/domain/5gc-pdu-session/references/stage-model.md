# PDU Session Procedure Stage Model

The bounded 5GC PDU Session Establishment procedure is evaluated across seven stages.

| Stage ID | Stage Name | Interface | Protocols | Expected Messages / Operations | Conditionality |
| --- | --- | --- | --- | --- | --- |
| `session_request` | Session Request | N1 | NAS-5GS | `PduSessionEstablishmentRequest` | Expected for UE-requested establishment |
| `sm_context_control` | SM Context Control | N11 | 3GPP-SBI | `CreateSMContext`, `UpdateSMContext` | Expected in 5GC SBA |
| `user_plane_control` | User Plane Control | N4 | PFCP | `SessionEstablishmentRequest`, `SessionEstablishmentResponse` | Expected for UPF session configuration |
| `access_resource_control` | Access Resource Control | N2 | NGAP | `PDUSessionResourceSetupRequest`, `PDUSessionResourceSetupResponse`, `InitialContextSetupRequest`, `InitialContextSetupResponse` | Expected for RAN resource allocation |
| `n1_n2_delivery` | N1/N2 Delivery | N11 | 3GPP-SBI | `N1N2MessageTransfer`, `N1N2TransferFailureNotification` | Conditional / Asynchronous transfer |
| `session_decision` | Session Decision | N1 | NAS-5GS | `PduSessionEstablishmentAccept`, `PduSessionEstablishmentReject` | Terminal decision stage |
| `user_plane_observation` | User Plane Observation | N3 | GTP-U | `G-PDU`, `EchoRequest`, `EchoResponse`, `ErrorIndication`, `EndMarker` | Post-establishment observation at capture point |

---

## 1. `session_request` (Session Request)
- **Role**: Captures the initial request from the UE on N1.
- **Evidence**: `PduSessionEstablishmentRequest` (5GSM message).
- **Extracted Fields**: PDU Session ID, Procedure Transaction Identity (PTI), Request Type (e.g. `INITIAL_REQUEST`), PDU Session Type (e.g. `IPV4`, `IPV6`, `IPV4V6`), SSC Mode, DNN, S-NSSAI.
- **Conditionality**: Expected when the procedure is initiated within the capture window. If capture begins after session setup, this stage is reported as `MISSING` with `PARTIAL_CAPTURE` limitation.

## 2. `sm_context_control` (SM Context Control)
- **Role**: AMF creates or updates an SM context with the SMF over N11.
- **Evidence**: `Nsmf_PDUSession_CreateSMContext` (POST `/sm-contexts`) request and response (201 Created with `Location` header assigning `sm_context_ref`), or 4xx/5xx ProblemDetails error.
- **Conditionality**: Expected in 5GC core networks.
- **Rule**: HTTP 201 Created proves that SMF accepted context creation; it does not prove the complete procedure succeeded.

## 3. `user_plane_control` (User Plane Control)
- **Role**: SMF establishes the user-plane session with the UPF over N4.
- **Evidence**: PFCP `SessionEstablishmentRequest` and `SessionEstablishmentResponse`.
- **Extracted Fields**: Header SEID, CP F-SEID, UP F-SEID, F-TEID (TEID + IP), PDR/FAR/URR/QER rules, UE IP address, Network Instance, QFI, PFCP Cause.
- **Rule**: `PFCP Cause = 1 ("Request accepted")` proves N4 control-plane session establishment; it does not prove N3 user-plane delivery.

## 4. `access_resource_control` (Access Resource Control)
- **Role**: AMF requests gNB to establish radio and transport resources for the PDU session.
- **Evidence**: NGAP `PDUSessionResourceSetupRequest` / `PDUSessionResourceSetupResponse`, or embedded PDU session resource lists in `InitialContextSetupRequest` / `InitialContextSetupResponse`.
- **Item-Level Evaluation**: NGAP responses return resource lists (`PDUSessionResourceSetupListSURes`, `PDUSessionResourceSetupListSUFail`). Evaluation is scoped strictly to the target PDU Session ID. A successful outcome message containing a failed item for the target session is evaluated as `RESOURCE_FAILED_ITEM_OBSERVED`.

## 5. `n1_n2_delivery` (N1/N2 Delivery)
- **Role**: SMF requests AMF to deliver N1 (NAS) and/or N2 (NGAP) information to the UE / RAN.
- **Evidence**: `Namf_Communication_N1N2MessageTransfer` and `N1N2Transfer Failure Notification`.
- **Semantics**:
  - `HTTP 200 OK` (`cause: N1_N2_TRANSFER_INITIATED`): AMF initiated transfer.
  - `HTTP 202 Accepted` (`cause: WAITING_FOR_ASYNCHRONOUS_TRANSFER` or `ATTEMPTING_TO_REACH_UE`): Transfer pending / asynchronous. Must remain `N1N2_TRANSFER_PENDING_OBSERVED`, never delivery success.
  - Failure Notification callback (`cause: UE_NOT_RESPONDING`, `AN_NOT_RESPONDING`): Direct observed protocol evidence of delivery failure, classified as `DELIVERY_FAILURE_NOTIFICATION_OBSERVED`.

## 6. `session_decision` (Session Decision)
- **Role**: Terminal signaling on N1 delivering the outcome to the UE.
- **Evidence**:
  - `PduSessionEstablishmentAccept`: Terminal positive protocol decision. Contains accepted PDU Address, QFI, Authorized QoS, Session AMBR. Classified as `ESTABLISHMENT_ACCEPT_OBSERVED`.
  - `PduSessionEstablishmentReject`: Terminal negative protocol decision. Contains 5GSM Cause. Classified as `ESTABLISHMENT_REJECT_OBSERVED` with `PROTOCOL_REJECT_OBSERVED` deviation.
- **Rule**: `Accept` is terminal protocol signaling; it does not constitute an end-to-end root-cause verification of application-plane success.

## 7. `user_plane_observation` (User Plane Observation)
- **Role**: Verifies user-plane traffic on N3 at the capture point following or concurrent with establishment.
- **Evidence**: GTP-U `G-PDU` traffic matching the provisioned F-TEID (TEID + outer IP).
- **Semantics**:
  - If matching G-PDU packets are observed: `GTPU_TRAFFIC_OBSERVED` with packet and byte counts.
  - If no matching G-PDU packets are observed within the capture window: Reported as "no matching N3 G-PDU evidence observed within the available capture window". **Never** reported as `USER_PLANE_FAILED`.
