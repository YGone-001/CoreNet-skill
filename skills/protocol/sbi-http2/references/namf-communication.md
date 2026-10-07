# Namf_Communication Bounded N1/N2 Delivery Semantics

## Specification Basis

Reviewed against 3GPP TS 29.518 (Release 19, version 19.8.0), clause 5.2.2.3 and clause 6.1.

The `Namf_Communication` service is provided by the Access and Mobility Management Function
(AMF) over the N11 reference point towards NF service consumers (such as the SMF). In the
context of session management and N1/N2 signaling delivery, the SMF produces session information
and requests the AMF to transfer it towards the UE (N1 SM) and/or the (R)AN (N2 SM).

## Service Direction and Ownership

- **N1N2MessageTransfer**: NF Service Consumer (e.g., SMF) -> NF Service Provider (AMF)
- **N1N2Transfer Failure Notification**: NF Service Provider (AMF) -> NF Service Consumer (callback)

These observations must not be collapsed:
1. SMF producing N1/N2 session information (SM Context update response or Namf transfer request)
2. AMF accepting an N1/N2 transfer request (HTTP 200 or 202)
3. AMF reporting asynchronous storage / paging state (HTTP 202 with `WAITING_FOR_ASYNCHRONOUS_TRANSFER` or `ATTEMPTING_TO_REACH_UE`)
4. AMF reporting delivery failure via callback (`UE_NOT_RESPONDING`, etc.)

## Supported Operations

In version 0.2.1, semantic support is bounded to N1/N2 delivery and failure reporting:

### 1. N1N2MessageTransfer

- **HTTP Method**: `POST`
- **Resource Path**: `{apiRoot}/namf-comm/{apiVersion}/ue-contexts/{ueContextId}/n1-n2-messages`
- **URI Privacy Contract**:
  - The path parameter `{ueContextId}` may carry sensitive subscriber identifiers such as SUPI, PEI, or GUTI.
  - The Skill replaces raw identity segments with the `{ueContextId}` token across all user-facing outputs (`http2.path`, `sbi.resource`, timeline, trace events, and correlation records).
  - Identity presence (`ue_context_id_present: true`) and classified type (`ue_context_id_type: SUPI | PEI | GUTI | GENERIC | UNKNOWN`) are recorded separately without persisting the raw value.
- **Request Payload**:
  - `application/json` (`N1N2MessageTransferReqData`) or
  - `multipart/related` (`N1N2MessageTransferReqData` JSON part + optional N1 message part and/or N2 information part)
- **Bounded Request Fields**:
  - `n1MessageContainer`:
    - `n1MessageClass`: e.g., `SM` (5GMM, LPP, SMS, UPDP, LCS also recognized)
    - `n1MessageContent`: `RefToBinaryData` (`contentId`)
  - `n2InfoContainer`:
    - `n2InformationClass`: e.g., `SM` (NRPPa, PWS, RAN, V2X also recognized)
    - `smInfo`:
      - `pduSessionId`: integer (1..255)
      - `n2SmInfoType`: e.g., `PDU_RES_SETUP_REQ`, `PDU_RES_MOD_REQ`, `PDU_RES_REL_CMD`
      - `n2InfoContent`: `RefToBinaryData` (`contentId`)
  - `pduSessionId`: integer (at root or inside `smInfo`)
  - `n1n2FailureTxfNotifURI`: callback URI for asynchronous delivery failure notification
- **Expected Responses**:
  - `200 OK`:
    - Response body: `N1N2MessageTransferRspData`
    - Bounded `cause` values: `N1_N2_TRANSFER_INITIATED`, `N1_MSG_NOT_TRANSFERRED`, `N2_MSG_NOT_TRANSFERRED`
    - Result classification: `RESPONSE`
  - `202 Accepted`:
    - Mandatory `Location` header containing the created N1/N2 transfer resource:
      `{apiRoot}/namf-comm/{apiVersion}/ue-contexts/{ueContextId}/n1-n2-messages/{n1n2MsgId}`
    - Response body: `N1N2MessageTransferRspData`
    - Bounded `cause` values: `WAITING_FOR_ASYNCHRONOUS_TRANSFER`, `ATTEMPTING_TO_REACH_UE`, `N1_N2_TRANSFER_INITIATED`, `N1_MSG_NOT_TRANSFERRED`, `N2_MSG_NOT_TRANSFERRED`
    - Result classification: `N1N2_TRANSFER_ACCEPTED_PENDING` (never `PDU_SESSION_SUCCESS` or `DELIVERED`)
  - `4xx / 5xx Error`:
    - Standard 3GPP `ProblemDetails` payload (`status`, `cause`, `title`, `invalidParams`)
    - Result classification: `HTTP_ERROR`

### 2. N1N2Transfer Failure Notification

- **HTTP Method**: `POST`
- **Resource Path**: Consumer-provided callback URI (from prior `n1n2FailureTxfNotifURI`)
- **Identification**: Identified by explicit operation annotation, matching prior callback URI, or payload structure containing `n1n2MsgDataUri` and `cause`.
- **Request Payload**: `N1N2MsgTxfrFailureNotification` (JSON)
- **Bounded Request Fields**:
  - `cause`: Bounded TS 29.518 failure cause:
    - `UE_NOT_RESPONDING`
    - `UE_NOT_REACHABLE_FOR_SESSION`
    - `TEMPORARY_REJECT_REGISTRATION_ONGOING`
    - `TEMPORARY_REJECT_HANDOVER_ONGOING`
    - `AN_NOT_RESPONDING`
    - `FAILURE_CAUSE_UNSPECIFIED`
  - `n1n2MsgDataUri`: URI of the failed transfer resource (matching `Location` from prior 202 response)
- **Result Classification**: `FAILURE_NOTIFICATION`
- **Expected Callback Response**:
  - `204 No Content`: Acknowledges notification receipt ("failure notification callback acknowledged")
  - Result classification: `RESPONSE`

## Resource Identity Distinction

CoreNet Skill strictly distinguishes SBI resource references and protocol identities:

| Identifier | Defined By | Scope & Purpose |
| :--- | :--- | :--- |
| `sm_context_ref` | TS 29.502 | SMF-allocated individual SM Context resource (`/nsmf-pdusession/v1/sm-contexts/{smContextRef}`) |
| `n1n2_transfer_ref` | TS 29.518 | AMF-allocated N1/N2 message transfer resource (`/namf-comm/v1/ue-contexts/{ueContextId}/n1-n2-messages/{n1n2MsgId}`) |
| `pdu_session_id` | TS 24.501 | End-to-end UE-allocated PDU Session identity (1..255) |
| `stream_id` | RFC 9113 | HTTP/2 multiplexed stream identifier scoped to a single TCP connection |

These identifiers must never be substituted for one another.

## Deterministic Transfer-to-Callback Correlation

- The initiating `N1N2MessageTransfer` request/response exchange is correlated into an `sbi-tx` transaction on its HTTP/2 stream.
- When an AMF returns `202 Accepted`, it provides a `Location` header yielding `n1n2_transfer_ref`.
- When an AMF later sends an `N1N2Transfer Failure Notification` on a separate HTTP stream/connection, it includes `n1n2MsgDataUri`.
- If `n1n2MsgDataUri` matches the prior `n1n2_transfer_ref`, the failure notification is deterministically attached to the initiating transfer transaction with `correlation_strength: STRONG`.
- **No Timestamp-Only Join**: If no matching transfer reference exists, or if references differ despite identical timestamps, the callback is reported under `unbound_callbacks` with an explicit limitation. It is NEVER correlated by timestamp proximity alone.

## Semantic Interpretation Boundaries

1. **HTTP 202 Accepted Is Not Delivery**:
   - An HTTP 202 response indicates that the AMF accepted the transfer request for processing or queued it while attempting to reach the UE (e.g. paging). It does NOT prove that N1 or N2 information reached the UE or RAN.
2. **Failure Notification Is Delivery Failure Evidence, Not Cause Verdict**:
   - An `N1N2Transfer Failure Notification` with cause `UE_NOT_RESPONDING` is direct protocol evidence that the AMF reported delivery failure. It does NOT prove that the gNB failed, that the UE radio link dropped, or that the AMF is defective.
3. **No Protocol Binary Decoding**:
   - The Skill records Content-ID binding, container classes, and part lengths. It never decodes or interprets the binary N1 (NAS) or N2 (NGAP) contents.
