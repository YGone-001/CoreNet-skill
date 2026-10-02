# Nsmf_PDUSession Bounded Evidence Semantics

## Specification Basis

Reviewed against 3GPP TS 29.502 (Release 19, version 19.8.0 / Release 19 lineage).

The `Nsmf_PDUSession` service is provided by the Session Management Function (SMF)
over the N11 reference point towards the Access and Mobility Management Function (AMF).

## Supported Operations

In version 0.1.0, semantic support is bounded to the three core SM Context operations:

### 1. Create SM Context (CreateSMContext)

- **HTTP Method**: `POST`
- **Resource Path**: `{apiRoot}/nsmf-pdusession/{apiVersion}/sm-contexts`
- **Request Payload**:
  - `application/json` (`SmContextCreateData`) or
  - `multipart/related` (`SmContextCreateData` JSON part + optional binary N1 SM message part)
- **Bounded Request Fields**:
  - `pduSessionId` (1..255)
  - `dnn` (Data Network Name)
  - `sNssai` (`sst`, `sd`)
  - `requestType` (INITIAL_REQUEST, EXISTING_PDU_SESSION, etc.)
  - `anType` (3GPP_ACCESS, NON_3GPP_ACCESS)
  - `ratType` (NR, EUTRA, WLAN, etc.)
  - `n1SmMsg` (RefToBinaryData: `contentId`)
  - `supi` / `gpsi` / `pei` (detected for presence/type; values redacted)
- **Expected Success Status**:
  - `201 Created`
  - **Location Header**: Mandatory on 201; contains the URI of the created individual SM Context resource:
    `{apiRoot}/nsmf-pdusession/{apiVersion}/sm-contexts/{smContextRef}`
  - **Response Payload**: `SmContextCreatedData` or multipart (JSON + optional N1/N2 binary parts)
- **Error Statuses**:
  - `307 Temporary Redirect`, `308 Permanent Redirect`
  - `400 Bad Request`, `403 Forbidden`, `404 Not Found`, `411 Length Required`, `413 Payload Too Large`, `415 Unsupported Media Type`, `429 Too Many Requests`, `500 Internal Server Error`, `503 Service Unavailable`, `504 Gateway Timeout`
  - Body: `ProblemDetails` or `SmContextCreateError` (which encapsulates `error` as ProblemDetails and optional `n1SmMsg`)

### 2. Update SM Context (UpdateSMContext)

- **HTTP Method**: `POST`
- **Resource Path**: `{apiRoot}/nsmf-pdusession/{apiVersion}/sm-contexts/{smContextRef}/modify`
- **Request Payload**:
  - `application/json` (`SmContextUpdateData`) or
  - `multipart/related` (`SmContextUpdateData` + optional N1/N2 binary parts)
- **Bounded Request Fields**:
  - `smContextRef` (extracted from path)
  - `pduSessionId` (if explicitly present)
  - `n1SmMsg` (RefToBinaryData)
  - `n2SmInfo` (RefToBinaryData)
  - `n2SmInfoType` (PDU_RES_SETUP_REQ, PDU_RES_REL_CMD, PDU_RES_MOD_REQ, etc.)
  - `upCnxState` (ACTIVATED, DEACTIVATED, ACTIVATING, SUSPENDED)
  - `anType` (Access Type)
  - `cause` (Cause / release reason)
- **Expected Success Statuses**:
  - `200 OK` (body contains `SmContextUpdatedData` or multipart)
  - `204 No Content` (empty body)
- **Error Statuses**:
  - `307`, `308`, `400`, `403`, `404`, `411`, `413`, `415`, `429`, `500`, `503`, `504`
  - Body: `ProblemDetails` or `SmContextUpdateError`

### 3. Release SM Context (ReleaseSMContext)

- **HTTP Method**: `POST`
- **Resource Path**: `{apiRoot}/nsmf-pdusession/{apiVersion}/sm-contexts/{smContextRef}/release`
- **Request Payload**: `SmContextReleaseData` (JSON)
- **Bounded Request Fields**:
  - `smContextRef` (extracted from path)
  - `cause` (Release cause)
  - `n1SmMsg` / `n2SmInfo` references if defined
- **Expected Success Statuses**:
  - `200 OK` (with `SmContextReleasedData`)
  - `204 No Content` (empty body)
- **Error Statuses**:
  - `307`, `308`, `400`, `403`, `404`, `500`, `503`, `504`
  - Body: `ProblemDetails`

## Recognized but Deferred Operations

The following operations are recognized by normative name from TS 29.502 but remain
`UNSUPPORTED` in v0.1.0:

| Operation | Method & Resource Path | Status |
| :--- | :--- | :--- |
| `RetrieveSMContext` | `GET /sm-contexts/{smContextRef}` | UNSUPPORTED |
| `SendMoData` | `POST /sm-contexts/{smContextRef}/send-mo-data` | UNSUPPORTED |
| `Create` (PDU Session) | `POST /pdu-sessions` | UNSUPPORTED |
| `Update` (PDU Session) | `POST /pdu-sessions/{pduSessionId}/modify` | UNSUPPORTED |
| `Release` (PDU Session) | `POST /pdu-sessions/{pduSessionId}/release` | UNSUPPORTED |
| `Get` (PDU Session) | `GET /pdu-sessions/{pduSessionId}` | UNSUPPORTED |
| `SmContextStatusNotify` | `POST {smContextStatusUri}` | UNSUPPORTED |

## Semantic Interpretation Boundaries

1. **HTTP Status is Not Procedure Verdict**:
   - `HTTP 201 Created` or `HTTP 200 OK` indicates that the SMF processed the HTTP request successfully according to the API contract. It does NOT mean the end-to-end PDU Session procedure succeeded, user-plane resources were bound, or UPF forwarding works.
   - `HTTP 4xx` or `HTTP 5xx` indicates an HTTP client or server error response. It does NOT mean the SMF software failed, that a software bug exists, or that the network function crashed.
2. **SM Context Reference vs. PDU Session ID**:
   - `smContextRef` is an API resource identifier allocated by the SMF to address this individual context.
   - `pduSessionId` is an integer (1..255) allocated by the UE identifying the 3GPP PDU session.
   - They must never be conflated, aliased, or substituted.
