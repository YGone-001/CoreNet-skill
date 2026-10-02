# Bounded Failure Cases and Error Semantics

## Error Evidence Representation

In 3GPP SBI, abnormal conditions are signaled across three distinct layers:
1. **HTTP/2 Transport Layer**: Frame-level errors (`RST_STREAM`, `GOAWAY`).
2. **HTTP Application Layer**: Status codes (`4xx Client Error`, `5xx Server Error`).
3. **3GPP Service Layer**: `ProblemDetails` and service-specific error structures (`SmContextCreateError`, `SmContextUpdateError`).

## ProblemDetails and 3GPP Service Errors

Per 3GPP TS 29.571 clause 5.2.4 and TS 29.502 clause 6.1.6.2, error responses return
either a standard `ProblemDetails` object or a service-specific wrapper containing `error`:

### Common 3GPP Session Management Error Causes

| Cause String | Typical Context | Interpretation Rule |
| :--- | :--- | :--- |
| `DNN_NOT_SUPPORTED` | SMF cannot serve the requested DNN | Reported as observed cause; do not infer provisioning defect without external evidence |
| `INSUFFICIENT_UP_RESOURCES` | UPF or N3 resource allocation failed | Observed cause; do not claim UPF crash or hardware defect |
| `SUBSCRIPTION_DENIED` | UDM/UDR subscription check rejected | Observed cause; do not claim UDM failure |
| `USER_LOCATION_NOT_ALLOWED` | Area restriction or PLMN policy | Observed cause; do not infer gNB defect |
| `NETWORK_FAILURE` | Internal failure signaled by SMF | Observed cause; do not assume software crash |

### Explicit Cause Boundary Rule

- A `cause` value inside a ProblemDetails payload is **wire evidence** indicating what the
  responding NF stated as the reason for rejection.
- A reported `cause` **MUST NEVER** be promoted to an end-to-end "root cause". Root-cause
  attribution requires multi-interface evidence confirmation.

## HTTP Status Boundaries

- **HTTP 2xx**: Proves only that the HTTP transaction succeeded according to the API contract.
  It **must never** be reported as `PDU_SESSION_SUCCESS` or end-to-end procedure success.
- **HTTP 4xx / 5xx**: Proves that the HTTP responder returned an error status. It **must never**
  be reported as `SMF_FAILURE` or implementation blame.

## Transport Error Scenarios

- **RST_STREAM**: Indicates that a stream was terminated with an error code (e.g., `CANCEL`,
  `REFUSED_STREAM`, `INTERNAL_ERROR`). Preserved as transport error evidence; does not establish
  an NF procedure verdict.
- **GOAWAY**: Indicates that an endpoint is closing the HTTP/2 connection. Preserved as connection
  evidence; does not imply that ongoing sessions on other connections failed.

## Partial and Incomplete Evidence

- **Open Request**: Request observed without matching response frame. Classed as `PARTIAL`
  correlation strength; not a network timeout unless corroborated by subsequent transport teardown.
- **Orphan Response**: Response observed without preceding request frame (e.g., capture started mid-stream).
  Classed as `PARTIAL` correlation strength.
- **Multipart Ambiguity**:
  - Missing Content-ID: JSON references a part that is absent from MIME parts.
  - Duplicate Content-ID: Multiple MIME parts share the same Content-ID.
  Both are documented as explicit analysis limitations without guesswork.

## TLS Encryption Limitation

When packet captures contain encrypted TLS application data without deciphering secrets:
- The Skill **MUST NOT** hallucinate missing HTTP/2 or SBI messages.
- The limitation must state:
  `HTTP/2/SBI payload unavailable due to encrypted/unavailable application data`.
