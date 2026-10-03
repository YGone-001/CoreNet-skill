# 3GPP SBI Model

## Architecture Principles

3GPP Service Based Interfaces (SBI) utilize RESTful HTTP/2 APIs with JSON serialization
(TS 29.500, TS 29.501). Resources are identified by standard URI templates:

    {apiRoot}/{apiName}/{apiVersion}/{apiSpecificResourceUriPart}

Where:
- `{apiRoot}` consists of the scheme (`http` or `https`) and authority (`host[:port]`),
  or an API root path prefix.
- `{apiName}` identifies the NF service (e.g., `nsmf-pdusession`).
- `{apiVersion}` is the major version string (e.g., `v1`).
- `{apiSpecificResourceUriPart}` identifies the resource collection, individual resource,
  or custom operation.

## Service Identification

Service identification is established directly from the request URI path:
- Requests targeting `/nsmf-pdusession/` identify the `Nsmf_PDUSession` service. Bounded SM Context operations (`CreateSMContext`, `UpdateSMContext`, `ReleaseSMContext`) are `SUPPORTED`.
- Requests targeting `/namf-comm/` for N1/N2 message transfer (`/namf-comm/{apiVersion}/ue-contexts/{ueContextId}/n1-n2-messages`) and consumer callbacks for N1N2 transfer failure notification are `SUPPORTED` under `Namf_Communication`. Remaining operations (UE Context Transfer, Registration Status Update, etc.) remain `UNSUPPORTED`.
- Requests targeting other 5GC services (e.g., `/nausf-auth/`, `/nudm-sdm/`,
  `/npcf-smpolicycontrol/`, `/nnrf-disc/`) are recognized as SBI services but marked
  `UNSUPPORTED` in this bounded Skill version.
- Requests with non-SBI paths are treated as generic HTTP/2 traffic (`UNSUPPORTED`).

Service identity must **never** be inferred from port numbers, timing, or endpoint IP addresses alone.

Paths containing subscriber identities (`/ue-contexts/{ueContextId}/`) are sanitized across all outputs.

## Safe Header Allowlist

To protect sensitive subscriber and system information, only an allowlisted subset of HTTP
headers is preserved in detailed events:

| Header Name | Standard | Semantic Role |
| :--- | :--- | :--- |
| `content-type` | RFC 9110 | Indicates media type (`application/json`, `multipart/related`, `application/problem+json`) |
| `content-length` | RFC 9110 | Size of body payload in octets |
| `accept` | RFC 9110 | Client acceptable media types |
| `location` | RFC 9110 | Resource URI of created resource (e.g., in `201 Created` response) |
| `user-agent` | RFC 9110 | Client identifier (e.g., NF client identity) |
| `3gpp-sbi-target-apiroot` | TS 29.500 | API root of the target NF when mediated by SCP or SEPP |
| `3gpp-sbi-routing-binding` | TS 29.500 | Routing binding parameters for NF instance or set selection |
| `3gpp-sbi-message-priority` | TS 29.500 | Message priority indication |
| `3gpp-sbi-sender-timestamp` | TS 29.500 | Timestamp indicating when request was sent |
| `3gpp-sbi-max-rsp-time` | TS 29.500 | Client maximum acceptable response time in milliseconds |
| `3gpp-sbi-correlation-id` | TS 29.500 | Transaction correlation identifier across SBA hops |

### Strict Header Prohibition

The `Authorization` header (and `Proxy-Authorization`) carries OAuth 2.0 Bearer access
tokens, client credentials, or authentication signatures. Per repository security rules:
- **`Authorization` header values MUST NEVER be persisted.**
- Tokens, keys, and private material are unconditionally stripped from all outputs.

## Intermediaries and SCP Boundary

An intermediary Service Communication Proxy (SCP) may route or forward SBI messages,
often introducing `3gpp-sbi-target-apiroot` or `3gpp-sbi-routing-binding` headers.
- The presence of such headers is an OBSERVED routing fact.
- It does **not** prove that an SCP caused an observed failure or delayed a response.
- Endpoints are described in protocol-neutral terms unless supported by explicit SBI evidence.
