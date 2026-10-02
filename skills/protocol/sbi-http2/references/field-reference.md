# Field Reference and TShark Verification Debt

## Field Verification Status

The field mappings below are verified against:
- Published Wireshark display-filter reference for `http2`, `json`, `mime_multipart`, and `tcp`.
- 3GPP TS 29.500, TS 29.501, TS 29.502, TS 29.571 (Release 19).

**Verification Debt:** In the current environment, local TShark was not available:
`LOCAL TSHARK NOT RUN`. All fields are published-reference verified. If running in an
environment with TShark installed, verify with `tshark -G fields`.

## HTTP/2 Wire and Pseudo-Header Fields

| Normalized Event Field | TShark Field Name | Type | Notes |
| :--- | :--- | :--- | :--- |
| `http2.stream_id` | `http2.streamid` | integer | Scoped by connection context |
| `http2.frame_type` | `http2.type` | string | `HEADERS`, `DATA`, `RST_STREAM`, `GOAWAY`, `SETTINGS`, `PING` |
| `http2.method` | `http2.headers.method` | string | `:method` pseudo-header (e.g. `POST`, `GET`) |
| `http2.path` | `http2.headers.path` | string | `:path` pseudo-header |
| `http2.status` | `http2.headers.status` | integer | `:status` pseudo-header (e.g. `201`, `200`, `400`) |
| `http2.scheme` | `http2.headers.scheme` | string | `:scheme` pseudo-header (`http`, `https`) |
| `http2.authority` | `http2.headers.authority` | string | `:authority` pseudo-header (`host[:port]`) |
| `http2.content_type` | `http2.header.value` (Content-Type) | string | Media type |
| `http2.content_length` | `http2.header.value` (Content-Length) | integer | Declared body length |
| `transport_error.error_code` | `http2.rst_stream.error` / `http2.goaway.error` | integer/string | Transport error code |
| `transport_error.last_stream_id` | `http2.goaway.last_streamid` | integer | Highest stream ID processed |

## Connection Transport Fields

| Normalized Event Field | TShark Field Name | Type | Notes |
| :--- | :--- | :--- | :--- |
| `connection.tcp_stream` | `tcp.stream` | integer | Dissector-local connection index |
| `connection.source_address` | `ip.src` / `ipv6.src` | string | IP address |
| `connection.destination_address` | `ip.dst` / `ipv6.dst` | string | IP address |
| `connection.source_port` | `tcp.srcport` | integer | TCP port |
| `connection.destination_port` | `tcp.dstport` | integer | TCP port |

## 3GPP SBI Fields

| Normalized Event Field | 3GPP Reference | Type | Notes |
| :--- | :--- | :--- | :--- |
| `sbi.service_name` | TS 29.502 | string | Normalized service identifier (`Nsmf_PDUSession`) |
| `sbi.api_version` | TS 29.502 | string | API major version (`v1`) |
| `sbi.operation` | TS 29.502 clause 5.2.2 | string | `CreateSMContext`, `UpdateSMContext`, `ReleaseSMContext` |
| `sbi.resource` | TS 29.502 clause 6.1.3 | string | Resource path string |
| `sbi.sm_context_ref` | TS 29.502 clause 6.1.3 | string | SM Context reference from Location header or path |
| `sbi.selected_headers` | TS 29.500 clause 5.2 | object | Allowlisted safe headers |

## Bounded Session Management Fields

| Normalized Event Field | 3GPP Reference | Type | Notes |
| :--- | :--- | :--- | :--- |
| `session_management.pdu_session_id` | TS 29.502 `pduSessionId` | integer | 1..255 |
| `session_management.dnn` | TS 29.502 `dnn` | string | Data Network Name |
| `session_management.snssai` | TS 29.571 `Snssai` | object | `{sst: integer, sd: hex string}` |
| `session_management.request_type` | TS 29.502 `requestType` | string | `INITIAL_REQUEST`, etc. |
| `session_management.access_type` | TS 29.571 `AccessType` | string | `3GPP_ACCESS`, `NON_3GPP_ACCESS` |
| `session_management.rat_type` | TS 29.571 `RatType` | string | `NR`, `EUTRA`, `WLAN`, etc. |
| `session_management.up_connection_state` | TS 29.502 `upCnxState` | string | `ACTIVATED`, `DEACTIVATED`, `ACTIVATING`, `SUSPENDED` |
| `session_management.n2_sm_info_type` | TS 29.502 `n2SmInfoType` | string | `PDU_RES_SETUP_REQ`, etc. |

## Privacy and Identity Fields

| Normalized Event Field | Source | Default Behavior |
| :--- | :--- | :--- |
| `privacy.subscriber_identity_present` | JSON body (`supi`, `gpsi`, `pei`) | `true` if any identity member is present, else `false` |
| `privacy.subscriber_identity_type` | Member name | `"SUPI"`, `"GPSI"`, or `"PEI"`; **raw identity values are REDACTED** |

## Multipart / Related Fields

| Normalized Event Field | MIME / 3GPP Reference | Description |
| :--- | :--- | :--- |
| `multipart_parts[].content_id` | `Content-ID` header | Identifier used to bind to JSON reference |
| `multipart_parts[].content_type` | `Content-Type` header | e.g. `application/vnd.3gpp.5gnas`, `application/vnd.3gpp.ngap` |
| `multipart_parts[].length` | Dissector / body size | Byte count; **raw bytes are NEVER persisted** |
| `multipart_parts[].semantic_role` | Derived | `JSON_METADATA`, `N1_SM_INFO`, `N2_SM_INFO`, `UNRESOLVED` |
| `multipart_parts[].reference_basis` | Derived | `ROOT_JSON`, `EXPLICIT_CONTENT_ID`, `UNREFERENCED`, `AMBIGUOUS_CONTENT_ID`, `MISSING_CONTENT_ID` |

## ProblemDetails Fields

| Normalized Event Field | TS 29.571 Member | Description |
| :--- | :--- | :--- |
| `problem_details.status` | `status` | HTTP status code integer |
| `problem_details.cause` | `cause` | 3GPP error cause string (e.g. `DNN_NOT_SUPPORTED`) |
| `problem_details.title` | `title` | Short summary title |
| `problem_details.invalid_params` | `invalidParams` | List of `{param, reason}` objects |
| `problem_details.service_error_type` | TS 29.502 | `SmContextCreateError`, `SmContextUpdateError`, or `ProblemDetails` |
