# Field Reference and TShark Verification Debt

## Field Verification Status

The field mappings below are verified against:
- Published Wireshark display-filter reference for `http2`, `json`, `mime_multipart`, and `tcp`.
- 3GPP TS 29.500, TS 29.501, TS 29.502, TS 29.518, TS 29.571 (Release 19).

**Verification Debt:** In the current environment, local TShark was not available:
`LOCAL TSHARK NOT RUN`. All fields are published-reference verified. If running in an
environment with TShark installed, verify with `tshark -G fields`.

## HTTP/2 Wire and Pseudo-Header Fields

| Normalized Event Field | TShark Field Name | Type | Notes |
| :--- | :--- | :--- | :--- |
| `http2.stream_id` | `http2.streamid` | integer | Scoped by connection context |
| `http2.frame_type` | `http2.type` | string | `HEADERS`, `DATA`, `RST_STREAM`, `GOAWAY`, `SETTINGS`, `PING` |
| `http2.method` | `http2.headers.method` | string | `:method` pseudo-header (e.g. `POST`, `GET`) |
| `http2.path` | `http2.headers.path` | string | `:path` pseudo-header (sanitized for identity-bearing paths) |
| `http2.status` | `http2.headers.status` | integer | `:status` pseudo-header (e.g. `201`, `200`, `202`, `400`) |
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
| `sbi.service_name` | TS 29.502 / TS 29.518 | string | `Nsmf_PDUSession`, `Namf_Communication` |
| `sbi.api_version` | TS 29.502 / TS 29.518 | string | API major version (`v1`) |
| `sbi.operation` | TS 29.502 / TS 29.518 | string | `CreateSMContext`, `UpdateSMContext`, `ReleaseSMContext`, `N1N2MessageTransfer`, `N1N2TransferFailureNotification` |
| `sbi.resource` | TS 29.502 / TS 29.518 | string | Sanitized resource path string |
| `sbi.sm_context_ref` | TS 29.502 clause 6.1.3 | string | SM Context reference from Location header or path |
| `sbi.n1n2_transfer_ref` | TS 29.518 clause 6.1.3 | string | Sanitized N1/N2 transfer reference from Location or notification |
| `sbi.selected_headers` | TS 29.500 clause 5.2 | object | Allowlisted safe headers |

## Bounded Namf_Communication Fields

| Normalized Event Field | 3GPP Reference | Type | Notes |
| :--- | :--- | :--- | :--- |
| `namf_communication.ue_context_id_present` | TS 29.518 clause 6.1.3 | boolean | True if `{ueContextId}` path parameter detected |
| `namf_communication.ue_context_id_type` | Derived | string | `SUPI`, `PEI`, `GUTI`, `GENERIC`, `UNKNOWN` |
| `namf_communication.n1_message_class` | TS 29.518 `n1MessageClass` | string | `SM`, `5GMM`, `LPP`, `SMS`, `UPDP`, `LCS` |
| `namf_communication.n2_information_class` | TS 29.518 `n2InformationClass` | string | `SM`, `NRPPa`, `PWS`, `RAN`, `V2X` |
| `namf_communication.n2_sm_info_type` | TS 29.518 `n2SmInfoType` | string | `PDU_RES_SETUP_REQ`, etc. |
| `namf_communication.n1_content_id` | TS 29.518 `RefToBinaryData` | string | Referenced N1 binary part Content-ID |
| `namf_communication.n2_content_id` | TS 29.518 `RefToBinaryData` | string | Referenced N2 binary part Content-ID |
| `namf_communication.failure_notification_uri_present` | TS 29.518 `n1n2FailureTxfNotifURI` | boolean | True if consumer callback URI provided |
| `namf_communication.transfer_cause` | TS 29.518 `cause` | string | `N1_N2_TRANSFER_INITIATED`, `WAITING_FOR_ASYNCHRONOUS_TRANSFER`, `ATTEMPTING_TO_REACH_UE`, etc. |
| `namf_communication.failure_cause` | TS 29.518 `cause` | string | `UE_NOT_RESPONDING`, `AN_NOT_RESPONDING`, `UE_NOT_REACHABLE_FOR_SESSION`, etc. |

## Bounded Session Management Fields

| Normalized Event Field | 3GPP Reference | Type | Notes |
| :--- | :--- | :--- | :--- |
| `session_management.pdu_session_id` | TS 29.502 / TS 29.518 | integer | 1..255 |
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
| `privacy.subscriber_identity_present` | JSON body or URI path | `true` if identity member or path parameter detected, else `false` |
| `privacy.subscriber_identity_type` | Member name / path pattern | `"SUPI"`, `"GPSI"`, `"PEI"`, `"GUTI"`, `"GENERIC"`, `"UNKNOWN"`; **raw identity values are REDACTED** |

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

## Direct-Capture TShark Compatibility

Version 0.2.1 introduces deterministic direct-capture compatibility handling:

- **Candidate Field Alias Resolution**: `http2.data.length` supports candidate aliases `("http2.data.length", "http2.length")`. `http2.goaway.last_streamid` supports `("http2.goaway.last_streamid", "http2.goaway.last_stream_id")`. `json.member_name` supports `("json.member_name", "json.member")`. MIME multipart header fields support fallback candidates and optional resolution.
- **Dynamic Header Mapping**: Field headers emitted by TShark are mapped back to canonical field names, filling any unavailable optional fields with empty strings.
- **Display Filter Resolution**: Uses `-Y http2` to focus extraction exclusively on HTTP/2 frames, preventing full-capture scanning of non-SBI frames.
- **Empty-Capture Handling**: When zero HTTP/2 records are present in a capture, the extractor cleanly reports exit code 6 (`EXIT_NO_EVENTS`), mapping to `NOT_OBSERVED_IN_CAPTURE` in capture pipelines.
