# SBI HTTP/2 Protocol Model

## Normative Basis

This Skill is bounded to the 3GPP Service Based Interface (SBI) protocols and HTTP/2
transport for the N11 interface, evaluated against:

- **3GPP TS 29.500** version 19.7.0 Release 19: *5G System; Technical Realization of Service Based Architecture; Stage 3*
- **3GPP TS 29.501** version 19.5.0 Release 19: *5G System; Principles and Guidelines for Services Definition; Stage 3*
- **3GPP TS 29.502** version 19.8.0 Release 19 (Release 19 lineage): *5G System; Session Management Services; Stage 3*
- **3GPP TS 29.571** version 19.4.0 / 19.8.0 Release 19: *5G System; Common Data Types for Service Based Interfaces; Stage 3*
- **RFC 9113**: *HTTP/2*
- **RFC 9110**: *HTTP Semantics*
- **RFC 2045 / RFC 2387**: *MIME Multipart/Related*

Field names follow the HTTP/2, MIME multipart, and JSON dissectors of Wireshark/TShark
as documented in published Wireshark display-filter references. In the reviewed execution
environment, local TShark was not available (`LOCAL TSHARK NOT RUN`); published display-filter
specifications are used.

## Architecture and Scope

SBI HTTP/2 is a Protocol-layer Skill in the CoreNet five-layer architecture:

    Foundation -> Protocol (sbi-http2) -> Correlation -> Domain -> Analysis Orchestration

The Skill answers protocol-local and API-boundary questions:
- Which HTTP/2 request and response were observed?
- Which HTTP/2 connection context and stream ID carried the interaction?
- Which 3GPP SBI service and API operation is represented?
- Whether Nsmf_PDUSession Create SM Context, Update SM Context, or Release SM Context was observed?
- Which SM Context resource reference was created, updated, or released?
- What bounded PDU Session ID, DNN, and S-NSSAI metadata are directly present in the API structure?
- Whether N1 SM and N2 SM information binary parts are referenced in multipart bodies?
- What ProblemDetails or service-error evidence was observed?
- What HTTP/2 transport errors (RST_STREAM, GOAWAY) were observed?
- Whether application payload is unavailable due to TLS encryption?

## Non-Goals and Explicit Boundaries

- **No Complete PDU Session Verdict**: An HTTP 201 or 200 response proves that the SBI operation returned an HTTP success status; it does not prove that end-to-end PDU Session establishment, user-plane setup, or packet delivery succeeded.
- **No Implementation Blame**: An HTTP 4xx/5xx status or ProblemDetails body is protocol-level error signaling; it does not prove an SMF software defect, AMF defect, or vendor bug.
- **No NAS Decoding**: Contained N1 SM information binary parts are referenced by Content-ID and length only; decoding 5GSM messages belongs strictly to `nas-5gs`.
- **No NGAP Decoding**: Contained N2 SM information binary parts are referenced by Content-ID, type, and length only; decoding NGAP transfers belongs strictly to `ngap`.
- **No Cross-Protocol Joins**: This Skill does not join N11 PDU Session IDs to NAS PDU Session IDs, does not map SM Context references to PFCP SEIDs or GTP-U TEIDs. That cross-interface correlation belongs to future Domain procedure analysis (`5gc-pdu-session`).
- **No Binary Parsers in Python**: No hand-written HPACK decoder, binary frame parser, TCP reassembly engine, or TLS decryption routine is implemented. Only TShark or deterministic structured input is used.
- **No TLS Decryption**: Encrypted TLS payload without dissector decode is explicitly reported as unavailable payload evidence; secrets, keys, and key logs are never handled.
