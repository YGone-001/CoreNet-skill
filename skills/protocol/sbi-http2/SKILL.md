# SBI HTTP/2

## Purpose

Answer WHAT 3GPP Service Based Interface (SBI) and HTTP/2 signaling traffic and fields
were observed on the N11 interface: the HTTP/2 method, path, status, connection context,
stream identity, Nsmf_PDUSession operation (Create SM Context, Update SM Context,
Release SM Context), Namf_Communication delivery operation (N1N2MessageTransfer,
N1N2Transfer Failure Notification), SM Context and transfer resource references,
bounded PDU Session ID / DNN / S-NSSAI metadata, multipart Content-ID binding for N1/N2
binary parts, ProblemDetails / service error evidence, HTTP/2 transport errors (RST_STREAM,
GOAWAY), and privacy-preserving identity handling.

This is a Protocol-layer Skill bounded to N11, the Nsmf_PDUSession service subset, and the
Namf_Communication N1/N2 delivery subset reviewed against 3GPP TS 29.500 version 19.7.0
Release 19, 3GPP TS 29.501 version 19.5.0 Release 19, 3GPP TS 29.502 version 19.8.0
Release 19 (Release 19 lineage), 3GPP TS 29.518 version 19.8.0 Release 19, and
3GPP TS 29.571 version 19.4.0 / 19.8.0 Release 19, carried over HTTP/2 (RFC 9113)
and HTTP Semantics (RFC 9110).

## Scope

- Identify HTTP/2 request and response frames (HEADERS, DATA presence/length, RST_STREAM,
  GOAWAY, SETTINGS, PING).
- Scope stream ID by connection context (dissector `tcp.stream` or explicit `connection_id`).
  Stream 1 on connection A and Stream 1 on connection B remain strictly separate transactions.
- Identify 3GPP SBI Nsmf_PDUSession operations: Create SM Context (`POST /sm-contexts`),
  Update SM Context (`POST /sm-contexts/{smContextRef}/modify`), and Release SM Context
  (`POST /sm-contexts/{smContextRef}/release`).
- Identify 3GPP SBI Namf_Communication operations: N1N2MessageTransfer
  (`POST /namf-comm/{apiVersion}/ue-contexts/{ueContextId}/n1-n2-messages`) and
  N1N2Transfer Failure Notification callback (`POST {n1n2FailureTxfNotifURI}`).
- Track SM Context resource references (`sm_context_ref`) from the `Location` response header
  or resource URI path, maintaining authority / API-root scope.
- Track N1N2 message transfer resource references (`n1n2_transfer_ref`) from the `Location`
  response header or transfer path.
- Sanitize identity-bearing URI paths (`/ue-contexts/{ueContextId}/`) by default, preventing
  SUPI/PEI/IMSI values from leaking into paths, resources, or event fields.
- Preserve bounded session management metadata: PDU Session ID, DNN, S-NSSAI (`sst`, `sd`),
  Request Type, Access Type, RAT Type, User Plane connection state, and N2 SM Information Type.
- Support multipart/related structure with explicit Content-ID binding for N1 SM message
  and N2 SM information binary references.
- Preserve ProblemDetails and service-specific error data (`status`, `cause`, `title`,
  invalid parameters) without promoting cause to root cause.
- Preserve HTTP/2 transport error evidence (RST_STREAM error codes, GOAWAY last stream ID).
- Redact subscriber identity values (`supi`, `gpsi`, `pei`) by default, preserving only
  presence and type.
- Strip and unconditionally reject `Authorization` header values and tokens.
- Explicitly report when application payload is unavailable due to TLS encryption.
- Correlate request/response transactions by connection and stream ID.
- Correlate N1N2Transfer Failure Notification callbacks deterministically by `n1n2_transfer_ref`.
- Project detailed events into the shared trace-event schema (`protocol: 3GPP-SBI`, `interface: N11`).

## Non-Goals

- Do not implement a byte-level HTTP/2 frame parser, HPACK decompressor, Huffman decoder,
  or TCP reassembly in Python. Only TShark or deterministic structured input is used.
- Do not perform TLS decryption, private key handling, or secret-log parsing.
- Do not decode NAS signaling from N1 SM binary parts (owned by `nas-5gs`).
- Do not decode NGAP transfers from N2 SM binary parts (owned by `ngap`).
- Do not join N11 PDU Session IDs to NAS PDU Session IDs, PFCP SEIDs, or GTP-U TEIDs.
  Cross-protocol joins belong to future Domain procedure analysis (`5gc-pdu-session`).
- Do not decide whether an end-to-end PDU Session succeeded or failed. An HTTP 2xx response
  proves only that the SBI request succeeded according to the API contract.
- Do not blame network functions (AMF, SMF, SCP) or infer implementation software bugs.
  An HTTP 4xx/5xx status or ProblemDetails is protocol-level signaling.
- Do not implement remaining Namf_Communication operations (UE Context Transfer, Registration
  Status Update, subscriptions, etc.) or full-catalog SBI services (Nausf_UEAuthentication,
  Nudm_SDM, Npcf_SMPolicyControl, etc.) in this version.
- Do not claim end-to-end root cause.

## Inputs

- An authorized PCAP/PCAPNG capture containing HTTP/2 over TCP/TLS, parsed with user-installed
  TShark (never auto-installed), or
- a structured SBI HTTP/2 fields JSONL export with the documented fields in
  `references/field-reference.md` (deterministic offline input; unit tests use only this form).

## Outputs

- `scripts/extract-sbi-http2.py <input> --output sbi-events.jsonl [--trace-output trace-events.jsonl]` —
  detailed SBI HTTP/2 event JSONL (schema `schemas/sbi-http2-event.schema.json`) plus optional
  trace-event projection (schema `schemas/trace-event.schema.json`).
- `scripts/correlate-sbi-http2.py sbi-events.jsonl --output correlation.json` —
  transaction correlation summary (schema `schemas/sbi-http2-correlation.schema.json`).
- `scripts/sbi_timeline.py sbi-events.jsonl [--format text|json]` —
  protocol-local timeline; never prints an SMF bug or session verdict.

## Dependencies

None required. Optional: `core-network-pcap` (capture provenance), `wireshark-analysis`,
`protocol-reverse-engineering`, `systematic-debugging` (investigation methods), `tshark`
(direct capture parsing; user-installed).

The package is standalone: runtime needs nothing outside this directory.

## Workflow

1. Confirm capture authorization and capture point; record boundaries and encryption state.
2. Run the extractor on the capture or structured input; treat every detailed event as OBSERVED
   wire evidence with its derivations listed.
3. Run the correlation script to associate requests and responses within connection-scoped streams.
4. Render the timeline for protocol-local ordering.
5. Identify the observed API operations, SM Context references, and failure boundaries without
   claiming root cause.

## Evidence Rules

- **OBSERVED**: HTTP method, path, status, scheme, authority, headers, frame types, stream ID,
  TCP endpoints, multipart part lengths/types, ProblemDetails fields, RST_STREAM / GOAWAY codes.
- **DERIVED**: Normalized operation name, SM Context reference from Location, status class,
  Content-ID binding, transaction key, correlation strength.
- **INFERRED**: Protocol-local relationships strongly suggested but not directly proven.
- **HYPOTHESIS**: Candidate explanations needing more evidence.
- **CONFIRMED**: Deliberately rare; this Skill never confirms end-to-end PDU Session success.

## Failure Handling

Missing or malformed structured input, empty input, unavailable or failing TShark, and
unsafe output replacement produce a readable error on stderr and non-zero exit codes
(tool unavailable 3, tshark failure 4, malformed input 5, no events 6, output failure 7).
Unsupported operations or services are reported `UNSUPPORTED`, unknown paths `UNKNOWN`.
TLS encrypted application data without cleartext HTTP/2 is reported with limitation
`HTTP/2/SBI payload unavailable due to encrypted/unavailable application data`.

## Validation

Run `python tests/test_sbi_http2.py` from this package for the fixture suite.
Repository checkouts also run `python scripts/validate-sbi-http2.py` for repository contract
validation.

## References

Read `README.md`, `references/protocol-model.md`, `references/http2-model.md`,
`references/sbi-model.md`, `references/nsmf-pdusession.md`, `references/namf-communication.md`,
`references/field-reference.md`, `references/multipart-model.md`, `references/privacy.md`,
`references/correlation.md`, and `references/failure-cases.md`.
Reviewed basis: 3GPP TS 29.500 v19.7.0, TS 29.501 v19.5.0, TS 29.502 v19.8.0,
3GPP TS 29.518 v19.8.0, TS 29.571 v19.4.0/v19.8.0, RFC 9113, RFC 9110.
