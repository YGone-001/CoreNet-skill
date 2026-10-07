# sbi-http2

`sbi-http2` is a standalone Protocol-layer package for bounded 3GPP Service Based
Interface (SBI) and HTTP/2 evidence extraction on the N11 interface. Version 0.2.1
implements the Nsmf_PDUSession subset and Namf_Communication N1/N2 delivery subset
reviewed against 3GPP TS 29.500 version 19.7.0 Release 19, 3GPP TS 29.501 version 19.5.0
Release 19, 3GPP TS 29.502 version 19.8.0 Release 19 (Release 19 lineage),
3GPP TS 29.518 version 19.8.0 Release 19, and 3GPP TS 29.571 version 19.4.0 / 19.8.0
Release 19, over HTTP/2 (RFC 9113) and HTTP Semantics (RFC 9110).

It extracts HTTP/2 request and response evidence, scopes streams by connection context,
identifies Create SM Context, Update SM Context, Release SM Context, Namf N1N2MessageTransfer,
and N1N2Transfer Failure Notification operations, tracks SM Context and transfer resource
references, sanitizes identity-bearing URI paths, preserves bounded session management
metadata (PDU Session ID, DNN, S-NSSAI), binds multipart N1/N2 binary references by Content-ID,
preserves ProblemDetails and transport errors (RST_STREAM, GOAWAY), enforces privacy
defaults on subscriber identities, deterministically correlates callbacks by transfer reference,
and projects normalized trace events.

**This Skill proves only what was observed on the wire at the SBI boundary.** An HTTP 2xx
response proves that the HTTP operation completed successfully according to the API contract;
it never proves that the end-to-end 5GC PDU Session procedure succeeded. An HTTP 4xx/5xx status
or ProblemDetails error never proves an AMF/SMF software defect or root cause. It does not decode
NAS or NGAP binaries, does not perform TLS decryption, and does not join cross-protocol
identifiers to PFCP or GTP-U.

Reviewed basis: 3GPP TS 29.500 v19.7.0, TS 29.501 v19.5.0, TS 29.502 v19.8.0,
TS 29.518 v19.8.0, and TS 29.571 v19.4.0/v19.8.0, cross-checked against the HTTP/2,
MIME multipart, and JSON dissectors of Wireshark/TShark as published in the Wireshark
display-filter reference. The reviewed environment had no local TShark installation,
so field names are published-reference verified rather than locally re-dumped; that
verification debt is recorded in `references/field-reference.md`.

## Package structure

- `scripts/sbi_model.py`: shared standalone normalization helpers, reviewed operation
  tables, multipart Content-ID binding, privacy redaction, and trace projection.
- `scripts/extract-sbi-http2.py`: capture or structured JSONL input to detailed SBI HTTP/2
  events, with optional trace projection.
- `scripts/correlate-sbi-http2.py`: request/response transaction correlation summary.
- `scripts/sbi_timeline.py`: protocol-local timeline (text or JSON).
- `schemas/sbi-http2-event.schema.json`: detailed event contract.
- `schemas/sbi-http2-correlation.schema.json`: transaction correlation contract.
- `schemas/trace-event.schema.json`: byte-identical copy of the shared trace-event schema.
- `references/`: protocol model, HTTP/2 model, SBI model, Nsmf_PDUSession, Namf_Communication,
  field reference, multipart model, privacy policy, correlation model, failure cases.
- `filters/wireshark.txt`: reviewed display filters.
- `examples/extracted/`: synthetic structured fixtures (documentation IP address ranges only,
  redacted subscriber identities, no binary payloads).
- `examples/expected/`: deterministic expected outputs.
- `tests/`: package-local test entry point (`test_sbi_http2.py`).

## Usage

```bash
python scripts/extract-sbi-http2.py capture.pcapng --output sbi-events.jsonl
python scripts/extract-sbi-http2.py capture.pcapng --trace-output trace-events.jsonl
python scripts/extract-sbi-http2.py fields.jsonl --input-format fields-jsonl --output sbi-events.jsonl
python scripts/correlate-sbi-http2.py sbi-events.jsonl --output correlation.json
python scripts/sbi_timeline.py sbi-events.jsonl --format text
```

Inputs are validated before extraction; existing outputs are refused unless `--force`
is given; outputs are deterministic.
