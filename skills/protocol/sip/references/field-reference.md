# SIP field reference

Field names were verified against TShark 4.2.2 (`tshark -G fields`) and actual
PDML output. The extractor never assumes a field name without a reviewed
dissection.

## TShark PDML fields

| Field | Type | Use |
| --- | --- | --- |
| `frame.number` | `FT_UINT32` | source frame provenance |
| `frame.time_epoch` | `FT_ABSOLUTE_TIME` | source timestamp; converted to UTC ISO-8601 |
| `frame.time_relative` | `FT_RELATIVE_TIME` | capture-relative time |
| `frame.len`, `frame.cap_len` | `FT_UINT32` | truncation detection |
| `ip.src`, `ip.dst` | `FT_STRING` | IPv4 endpoints |
| `ipv6.src`, `ipv6.dst` | `FT_STRING` | IPv6 endpoints |
| `udp.srcport`, `udp.dstport` | `FT_UINT16` | UDP endpoints |
| `tcp.srcport`, `tcp.dstport` | `FT_UINT16` | TCP endpoints |
| `tcp.stream` | `FT_UINT32` | decoder-provided TCP stream identity |
| `tcp.len` | `FT_UINT32` | single-segment payload presence |
| `tcp.segment.count` | `FT_UINT32` | reassembled segment count |
| `tcp.reassembled.length` | `FT_UINT32` | reassembled byte count |
| `sip.Method` | `FT_STRING` | request method |
| `sip.Status-Code` | `FT_UINT32` | response status code |
| `sip.Status-Line` | `FT_STRING` | standard reason phrase comparison only |
| `sip.Request-Line` | `FT_STRING` | request start-line presence |
| `sip.r-uri` | `FT_STRING` | Request-URI presence/length only |
| `sip.Call-ID` | `FT_STRING` | Call-ID presence/length only |
| `sip.CSeq`, `sip.CSeq.seq`, `sip.CSeq.method` | `FT_STRING`, `FT_UINT32`, `FT_STRING` | CSeq evidence |
| `sip.Via`, `sip.Via.branch`, `sip.Via.transport` | `FT_STRING` | Via count and privacy-safe metadata |
| `sip.From`, `sip.from.tag` | `FT_STRING` | From count and tag presence/length |
| `sip.To`, `sip.to.tag` | `FT_STRING` | To count and tag presence/length |
| `sip.Max-Forwards` | `FT_UINT32` | integer value |
| `sip.Content-Type` | `FT_STRING` | safe base media type |
| `sip.Content-Length` | `FT_UINT32` | integer value |
| `sip.Route` | `FT_STRING` | occurrence count |
| `sip.Record-Route` | `FT_STRING` | occurrence count |
| `sip.Contact` | `FT_STRING` | occurrence count |
| `sip.Authorization` | `FT_STRING` | occurrence count |
| `sip.Proxy-Authorization` | `FT_STRING` | occurrence count |
| `sip.WWW-Authenticate` | `FT_STRING` | occurrence count |
| `sip.Proxy-Authenticate` | `FT_STRING` | occurrence count |
| `sip.P-Asserted-Identity` | `FT_STRING` | occurrence count |
| `sip.P-Preferred-Identity` | `FT_STRING` | occurrence count |
| `sip.msg_body` | `FT_BYTES` | presence and byte length only |
| `sip.header_not_terminated`, `sip.header_no_colon` | `FT_NONE` | decoder integrity findings |
| `sip.Status-Code.invalid`, `sip.Call-ID.invalid`, `sip.content_length.invalid`, `sip.sec_mechanism.malformed`, `sip.unrecognized_header` | `FT_NONE` | decoder integrity findings |

TShark emits the SIP request/status start line as a child-bearing field; the
extractor searches the SIP protocol subtree for these reviewed names rather than
assuming a flat child order. Reassembly metadata is emitted in the decoder's
`tcp.segments` group and is read from the packet subtree.

## Sanitized dissector-record JSONL

One JSON object per line. Unknown fields are rejected so a caller cannot smuggle
unreviewed semantics into the contract.

Required:

```json
{
  "frame_number": 1,
  "transport": {
    "protocol": "UDP",
    "source_address": "192.0.2.10",
    "source_port": 5060,
    "destination_address": "192.0.2.20",
    "destination_port": 5060
  },
  "headers": {}
}
```

Optional record fields:

| Field | Meaning |
| --- | --- |
| `capture_file` | capture identity; defaults to `capture.pcap` |
| `frame_time_epoch` | source epoch string; converted to UTC ISO-8601 |
| `frame_time_relative` | capture-relative seconds with nine fractional digits |
| `message_occurrence` | positive occurrence within the frame; defaults to 1 |
| `integrity_findings` | reviewed decoder finding labels |
| `capture_truncated` | boolean capture truncation evidence |
| `observation_role` | optional `CLIENT`, `SERVER` or `UNKNOWN` capture-side declaration; defaults to `UNKNOWN` |

Transport fields: `protocol` (`UDP` or `TCP`), endpoints, optional `stream_id`,
`reassembly` (`NOT_APPLICABLE`, `SINGLE_SEGMENT`, `REASSEMBLED`, `INCOMPLETE`,
`UNKNOWN`), `reassembled_length` and `segment_count`. Plaintext SIP events must
declare `UDP` or `TCP`; `TLS` and other transports are rejected as invalid input.

Header fields: `method`, `status_code`, `reason_phrase`, `request_uri`, `call_id`,
`cseq_sequence`, `cseq_method`, `via` (array of `{branch, sent_by, transport}`),
`from` and `to` (objects with `count`, `tag` and optional `uri`), `max_forwards`,
`content_type`, `content_length`, `body_length`, and the reviewed `*_count`
occurrence fields. `via.sent_by` is the top Via sent-by value (`host:port` or
`host`); it is mandatory for modern matching. `from.uri` and `to.uri` are required
for legacy matching but are never published. Raw `branch`, `sent_by`, `call_id`,
tags and URIs are consumed in memory and never published.

The optional transaction output is defined by `schemas/sip-transactions.schema.json`
and `references/transactions.md`. It contains opaque transaction references,
matching mode, observed evidence status, optional RFC transaction state and role,
response-branch and retransmission classifications with fingerprint confidence,
capture completeness, CANCEL/ACK association evidence and missing evidence.

Raw values supplied for identity, URI, tag, Call-ID, credential or body fields are
consumed only to compute presence and length. They are never copied to the output.