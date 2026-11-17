# SIP

## Purpose

Answer WHAT SIP requests and responses, and which reviewed SIP header facts, were
observed in a capture. This is a Protocol-layer Skill for SIP message extraction
over UDP and TCP. It preserves source provenance and publishes privacy-safe
presence and length metadata instead of subscriber identities, URIs, dialog tags,
Call-ID values, credentials or message bodies.

## Scope

- Extract SIP requests and responses over IPv4 and IPv6.
- Support SIP over UDP and SIP over TCP, including TCP segmentation reassembled by
  the accepted TShark decoder.
- Preserve frame number, frame time, capture-relative time, transport endpoints,
  TCP stream identity and message occurrence within a frame.
- Preserve request method, response status code, a reviewed standard reason phrase,
  CSeq number and method, Via branch presence/length, From/To tag presence/length,
  Max-Forwards, Content-Type, Content-Length, body presence/length, and bounded
  header occurrence counts.
- Preserve message completeness, dissector findings, truncation and missing
  mandatory evidence as explicit classifications.
- Publish one sanitized JSONL event per observed SIP message, plus an optional
  shared trace-event projection.

## Non-Goals

- No SIP transaction correlation and no dialog correlation.
- No IMS registration, authentication, call, session, SDP or RTP semantics.
- No inferred transaction success from a status code.
- No plaintext extraction from TLS or other encrypted transports.
- No custom TCP/IP reassembly; the decoder-delivered SIP message is the observation
  boundary.
- No raw Call-ID, From/To URI, Via branch, Contact, Route, P-Asserted-Identity,
  Authorization, WWW-Authenticate, message header dump or message body publication.
- No subscriber identity, IMSI, MSISDN, credential, nonce or authentication vector.

## Inputs

| Input | Description |
| --- | --- |
| PCAP / PCAPNG | A capture containing plaintext SIP over UDP or TCP. Requires an installed TShark; the capture is dissected to PDML. |
| PDML | A stored `tshark -T pdml` dissection. No decoder is required at run time. |
| Sanitized JSONL | Reviewed dissector-record input described in `references/field-reference.md`. No decoder is required. |

## Outputs

- SIP event JSONL (`schemas/sip-events.schema.json`).
- Optional shared trace-event JSONL projection (`schemas/trace-event.schema.json`).

## Evidence semantics

Fields are `OBSERVED` when they come from the verified TShark dissection or a
reviewed dissector record. A message is `COMPLETE`, `INCOMPLETE`, `MALFORMED` or
`TRUNCATED` according to explicit start-line, CSeq, Call-ID, decoder-finding and
capture-truncation evidence. An unknown extension method is retained with
`method_scope: EXTENSION`; no IMS procedure meaning is attached.

## Privacy

Subscriber identities, SIP URIs, dialog tags, Call-ID values, Via branches,
credentials and message bodies are never published. They are represented only by
presence, occurrence count and bounded length. Standard reason phrases and safe
media types may be published; arbitrary reason phrases and media-type parameters
are withheld. See `references/privacy.md`.

## Supported decoder

Verified against TShark 4.2.2. The reviewed field names are listed in
`references/field-reference.md`. TCP reassembly metadata is read from the
decoder's reassembled segment group; the Skill does not reassemble streams itself.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Extraction succeeded. |
| 2 | Invalid input (capture signature, JSONL structure or unsupported record shape). |
| 3 | No plaintext SIP messages observed. |
| 4 | TShark is unavailable. |
| 5 | TShark execution or dissection failure. |
| 6 | Output destination or publication failure. |

## Reproduction

```bash
python3 skills/protocol/sip/scripts/extract-sip.py \
  skills/protocol/sip/examples/pdml/base-udp.pdml \
  --output /tmp/sip-events.jsonl \
  --trace-output /tmp/sip-trace.jsonl \
  --force

python3 skills/protocol/sip/scripts/extract-sip.py \
  /path/to/capture.pcapng \
  --output /tmp/sip-events.jsonl \
  --force

python3 -m unittest discover -s skills/protocol/sip/tests -p 'test_*.py' -v
python3 scripts/validate-sip.py
```

## Known limitations

- Encrypted SIP over TLS is not decrypted and produces no SIP event.
- SIP over WebSocket, SIP over SCTP and other encapsulations are unsupported.
- Multiple SIP messages in one frame are published only when the decoder exposes
  multiple SIP protocol instances.
- A TCP observation belongs to the frame where the decoder delivers the reassembled
  message; earlier segment frames are not synthesised as SIP events.
- Transaction and dialog correlation belong to later Correlation and Domain layers.