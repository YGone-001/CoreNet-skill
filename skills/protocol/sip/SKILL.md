# SIP

## Purpose

Answer WHAT SIP requests and responses, and which reviewed SIP header facts, were
observed in a capture, and WHICH observed requests and responses belong to the same
protocol-local SIP transaction. This is a Protocol-layer Skill for SIP message
extraction and transaction correlation over UDP and TCP. It preserves source
provenance and publishes privacy-safe presence and length metadata instead of
subscriber identities, URIs, dialog tags, Call-ID values, credentials or message
bodies.

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
- Correlate requests and responses using RFC 3261 transaction identity: modern
  magic-cookie matching uses top Via branch, top Via sent-by and request method;
  legacy RFC 2543 branches use Request-URI, To, From, Call-ID, CSeq and top Via.
  Call-ID alone is never a transaction identity.
- Validate request-line method against CSeq method; a contradiction cannot form a
  valid transaction identity.
- Verify CANCEL and non-2xx ACK header consistency against the original INVITE,
  including Request-URI, To/From values, Call-ID, CSeq number and top Via relationship.
- Publish observed evidence status separately from RFC transaction state, with the
  transaction role explicit and `UNKNOWN` when a passive capture cannot establish it.
- Publish matching mode, response branches, transaction state, retransmission
  classification with fingerprint completeness, capture completeness and explicit
  missing evidence.
- Handle CANCEL, non-2xx ACK and 2xx ACK according to separate transaction roles,
  and preserve RFC 6026 `ACCEPTED` for INVITE 2xx transactions.
- Publish one sanitized JSONL event per observed SIP message, plus an optional
  transaction JSON document and an optional shared trace-event projection.

## Non-Goals

- No SIP dialog correlation, dialog identity, 2xx ACK dialog association or
  forked-dialog selection.
- No IMS registration, authentication, call, session, SDP or RTP semantics.
- No timer configuration or timeout inference from an unobserved response.
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
- Optional SIP transaction JSON (`schemas/sip-transactions.schema.json`).
- Optional shared trace-event JSONL projection (`schemas/trace-event.schema.json`).

## Evidence semantics

Fields are `OBSERVED` when they come from the verified TShark dissection or a
reviewed dissector record. A message is `COMPLETE`, `INCOMPLETE`, `MALFORMED` or
`TRUNCATED` according to explicit start-line, CSeq, Call-ID, decoder-finding and
capture-truncation evidence. An unknown extension method is retained with
`method_scope: EXTENSION`; no IMS procedure meaning is attached.

Transaction state and matching status are `DERIVED` from observed message identity
and source event references. They do not restate a network verdict. An unobserved
response is capture incompleteness, not a timeout. A 200 OK to CANCEL acknowledges
CANCEL only; the INVITE outcome requires the corresponding INVITE response.

## Transaction correlation

The correlation model follows RFC 3261 Section 17 and RFC 6026. A branch beginning
with `z9hG4bK` uses modern matching: capture, top Via branch, top Via sent-by and
CSeq method. Any other present branch uses legacy matching over Request-URI, To,
From, Call-ID, CSeq and top Via. Missing legacy evidence yields `NOT_ESTABLISHED`
and never falls back to Call-ID. Request method and CSeq method must agree.

CANCEL is its own transaction and is associated with an INVITE only when the
applicable Via relationship, Request-URI, Call-ID, To URI, From URI, tags, numeric
CSeq and both request-line/CSeq methods are observed and consistent. A missing
required value is insufficient evidence and never establishes the association; a
contradiction is reported separately as a conflict. An absent initial To tag on both
messages is legitimate; a tag present on only one side is a conflict. A 200 OK to
CANCEL and a 487 INVITE are published as a `CANCEL_RESPONSE_SEQUENCE_OBSERVED`
evidence sequence; they do not establish RFC `TERMINATED` because timer evidence is
unavailable.

A non-2xx ACK is attached only when its Request-URI, Call-ID, From URI and tag, To
URI, CSeq number, Via relationship and To-tag against the observed final response
are observed and consistent. One shared eligibility result decides association and
reports missing and conflicting fields separately; a missing required field cannot
produce server `CONFIRMED` or client `TERMINATED`. An invalid ACK remains unresolved
and changes no transaction state. A 2xx ACK is an independent request transaction
and is never merged. See `references/transactions.md`.

`transaction_role` is `UNKNOWN` for a passive capture unless the input declares a
side. `observed_evidence_status` describes the capture; `rfc_transaction_state` is
published only when the role is established and `state_semantics` distinguishes the
two. A client INVITE that observes a non-2xx final response plus ACK stays
`COMPLETED`; only the server projection becomes `CONFIRMED`. `TERMINATED` requires
timer or equivalent independently observed transition evidence.

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
  --transaction-output /tmp/sip-transactions.json \
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
- A passive capture cannot establish client or server stack role, so RFC transaction
  state stays unavailable unless the sanitized input declares `observation_role`.
- RFC timer expiry (`TERMINATED`, timer D/H/I/J/M) is never inferred from capture
  silence.
- Legacy matching requires Request-URI, To, From, Call-ID, CSeq and top Via; missing
  values remain `NOT_ESTABLISHED` rather than using a weaker fallback.
- A sanitized field-only fingerprint cannot prove exact message equality; repeats are
  reported as retransmission candidates.
- SIP transaction correlation is protocol-local; SIP dialog correlation and IMS
  procedure analysis remain outside this Skill.