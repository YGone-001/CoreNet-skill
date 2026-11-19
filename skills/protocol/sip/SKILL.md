# SIP

## Purpose

Answer WHAT SIP requests and responses, and which reviewed SIP header facts, were
observed in a capture; WHICH observed requests and responses belong to the same
protocol-local SIP transaction; and WHICH observed INVITE-created SIP dialog branches
are supported by the accepted transaction evidence. This is a Protocol-layer Skill
for SIP message extraction, transaction correlation and bounded dialog evidence over
UDP and TCP. It preserves source provenance and publishes privacy-safe presence and
length metadata instead of subscriber identities, URIs, dialog tags, Call-ID values,
credentials or message bodies.

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
- Publish privacy-safe Expires, Min-Expires and Contact expiration metadata. Contact
  evidence includes header-occurrence counts plus wildcard, non-wildcard, explicit,
  zero, positive, malformed and default-expiration entry counts, a boundary status, a
  wildcard-boundary classification and whether the evidence is complete enough for a
  removal-scope conclusion. A wildcard token is recognised only at a provable
  top-level Contact boundary, including a wildcard mixed with another value or
  repeated in one header field. Commas inside an angle-bracketed URI or a quoted
  display name are not boundaries. An unbracketed comma, unbalanced delimiter,
  truncated value or otherwise unprovable boundary is published as `UNRESOLVED`; no
  individual Contact count is fabricated. No Contact URI is published.
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
  transaction JSON document, an optional dialog evidence JSON document and an
  optional shared trace-event projection.

## Dialog evidence

Dialog analysis consumes the same capture-local private message records and the
accepted transaction document:

- Dialog identity requires the capture, Call-ID, the initial INVITE From tag and a
  response To tag. Call-ID alone is never a dialog identity, and identical
  identifiers in two captures never share one dialog.
- A tagged 180/183 establishes Early Dialog evidence; 100 Trying never creates a
  dialog.
- A 2xx response with a To tag establishes or confirms the matching dialog branch.
- One INVITE may produce multiple independently identified forked dialogs with
  distinct To tags; repeated responses on one branch do not duplicate a dialog.
- A distinct initial INVITE transaction that reuses an established capture-scoped
  identity is published as a `REUSED_DIALOG_IDENTITY` unbound observation; it is
  never silently merged and no lifecycle generation is inferred.
- A 2xx ACK is associated only with a uniquely supported Confirmed Dialog; its Via
  branch may differ from the INVITE.
- BYE, re-INVITE, UPDATE, INFO, PRACK, REFER and MESSAGE are associated to one
  established dialog using the capture, tag pair, Call-ID and direction. A re-INVITE
  does not create a new dialog.
- BYE with a 2xx response on a confirmed dialog publishes `TERMINATED`; a BYE without
  a response keeps the dialog `CONFIRMED` and publishes termination signaling without
  claiming completion.
- Incomplete captures and dialog-shaped contexts without a creator remain explicit
  unbound or ambiguous observations; no preceding INVITE or confirmed dialog is
  fabricated.
- Every bounded reference collection publishes `reference_accounting` with observed
  unique, published and omitted counts that conserve the observed total.
- CSeq gaps are computed within each dialog direction separately; a numeric gap is
  observation only and never a packet-loss or IMS verdict.

See `references/dialogs.md` for the identity, forking, ACK, in-dialog and lifecycle
rules. Dialog evidence never establishes IMS registration, call success, RTP media or
two-way audio.

## Non-Goals

- No IMS registration, authentication, call, session, SDP or RTP semantics.
- No dialog timeout or capture-boundary termination inference.
- No full SUBSCRIBE/NOTIFY subscription-dialog state machine.
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
- Optional SIP dialog evidence JSON (`schemas/sip-dialogs.schema.json`).
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
  --dialog-output /tmp/sip-dialogs.json \
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
- Dialog identity is capture-scoped and derived from the initiating INVITE From tag
  plus a response To tag; it is not a portable subscriber identity. A capture file
  name is the accepted capture identity and does not distinguish separately acquired
  captures that share a basename.
- Dialog state reflects signaling evidence only. `TERMINATED` requires a BYE with a
  2xx response on a confirmed dialog; no RTP, media or IMS outcome is inferred.
- CSeq sequence gaps are per direction; no packet-loss or call-failure verdict is
  derived from a gap.
- Dialogs that begin before the capture are reported as unbound observations, never
  as fabricated initial INVITEs.
- Non-INVITE dialog usages such as SUBSCRIBE/NOTIFY are recognized but not modelled.
- SIP dialog evidence is protocol-local; IMS Domain procedure analysis remains
  outside this Skill.