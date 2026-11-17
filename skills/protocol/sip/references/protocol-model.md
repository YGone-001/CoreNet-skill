# SIP protocol model

SIP is a text-based request/response protocol. This Skill observes individual
messages; it does not reconstruct SIP transactions, dialogs or IMS procedures.

## Message identity

A message is a `REQUEST` when the decoder exposes a request method, and a
`RESPONSE` when it exposes a three-digit status code or a status line. A SIP
protocol instance without either is retained as `UNKNOWN` and classified
`MALFORMED`; the decoder evidence is not discarded.

The request method is preserved as a bounded token. Reviewed core methods are
tagged `CORE`; any other valid method token is tagged `EXTENSION`. Extension
methods are evidence, not unsupported data, and no IMS meaning is attached.

The response status code is protocol-local evidence. The Skill never turns a code
into transaction, registration, authentication or call success. A reviewed
standard reason phrase may be published; a non-standard phrase is withheld and
only its presence and length remain.

## Start line and mandatory evidence

A request start line supplies the method and Request-URI. A response start line
supplies the status code and reason phrase. The Skill publishes Request-URI
presence and length only, never the URI value.

CSeq presence and Call-ID presence are recorded. A message missing CSeq or Call-ID
is `INCOMPLETE`, not malformed. A message missing its start line, carrying
decoder-reported header damage, or exposing an invalid status code is `MALFORMED`.
A capture-truncated message is `TRUNCATED`.

An unanswered request and a response without its request are both valid observed
messages. They are never dropped and never paired by timing.

## Header observations

| Header | Published evidence |
| --- | --- |
| CSeq | presence, sequence number, method token, occurrence count |
| Via | count, branch presence/length, transport names |
| From / To | count, tag presence/length |
| Call-ID | presence, length, occurrence count |
| Max-Forwards | integer value |
| Content-Type | safe base media type only |
| Content-Length | integer value |
| Route / Record-Route / Contact | occurrence count |
| Authorization / Proxy-Authorization | occurrence count |
| WWW-Authenticate / Proxy-Authenticate | occurrence count |
| P-Asserted-Identity / P-Preferred-Identity | occurrence count |

A missing optional header is not a malformed message. Occurrence counts are
bounded by the publishing schema; no raw header value is published.

## Transport

The Skill publishes UDP or TCP, source/destination address and port, TCP stream
index and decoder-delivered reassembly status. For TCP, reassembly status is
`REASSEMBLED` when the decoder exposes reassembled segment metadata, otherwise
`SINGLE_SEGMENT` or `INCOMPLETE`. The Skill does not reassemble TCP streams itself.

The event belongs to the frame where the decoder delivers the SIP message. Earlier
segment frames are not synthesised as SIP observations.

## Non-goals

Transaction matching, dialog identity, registration state, authentication state,
SDP negotiation, RTP media and IMS failure boundaries are outside this Protocol
layer. Those belong to later Correlation, Domain and Orchestration work.