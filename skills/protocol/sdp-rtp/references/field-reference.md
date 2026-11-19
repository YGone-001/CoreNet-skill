# SDP field reference and normative review record

## Normative review record

| Specification | Clauses reviewed | Use |
| --- | --- | --- |
| RFC 8866 (January 2021, obsoletes RFC 4566) | Sections 5.1-5.14 and Section 9 (SDP grammar) | Line grammar, required session order, origin/name/connection/timing/media structure, attributes, media descriptions and limits |
| RFC 8866 | Sections 6.6, 6.7, 6.15 | `rtpmap`, media direction attributes and `fmtp` vocabulary |

The RFC was directly retrieved from the RFC Editor and reviewed for this
implementation. The parser is bounded and does not claim complete RFC 8866
conformance for every extension or every registered SDP attribute.

## Structural fields

| Field | Published evidence |
| --- | --- |
| `v=` | `sdp_version`; only version 0 is supported as observed structure |
| `o=` | username presence/length/redaction, session-id presence/length/redaction, session version, network type, address type/family/class |
| `s=` | presence, length and redaction only; session text is never published |
| `c=` | network type, address type/family/class, multicast flag, TTL, address count; address redacted |
| `t=` | bounded numeric start/stop values and unbounded flag |
| `m=` | media type, port, port count, protocol and payload format classifications |
| Session attributes | independent session-scoped inventory |
| Media attributes | independent media-scoped inventory; never merged with session attributes |

## Recognised attributes

| Attribute | Published representation |
| --- | --- |
| `rtpmap` | payload type, encoding name, clock rate, optional channels |
| `fmtp` | payload type, parameter count/names, safe reviewed metadata values, omitted count |
| `sendrecv`, `sendonly`, `recvonly`, `inactive` | direction per scope; conflicting directions become `AMBIGUOUS` |
| `mid` | safe token; conflicting values become `AMBIGUOUS` |
| `rtcp` | port, address family/class only, address redacted |
| `rtcp-mux` | boolean presence |
| `group` | semantics, bounded mids and reference status |
| `ptime`, `maxptime` | bounded numeric values |
| `setup` | safe role enum |
| `ice-options` | bounded safe option tokens |
| `ice-lite` | boolean presence |
| `ice-ufrag`, `ice-pwd`, `candidate`, `remote-candidates`, `fingerprint`, `crypto`, `identity` | sensitive presence classification, redacted length and safe reviewed metadata only |

Unknown attributes remain in `unknown_attributes` with name, value presence, length and
`UNINTERPRETED` classification. Unknown line types remain in `unknown_lines` and make
the message `UNSUPPORTED`.

## Scope rules

Session-level and media-level attributes are stored in separate arrays. The parser does
not compute effective media attributes by merging session defaults into media sections.
A BUNDLE `group` reference is checked against the media MIDs and is `RESOLVED`,
`UNRESOLVED` or `PENDING`; it never collapses or reorders media sections.

## Limits

- 512 supplied messages.
- 65,536 bytes per SDP body.
- 8,192 characters per line.
- 64 media sections.
- 256 attributed descriptors per scope.
- 64 formats per media section.
- 32 published list/FMTP parameter items.

Input exceeding the body limit is `INVALID` with `OVERSIZED_INPUT`; it is not parsed
partially.

## Evidence limits

A structurally valid `m=` line, RTP mapping, direction or BUNDLE group is observation
of an SDP declaration. It does not prove offer/answer agreement, media negotiation,
RTP delivery, endpoint reachability, QoS, IMS registration or call success.