# SDP field reference and normative review record

## Normative review record

| Specification | Clauses reviewed | Use |
| --- | --- | --- |
| RFC 8866 (January 2021, obsoletes RFC 4566) | Sections 5.1-5.14 and Section 9 (SDP grammar) | Line grammar, required session order, origin/name/connection/timing/media structure, attributes, media descriptions and limits |
| RFC 8866 | Sections 6.6, 6.7, 6.15 | `rtpmap`, media direction attributes and `fmtp` vocabulary |
| RFC 3550 | Sections 5.1, 5.2, 5.3, 5.3.1, 6.1, 6.4, 6.5, 6.6, 6.7 | RTP fixed header/extension and RTCP SR/RR/SDES/BYE structure |

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

## RTP fixed header and extension fields

| Field | Published evidence |
| --- | --- |
| `rtp.version` | Two-bit range 0-3; version 2 supported, other representable versions `UNSUPPORTED`, values outside 0-3 `INVALID` |
| `rtp.padding`, `rtp.padding.count` | Tri-state presence: explicit false/true preserved, missing `INCOMPLETE`, invalid `INVALID`; count required when true |
| `rtp.ext`, `rtp.ext.profile`, `rtp.ext.len` | Tri-state presence; profile/length required when true; extension data never published |
| `rtp.cc`, `rtp.csrc.item` | CSRC count and safe numeric identifiers; count mismatch is `AMBIGUOUS` |
| `rtp.marker`, `rtp.p_type` | Tri-state marker and numeric payload type; missing marker is `INCOMPLETE`, invalid `INVALID` |
| `rtp.seq`, `rtp.timestamp`, `rtp.ssrc` | Sequence, timestamp and SSRC; SSRC reference is capture-scoped |
| `frame.number`, `frame.time_epoch`, `udp.stream`, `udp.stream.pnum` | Frame/transport provenance only; UDP stream is not an RTP session identity |

A dynamic payload type is numeric evidence only. No codec, media session, subscriber
identity or delivery verdict is derived from payload type, UDP port or SSRC.

## RTCP subset

| Packet family | Published evidence |
| --- | --- |
| SR (200) | Sender SSRC, NTP MSW/LSW and presence, RTP timestamp, sender packet/octet counts, report blocks |
| RR (201) | Sender SSRC, report count, reported SSRC, fraction lost, signed cumulative packets lost, extended highest sequence, interarrival jitter, LSR, DLSR |
| SDES (202) | declared source count, observed chunk count, source SSRC, item type/name, presence and redacted length; item text never published |
| BYE (203) | declared source count, observed source list/count, source identifiers, reason presence/redacted length; reason text never published |
| APP (204) | `UNSUPPORTED`; application data never published |
| RTPFB (205), PSFB (206) | `UNSUPPORTED`; feedback data never published |
| XR (207), AVB (208), RSI (209) | `UNSUPPORTED` |
| Unknown | `UNSUPPORTED`/`UNKNOWN`; no payload |

Report blocks are nested under their component in structured input. Flat repeated
arrays are not zipped by position. If component/report-block association is not proven,
the component is `AMBIGUOUS` or `INCOMPLETE` and no arbitrary SSRC is selected.

For SDES/BYE the header source-count field is validated against nested chunks/sources:
missing hierarchy is `INCOMPLETE`; a declared/observed mismatch is `AMBIGUOUS`.
`rtcp.ssrc.cum_nr` is a signed 24-bit receiver-reported value; negative values are
preserved. `rtcp.ssrc.fraction` and `rtcp.ssrc.jitter` are receiver-reported values.
Jitter remains in RTP timestamp units; no millisecond or MOS conversion is performed.

## Input modes

- Structured JSONL: deterministic offline records with explicit nested RTCP
  components/report blocks.
- Authorized capture: installed TShark JSON tree, reviewed allowlist, optional explicit
  `-d` decode-as mappings. No protocol inference from UDP ports, SDP or payload type.
  TShark JSON compound RTCP components may be unavailable; the limitation is explicit.

## TShark fields verified locally

The installed TShark exposes `rtp.version`, `rtp.padding`, `rtp.ext`, `rtp.cc`,
`rtp.marker`, `rtp.p_type`, `rtp.seq`, `rtp.timestamp`, `rtp.ssrc`, `rtcp.version`,
`rtcp.pt`, `rtcp.length`, `rtcp.senderssrc`, `rtcp.ssrc.*`, `rtcp.sdes.*`,
`udp.stream` and `udp.stream.pnum`. The extractor probes these fields before capture
extraction and fails explicitly if any reviewed field is unavailable. Payload fields
(`rtp.payload`, `udp.payload`, `rtcp.app.data`, SDES text) are never exported.

## Limits

- Structured input: 1,024 records, 16 RTCP components per compound packet, 31 report
  blocks, 16 SDES chunks/items and 16 BYE sources per component.
- `capture_file` must be a safe basename; absolute paths and path separators are rejected.
- RTP packet length and all numeric fields are range-validated.
- Capture extraction is bounded by the same event limits and does not persist raw
  TShark JSON.
