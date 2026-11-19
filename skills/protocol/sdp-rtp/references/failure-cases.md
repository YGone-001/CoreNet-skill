# SDP failure and ambiguity cases

| Case | Result |
| --- | --- |
| Valid single media | `OBSERVED` with one media section |
| Multiple media sections | separate media records; no merging |
| Audio and video | separate media types and formats |
| IPv4/IPv6 connection | address family/class published; raw address redacted |
| Static/dynamic RTP payloads | `STATIC` and `DYNAMIC` classification |
| `rtpmap` | payload, encoding, clock and channels only |
| `fmtp` | bounded parameter metadata; arbitrary values remain uninterpreted |
| Directions | session/media separate; conflicting values `AMBIGUOUS` |
| Session vs media attributes | separate inventories; no effective merge |
| `rtcp` / `rtcp-mux` | port and mux presence; address redacted |
| BUNDLE group | mids and reference status; no media merge |
| Missing mandatory field | `INCOMPLETE`, never a valid media verdict |
| Invalid media port | message `INVALID`, no fabricated media section |
| Invalid payload declaration | media `INVALID`; no RTP success |
| Duplicate/contradictory attribute | `AMBIGUOUS`; no preferred value |
| Malformed line | `INVALID`; malformed line metadata only |
| Mixed line endings | accepted; style published as `MIXED` |
| Unknown attribute | uninterpreted evidence with name/length only |
| Unknown line type | `UNSUPPORTED`; raw value not published |
| Truncated body | `INCOMPLETE` |
| Oversized body | `INVALID` / `OVERSIZED_INPUT` |
| Sensitive attribute | presence classification and redacted length only |
| Capture provenance mismatch | input rejected |
| Duplicate source reference | input rejected |
| BUNDLE reference to missing MID | `AMBIGUOUS` / `UNRESOLVED` |
| Deterministic replay | byte-identical JSON and report |

Missing or contradictory evidence is never converted into a media-success verdict.

## RTP/RTCP failure cases

| Case | Result |
| --- | --- |
| RTP v2 fixed header | `OBSERVED` |
| Marker / static or dynamic payload type | Numeric observation only; no codec inference |
| Sequence/timestamp at boundaries | Exact numeric preservation |
| Multiple CSRCs | Count and identifiers preserved |
| Extension/padding | Presence and bounded metadata; extension bytes never published |
| Missing RTP fields | `INCOMPLETE` |
| Invalid RTP ranges | `INVALID` |
| Truncated RTP packet | `INCOMPLETE` |
| RTP version 0/1/3 | `UNSUPPORTED` |
| RTP version outside 0-3 or non-integer | `INVALID` |
| RTP padding/extension/marker missing | `INCOMPLETE`, never false |
| RTP padding/extension/marker invalid type/value | `INVALID` |
| RTP padding true without count | `INCOMPLETE` |
| RTP extension true without profile/length | `INCOMPLETE` |
| RTP payload field present in input | Ignored; limitation recorded; never output |
| RTCP Sender Report | Sender fields and report blocks preserved |
| RTCP Receiver Report | Signed cumulative loss preserved, including negative values |
| Multiple report blocks | Nested association preserved |
| Fraction lost / jitter | Receiver-reported values; no local conversion |
| SDES CNAME/other items | Item type/name, presence and redacted length only |
| SDES count matches chunks | `OBSERVED` |
| SDES chunk hierarchy missing | `INCOMPLETE` |
| SDES declared/observed count mismatch | `AMBIGUOUS` |
| BYE sources/reason | Source identifiers and redacted reason length only |
| BYE count matches sources | `OBSERVED` |
| BYE source hierarchy missing | `INCOMPLETE` |
| BYE declared/observed count mismatch | `AMBIGUOUS` |
| BYE invalid source identifier | `INVALID` |
| Zero-source BYE | `OBSERVED` with a useless-but-valid limitation |
| Compound RTCP | Component order preserved when structured input proves it |
| Multiple components | Independent identities and references |
| APP / RTPFB / PSFB / XR / unknown | `UNSUPPORTED`; no payload |
| Malformed RTCP length | `INVALID` |
| Invalid report-block binding | `AMBIGUOUS`/`INCOMPLETE`; no arbitrary SSRC |
| Truncated compound component | `INCOMPLETE` |
| Mixed capture provenance | Input rejected |
| Absolute/path-form capture_file | Input rejected without path leakage |
| Duplicate reference | Input rejected |
| TShark unavailable | Explicit tool-unavailable failure; capture path NOT RUN |
| Unsupported TShark field | Explicit unsupported-field failure |
| Explicit decode-as | Passed to TShark; no port inference |
| Output collision | Rejected |
| Deterministic replay | Byte-identical JSON and report |
