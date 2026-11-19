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