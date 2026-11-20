# Failure Cases

## Input contract failures

| Case | Required behavior |
|---|---|
| Wrong SDP or RTP/RTCP analysis name or version | Rejected, exit `2`, no output |
| Wrong SDP or RTP/RTCP event schema version | Rejected, exit `2`, no output |
| Different capture basenames | Rejected, exit `2`, no output |
| Different capture SHA-256 values | Rejected, exit `2`, no output |
| Different endpoint contexts | Rejected, exit `2`, no output |
| Duplicate SDP message, media or RTP event reference | Rejected, exit `2`, no output |
| Invalid media index or endpoint-reference syntax | Rejected, exit `2`, no output |
| Output collides with an input | Rejected, exit `6`, no output |

## Match failures

| Case | Required behavior |
|---|---|
| One SDP endpoint, one stream | `MATCHED_ENDPOINT`, `STRONG` |
| One SDP endpoint, multiple streams | `AMBIGUOUS`, no stream selected |
| Multiple unrelated media sections, one endpoint | `AMBIGUOUS`, `UNRELATED_MEDIA_SHARE_ENDPOINT` |
| Multiple SDP messages share one endpoint | `AMBIGUOUS`, no message selected |
| Stream source/destination endpoint set changes | `AMBIGUOUS`, `UDP_STREAM_ENDPOINT_SET_CONFLICT` |
| One stream equals both source and destination | `AMBIGUOUS`, `SOURCE_AND_DESTINATION_ENDPOINT_SHARED` |
| Valid endpoint, no observed stream | `UNMATCHED`, `NO_OBSERVED_RTP_STREAM_FOR_ENDPOINT` |
| Advertised and observed endpoints differ | `UNMATCHED`; no NAT mapping invented |

## Missing-evidence failures

| Case | Required behavior |
|---|---|
| No endpoint key was used | `INSUFFICIENT_EVIDENCE`, `ENDPOINT_REFERENCE_UNAVAILABLE` |
| SDP message or media is not `OBSERVED` | `INSUFFICIENT_EVIDENCE`, `SDP_EVIDENCE_NOT_OBSERVED` |
| Missing RTP `udp.stream` | Packet counted as ungrouped; no stream association |
| Missing RTP endpoint fields | Stream `INCOMPLETE`; no established match |
| Non-observed RTP event | Excluded from stream grouping; counted separately |
| RTCP event | Never promoted to an RTP stream |
| ICE candidate or credentials present | `INSUFFICIENT_EVIDENCE`, `ICE_SELECTED_TRANSPORT_NOT_ESTABLISHED` |
| Disabled, multicast, unspecified, link-local, domain-name, bundle-only or unsupported transport media | `OUT_OF_SCOPE` with the bounded reason code |
| Encapsulated or multiple transport-layer candidates | `AMBIGUOUS`, `MULTIPLE_TRANSPORT_CANDIDATES` |

## BUNDLE failures

| Case | Required behavior |
|---|---|
| Resolved BUNDLE group, one shared endpoint and one stream | `BUNDLE_TRANSPORT_MATCHED` |
| Unresolved BUNDLE group | No bundle claim; shared endpoint remains ambiguous or unmatched |
| Multiple resolved BUNDLE groups for one MID | No bundle claim |
| Missing or duplicate MID | No invented bundle membership |
| Bundle-only media with a zero port | `OUT_OF_SCOPE`, `MEDIA_DISABLED` |

## Security and privacy failures

| Case | Required behavior |
|---|---|
| Missing, malformed or non-owner-only key file | Rejected before output |
| Key generator target already exists | Refused; existing key untouched |
| Key generator target inside the repository | Refused |
| Raw address, port, endpoint tuple or key material in output | Validation failure |