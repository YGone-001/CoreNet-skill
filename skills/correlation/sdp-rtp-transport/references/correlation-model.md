# Correlation Model

Deterministic transport endpoint correspondence only. The layer decides which
SDP media description and RTP UDP stream share an exact capture-scoped endpoint;
it never decides what happened to the call or media.

## Inputs

Accepted SDP Analysis and RTP/RTCP Analysis artifacts. No SDP body, RTP payload
or capture is read here. The only join key is the HMAC endpoint reference, which
already includes the capture SHA-256.

## Stream grouping

Accepted RTP packets are grouped by:

```text
capture identity + udp.stream
```

The group is capture-local. `udp.stream` is not a SIP dialog, IMS session,
subscriber identity or globally unique identifier. A packet without
`udp.stream` stays an ungrouped packet and is never promoted to a stream
association.

For each stream the analysis preserves unique packet references, source and
destination endpoint references, observed SSRC references, packet count, first
and last frame numbers and endpoint-set consistency.

## Match directions

- `RTP_SOURCE_ENDPOINT_MATCH`: the SDP endpoint equals the RTP packet source.
- `RTP_DESTINATION_ENDPOINT_MATCH`: the SDP endpoint equals the RTP packet
  destination.

Direction is a transport observation. It is never interpreted as an IMS sender
or receiver role, call direction or subscriber identity.

## Statuses and strength

| Status | Meaning | Strength |
|---|---|---|
| `MATCHED_ENDPOINT` | One SDP endpoint equals one unique RTP UDP stream endpoint | `STRONG` |
| `BUNDLE_TRANSPORT_MATCHED` | One resolved BUNDLE group with one shared endpoint equals one unique stream | `STRONG` |
| `AMBIGUOUS` | Multiple streams, competing media owners or a conflicting stream endpoint set | `MEDIUM` |
| `INSUFFICIENT_EVIDENCE` | Endpoint or stream evidence is missing, incomplete or ICE-dependent | `WEAK` |
| `UNMATCHED` | A valid SDP endpoint has no observed RTP stream | `WEAK` |
| `OUT_OF_SCOPE` | Disabled, multicast, unspecified, link-local, unresolved-name, bundle-only or unsupported transport | `WEAK` |

`STRONG` means exact HMAC endpoint equality only. It is evidence grouping, not
causal confidence and not IMS session identity.

## BUNDLE

A media section is bundle-eligible only when it has a non-ambiguous MID and
belongs to exactly one resolved `a=group:BUNDLE` group. Several media sections
are grouped into one `BUNDLE_TRANSPORT_MATCHED` record only when they belong to
the same resolved group and share the same valid endpoint reference. The record
lists all associated media sections; none is selected as the demultiplexed
owner. RTP header-extension MID demultiplexing is not implemented.

Unresolved BUNDLE groups, multiple groups, missing MID and duplicate MID
preserve ambiguity instead of inventing a shared transport.

## Multiple candidates

At minimum the model distinguishes:

1. One SDP endpoint to one UDP stream.
2. One SDP endpoint to multiple UDP streams.
3. Multiple SDP media sections to one UDP stream.
4. Multiple SDP messages with the same endpoint reference.
5. One UDP stream whose endpoint set changes.
6. One stream matching both source and destination observations.
7. BUNDLE group sharing one transport.
8. Missing UDP stream identity.
9. Missing endpoint references.
10. Endpoint context mismatch.

No nearest-timestamp winner is selected. Timestamp proximity is never used.

## What this model does not do

- No IMS session identity, call identity or subscriber correlation.
- No NAT rewriting, ICE candidate selection, STUN, TURN, DTLS or SRTP.
- No RTP stream reconstruction, RTCP stream correlation, packet-loss, jitter,
  MOS or QoS calculation.
- No media-delivery, two-way-audio or call-success verdict.