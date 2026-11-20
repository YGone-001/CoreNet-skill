# Stream Identity

## Composite identity

An RTP source stream is identified only by the capture-scoped composite key:

```text
capture_sha256 + udp_stream + ssrc_reference
```

The published reference is:

```text
rtp-source-stream:<capture_file>:<udp_stream>:<ssrc_hex>
```

`<ssrc_hex>` is the eight-lowercase-hexadecimal suffix of the accepted
capture-scoped `ssrc_reference`. The raw SSRC value is not published as a
standalone identity when that reference exists.

## Rules

| Observation | Result |
| --- | --- |
| Same capture, same UDP stream, same SSRC reference | One candidate source stream |
| Same SSRC reference on different UDP streams | Separate source streams |
| Different SSRC references on the same UDP stream | Separate source streams |
| Same source stream with several observed payload types | One stream with a payload-type inventory |
| Missing or invalid UDP stream | Unassigned RTP packet |
| Missing, malformed or conflicting SSRC reference | Unassigned RTP packet |
| Missing sequence evidence with valid stream identity | Assigned but not sequence-eligible |

Different UDP streams are never merged because their endpoint references are
equal. Different SSRC references are never merged because their endpoint
references are equal. A capture mismatch is rejected as contradictory input.

## Event eligibility

An event participates in sequence reconstruction only when all sequence-critical
fields are independently valid:

- RTP version is supported version `2`;
- the sequence number is present and in `0..65535`;
- the SSRC reference is valid and agrees with the capture;
- the UDP stream identifier is available;
- capture, frame number, occurrence and reference identity are valid.

An upstream `INCOMPLETE` event may still be eligible when these fields are
valid. Events marked `INVALID`, `UNSUPPORTED` or `AMBIGUOUS` are assigned to
their stream but excluded from sequence evidence. They are never silently
promoted.

## Deterministic ordering

Within a stream, packets are processed by:

1. `frame_number`;
2. `message_occurrence`;
3. `event_reference`.

Sequence order never replaces capture observation order. Original event
references are preserved on the stream record.

## Endpoint evidence

Optional capture-scoped HMAC endpoint references are preserved at stream level:

- `source_endpoint_references`;
- `destination_endpoint_references`;
- `endpoint_evidence_status`;
- `endpoint_context_reference`.

One distinct source endpoint reference yields
`source_endpoint_identity_status = ESTABLISHED`. Multiple distinct source
references yield `AMBIGUOUS`, without silently selecting one. No reference
yields `UNAVAILABLE`.

A unique endpoint reference is a capture-scoped pseudonym. It never establishes
UE identity, IMS identity, access/core side, sender/recipient role, media
delivery or call success. Raw IP addresses and UDP ports are never published.