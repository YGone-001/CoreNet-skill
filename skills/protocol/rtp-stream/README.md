# rtp-stream

`rtp-stream` is an independent Protocol Skill that reconstructs bounded RTP
source-stream and sequence-integrity evidence from an already-accepted
RTP/RTCP Analysis artifact.

It is not an IMS Domain, a Correlation Skill, a packet-loss meter or a QoS
engine. It consumes the accepted `sdp-rtp` Protocol output and never decodes an
RTP packet itself.

## Responsibility

- Group observed RTP packets into capture-scoped source streams using the exact
  composite identity `capture_sha256 + udp_stream + ssrc_reference`.
- Keep different UDP streams and different SSRCs separate even when their
  endpoints look identical.
- Run the bounded RFC 3550 Appendix A.1 sequence validation algorithm with
  `RTP_SEQ_MOD = 65536`, `MIN_SEQUENTIAL = 2`, `MAX_DROPOUT = 3000` and
  `MAX_MISORDER = 100`.
- Reconstruct epoch-local extended sequence numbers, including 16-bit wrap.
- Report sequence probation, duplicates, out-of-order packets, unobserved
  sequence-number slots and restart patterns.
- Account for every RTP input event exactly once: assigned to a source stream or
  published in the unassigned packet inventory.
- Count RTCP components without ever associating them with an RTP stream.

## Non-goals

RTP payload, audio/video, codec, SDP Offer/Answer, SIP dialog, IMS session,
SDP-to-RTP correlation, RTCP-to-RTP correlation, packet-loss verdict, jitter,
MOS, QoS, ICE, STUN, TURN, NAT, DTLS, SRTP, header-extension MID
demultiplexing, subscriber/IMS identity and media-delivery or call verdicts are
out of scope.

## Dependencies

Required: the `sdp-rtp` Protocol Skill (version `0.4.0` or later) providing:

- `schemas/rtp-rtcp-events.schema.json` (event schema `1.2.0`);
- `scripts/rtp_rtcp_model.py` and its endpoint reference helper.

The Skill is standalone apart from that accepted Protocol dependency. If the
dependency cannot be located the CLI fails closed with a clear message.

## Installation

Copy `skills/protocol/rtp-stream/` together with the accepted
`skills/protocol/sdp-rtp/` package. No third-party runtime dependency is needed
for reconstruction; the repository validator uses the bounded `jsonschema`
dependency for strict schema validation and falls back to the accepted
structural and semantic checks with an explicit published limitation when it
is unavailable.

## Input

One RTP/RTCP Analysis JSON:

- analysis name `rtp-rtcp`;
- analysis version `0.4.0`;
- event schema version `1.2.0`;
- parser version `0.4.0`.

Endpoint references are optional. A missing HMAC endpoint key does not block
sequence reconstruction. Raw IP addresses, raw UDP ports, payload bytes and key
material are never published.

## Output

- `rtp-stream` Analysis JSON, analysis version `0.1.0`, event schema `1.0.0`,
  validated against `schemas/rtp-stream-analysis.schema.json`.
- Optional deterministic plain-text report.

The output preserves the source analysis SHA-256, the capture identity, the
source-stream and epoch inventory, unassigned RTP packets, RTCP event counts
with `NOT_INTERPRETED_FOR_RTP_STREAM_ASSOCIATION`, completeness counters,
limitations and explicit `not_confirmed` boundaries.

## Usage

```bash
python3 scripts/reconstruct-rtp-streams.py \
  --rtp-rtcp-analysis accepted-rtp-rtcp-analysis.json \
  --output rtp-stream-analysis.json \
  --report rtp-stream-report.txt
```

Exit codes:

| Code | Meaning |
| --- | --- |
| `0` | Reconstruction completed |
| `2` | Malformed, contradictory or unverifiable input |
| `6` | Output path collision, existing destination without `--force`, or write failure |

`--expected-source-sha256 <64 lowercase hex>` optionally pins the source
artifact, and `--force` replaces an existing destination.

## Evidence semantics

A sequence gap is `UNOBSERVED_SEQUENCE_NUMBERS`, never a confirmed network
packet loss. A duplicate observation does not prove retransmission. An
out-of-order observation does not prove a cause. A restart pattern is only the
implemented RFC 3550 bad-sequence resynchronization behaviour; its physical
cause is never inferred. Capture boundaries remain unknown, so no leading,
trailing or termination inference is published.

## Testing

```bash
python3 -m unittest discover -s skills/protocol/rtp-stream/tests -p 'test_*.py' -v
python3 scripts/validate-rtp-stream.py
```

Fixtures are synthetic and sanitized. No capture, raw address, port, payload or
subscriber identity is committed.

## Provenance

Original CoreNet implementation. RFC 3550 Appendix A.1 supplies the bounded
sequence validation algorithm; no upstream code was imported. See
`manifest.yaml` for the versioned contract.