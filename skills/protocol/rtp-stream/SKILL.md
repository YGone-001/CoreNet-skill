# RTP Stream Protocol Skill

## Purpose

Reconstruct bounded RTP source-stream evidence from an already-accepted
RTP/RTCP packet observation artifact and apply the RFC 3550 Appendix A.1
sequence-number validation algorithm. This is a Protocol-layer capability: it
answers *what sequence state was observed for each capture-scoped RTP source
stream*, not whether media was delivered, lost, degraded or successful.

## Input contract

Accept exactly one RTP/RTCP Analysis JSON produced by the `sdp-rtp` Protocol
Skill with:

- analysis name `rtp-rtcp`;
- analysis version `0.4.0`;
- event schema version `1.2.0`;
- parser version `0.4.0`.

The input is validated against the authoritative
`sdp-rtp/schemas/rtp-rtcp-events.schema.json` and the accepted
`rtp_rtcp_model.validate_analysis` implementation. No second RTP decoder exists
in this Skill. No raw PCAP input is accepted and TShark is never executed.

Provenance verification covers the analysis name and versions, the source
artifact SHA-256, a single privacy-safe capture basename and SHA-256, event and
frame identity, unique event references, RTP/RTCP event counts, completeness
counters and an optional endpoint context reference. Contradictory or malformed
artifacts are rejected before any output is produced.

## Workflow

1. Verify the source artifact and all provenance fields.
2. Classify every RTP event exactly once as assigned or unassigned.
3. Group assigned events by `capture_sha256 + udp_stream + ssrc_reference`.
4. Order each stream deterministically by `frame_number`, then
   `message_occurrence`, then `event_reference`.
5. Run the bounded RFC 3550 Appendix A.1 sequence state machine over
   sequence-eligible events.
6. Publish source-stream, epoch, gap, restart and unassigned-packet evidence.
7. Count RTCP events separately and never associate them with an RTP stream.

## Sequence state

Documented constants:

| Constant | Value |
| --- | --- |
| `RTP_SEQ_MOD` | `65536` |
| `MIN_SEQUENTIAL` | `2` |
| `MAX_DROPOUT` | `3000` |
| `MAX_MISORDER` | `100` |

On first observation the source is initialized with `max_seq = seq - 1` and
`probation = MIN_SEQUENTIAL`; the first packet is then evaluated by the same
probation branch. A source is validated only after `MIN_SEQUENTIAL` sequential
packets. A packet more than `MAX_DROPOUT` ahead, or at least `MAX_MISORDER`
behind, is a bad-sequence observation; the next sequential packet forms a new
epoch and the intervening observation is a restart candidate. Wrap is handled
by a 16-bit cycle counter, and every epoch publishes epoch-local extended
sequence positions.

## Output contract

`rtp-stream` analysis version `0.1.0`, event schema version `1.0.0`, validated
against `schemas/rtp-stream-analysis.schema.json`.

Top-level records keep the input provenance, source-stream inventory,
unassigned packet inventory, RTCP count, completeness counters, limitations
and `not_confirmed` boundaries. Every source stream preserves:

- capture, UDP stream and capture-scoped SSRC reference;
- optional source/destination endpoint references and their evidence status;
- payload-type inventory and frame range;
- RTP, eligible, incomplete and excluded packet counts;
- sequence validation status and epochs;
- wrap, duplicate, out-of-order, gap, unobserved-slot and restart counts;
- missing evidence and conflict findings.

## Evidence boundaries

A sequence gap means `UNOBSERVED_SEQUENCE_NUMBERS`. It never means
`NETWORK_PACKET_LOSS_CONFIRMED`. A duplicate observation never implies a
retransmission, and an out-of-order observation never implies a routing or
application cause. An observed restart pattern is only the implemented
bad-sequence resynchronization behaviour; it never proves a UE reboot,
application restart, network interruption, SSRC collision or sender
replacement.

A capture may begin or end mid-stream. Leading and trailing missing packets are
never inferred, the first observed sequence number is not the stream origin and
the final observed sequence number is not stream termination. Only gaps inside
the observed validated range are calculated.

RTCP SR/RR/SDES/BYE components are counted but never assigned to an RTP stream.
A BYE never proves RTP teardown. Remote-reported RTCP values are never
converted into local loss, jitter or QoS statistics.

## Failure behavior

Reject loudly, with exit code `2`, when:

- the source analysis name, version, event schema or parser version differs;
- the source artifact SHA-256 does not match an explicit expectation;
- capture identity is mixed or malformed;
- event references are duplicated or disagree with frame identity;
- completeness counters disagree with the event inventory;
- the optional endpoint context reference is missing or malformed.

Exit code `6` reports output-path failure, collision or a pre-existing
destination without `--force`. Output is written atomically.

## CLI

```bash
python3 scripts/reconstruct-rtp-streams.py \
  --rtp-rtcp-analysis rtp-rtcp-analysis.json \
  --output rtp-stream-analysis.json \
  --report rtp-stream-report.txt
```

Optional: `--expected-source-sha256 <64 lowercase hex>` and `--force`.

## Testing

The test matrix covers input provenance, stream identity, probation,
sequential validation, wrap, duplicates, reordering, gaps, restart patterns,
capture boundaries, eligibility, privacy, schema, count conservation,
truncation accounting, atomic output, collision protection and compatibility
with the accepted upstream `sdp-rtp` fixtures.

```bash
python3 -m unittest discover -s skills/protocol/rtp-stream/tests -p 'test_*.py' -v
python3 scripts/validate-rtp-stream.py
```