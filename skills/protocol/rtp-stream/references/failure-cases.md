# Failure Cases

## Rejected input

The CLI exits with code `2` and produces no output when:

| Condition | Reason |
| --- | --- |
| Wrong analysis name | The artifact was not produced by the accepted `sdp-rtp` RTP/RTCP producer |
| Wrong analysis, event schema or parser version | The artifact contract is not the accepted `0.4.0` / `1.2.0` / `0.4.0` triple |
| Accepted-schema violation | The artifact does not match `rtp-rtcp-events.schema.json` |
| Source artifact SHA-256 mismatch against an explicit expectation | The supplied artifact is not the pinned source |
| Mixed capture file or capture SHA-256 | Two captures cannot be reconstructed as one source inventory |
| Duplicate event references | Each accepted packet reference must be unique |
| Frame reference or reference suffix inconsistency | Frame identity is contradictory |
| Event-count or completeness disagreement | The artifact counters do not describe its events |
| Missing or malformed endpoint context | Endpoint references cannot be published without their scope |
| Malformed or missing artifact | The source is not valid UTF-8 JSON or is not an object |

## Event-level classification (not a hard rejection)

- Missing or invalid UDP stream identifier: unassigned packet with a
  `UDP_STREAM_UNAVAILABLE` reason.
- Missing, malformed or conflicting SSRC reference: unassigned packet with the
  corresponding SSRC reason.
- Missing sequence number on an otherwise identified stream: assigned,
  `incomplete_packet_count` incremented, not sequence-eligible.
- Upstream `INVALID`, `UNSUPPORTED` or `AMBIGUOUS`: assigned but excluded from
  sequence evidence.
- Unsupported RTP version: assigned but excluded.
- An upstream `INCOMPLETE` event with valid sequence-critical fields remains
  eligible.

Every RTP event is accounted for exactly once. No event is silently dropped and
no event is assigned to two streams.

## Indeterminate but not failed

- `PROBATION`: the source did not complete sequential validation inside the
  capture. This is an incomplete-evidence outcome, not a protocol error.
- `AMBIGUOUS`: a restart candidate is unconfirmed at capture end. Continuity
  after that observation remains unresolved.
- `INSUFFICIENT_EVIDENCE`: the stream has no sequence-eligible packet.
- A gap that is later filled by reordered observations is preserved as gap
  evidence with `filled_by_later_observation = true` and a remaining unobserved
  slot count of zero.

## Output failure

Exit code `6` covers:

- the output or report path equals the input artifact;
- the destination exists and `--force` was not supplied;
- the destination directory does not exist;
- atomic write or replacement failed.

## Never produced

The Skill never publishes network packet loss, retransmission cause, restart
cause, SSRC collision, sender replacement, jitter, MOS, QoS, RTP delivery,
two-way audio, call success, RTCP-to-RTP association or teardown. If evidence is
insufficient, the limitation is stated and the relevant value is not inferred.