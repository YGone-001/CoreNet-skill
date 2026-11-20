# Sequence Validation

## Source

Bounded RFC 3550 Appendix A.1 sequence-number tracking with the documented
constants:

| Constant | Value | Meaning |
| --- | --- | --- |
| `RTP_SEQ_MOD` | `65536` | 16-bit sequence-number modulus |
| `MIN_SEQUENTIAL` | `2` | Sequential packets required before a source is valid |
| `MAX_DROPOUT` | `3000` | Largest forward gap accepted as in order |
| `MAX_MISORDER` | `100` | Largest backward distance accepted as reordering |

No alternative sequence semantics are implemented.

## Probation

For a previously unseen source the state is initialized as:

```text
init_seq(s, seq)
s.max_seq = seq - 1
s.probation = MIN_SEQUENTIAL
```

The first packet is then evaluated by the same probation branch. A source with
`MIN_SEQUENTIAL = 2` therefore becomes validated on its second sequential
packet. Until then the epoch status is `PROBATION`, and the analysis publishes
`SEQUENTIAL_VALIDATION_INCOMPLETE`. A capture that starts mid-stream cannot be
declared continuous.

Published statuses:

- `PROBATION` — the source has not completed sequential validation;
- `VALIDATED` — sequential validation completed;
- `INSUFFICIENT_EVIDENCE` — no sequence-eligible packet exists;
- `AMBIGUOUS` — an unconfirmed restart candidate leaves continuity unresolved
  at the end of the capture.

## Validated state

For `udelta = (seq - max_seq) mod 65536`:

1. `udelta < MAX_DROPOUT` — in order with a permissible gap. If `seq < max_seq`
   the 16-bit sequence wrapped and one cycle is added.
2. `udelta <= RTP_SEQ_MOD - MAX_MISORDER` — a very large jump. A packet equal to
   the pending bad-sequence value confirms resynchronization and starts a new
   epoch; otherwise the packet is a restart candidate and is not accepted as a
   sequence position.
3. Otherwise — a duplicate or reordered packet.

A value of `MAX_DROPOUT` itself is not in order. With `MAX_MISORDER = 100`, a
backward distance of exactly 100 is a very large jump under the RFC arithmetic,
while 99 is treated as duplicate or reordered.

## Extended sequence numbers

Each epoch reconstructs epoch-local extended positions as
`cycles * 65536 + sequence`. Wrapping is counted, never treated as a restart or
as a large gap:

```text
65534 -> 65535 -> 0 -> 1
```

produces extended positions `65534, 65535, 65536, 65537`. A late packet from a
previous cycle is mapped back to its nearest cycle so that duplicate detection
does not confuse two different occurrences of the same 16-bit value.

## Duplicates and reordering

- A repeated extended position within one epoch is a duplicate observation.
- A new extended position earlier than the highest observed position is an
  out-of-order observation.
- Duplicate observations do not imply retransmission and out-of-order
  observations do not imply a cause.
- Neither classification reorders the original event inventory.

## Gaps

A gap is opened when an accepted in-order observation is more than one position
beyond the highest observed extended position. Published evidence includes:

- the start and end event references;
- the start and end extended positions;
- the unobserved 16-bit sequence numbers;
- whether a later reordered observation filled a previously observed gap;
- the remaining unobserved slot count.

Only slots inside the observed validated range are calculated. Leading and
trailing missing packets are never inferred. A gap means
`UNOBSERVED_SEQUENCE_NUMBERS`; it is never a network packet-loss verdict.

## Restart patterns

A restart candidate is the packet rejected as a very large jump. If the next
draw from the sequence state equals the stored bad sequence value, the source is
resynchronized into a new independent epoch and the pattern is published as
`CONFIRMED`. Otherwise the candidate remains `UNCONFIRMED`.

The analysis never infers that a restart was caused by a UE reboot, application
restart, network interruption, SSRC collision or RTP sender replacement.

## Capture boundaries

The first observed sequence number is not the stream origin. The final observed
sequence number is not proof of stream termination. Every stream carries
`CAPTURE_BOUNDARY_COMPLETENESS_UNKNOWN`, and no leading or trailing gap is
published.