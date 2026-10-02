# GTP-U Failure Cases

Protocol-local abnormal or inconclusive patterns this Skill can report.
Each pattern names what is OBSERVED, what is DERIVED, and the hard boundary
against causal overreach.

## User-plane observation patterns

- G-PDU observed with no PDU Session Container — fully valid evidence. The
  absence of a container is not an error, and no QFI is invented.
- One-way traffic only — packets observed in a single directed context.
  Report it as "traffic observed only in this direction within the available
  capture". Never "downlink failed" or "uplink works, downlink broken".
- Opaque inner packet — the encapsulated packet is ESP/IPsec or otherwise
  opaque. The opacity flag and the bounded protocol metadata are preserved
  and analysis stops; no decryption is attempted.
- Truncated capture — the capture ends before the expected continuation.
  The observation boundary is stated; nothing is inferred from what is
  missing.

## Sequence and duplicate patterns

- Numeric sequence gap — for example observed sequence numbers 100, 101 and
  103. A `sequence_discontinuity_candidate` may be raised as a
  non-conclusive flag. **Packet loss is never concluded**, because GTP-U
  sequence numbers are optional and their use depends on the procedure and
  context.
- Missing sequence number — the S flag is clear, so no sequence number
  exists in that header. The field stays null; a zero is never fabricated.
- Repeated sequence number — reported as a duplicate-observation candidate
  with its basis. The frames are never deleted, deduplicated, or called
  retransmissions.

## Header and message patterns

- Malformed structured input — missing or non-integer frame number, a
  message type outside 0..255, a TEID outside the 32-bit range, a sequence
  number outside the 16-bit range, or an invalid extension header entry. The
  extractor fails loudly per record; it never guesses.
- Unknown message type — a code outside the reviewed table is UNKNOWN with
  the numeric code preserved and no invented name or class.
- Known but unsupported message — Tunnel Status (253) is recognized and
  UNSUPPORTED with no semantics beyond the bounded header fields.
- Unexpected TEID rule where normatively provable — a G-PDU or End Marker
  observed with an all-zeroes header TEID. The reviewed rule expects the
  tunnel TEID, so a limitation is recorded. The value is never corrected and
  the packet is never dropped.
- Unknown extension header type — preserved as UNKNOWN with its observed
  numeric value. The packet is not dropped and no semantics are invented.

## Container and QFI patterns

- Ambiguous QFI — several PDU Session Container values observed in one
  message. The container object is omitted and every observed value is
  preserved as unbound evidence. No value is selected arbitrarily, and the
  generic `session.qfi` is omitted.
- Container observed but not safely attributable — the container fields are
  visible yet the parent relation cannot be proven. The values are kept as
  unbound metadata with a limitation rather than attached to an arbitrary
  header.

## Control-message patterns

- Error Indication observed — the affected tunnel TEID and the header TEID
  are preserved separately. The message states that a peer has no tunnel
  context; it is never converted into automatic blame of a node, and it is
  not an end-to-end root cause.
- End Marker observed — preserved for its directed TEID context. It is
  signalling evidence, not proof that a tunnel teardown completed end to
  end, and not proof that user-plane traffic stopped.
- Echo Request without a visible Echo Response — reported as an observation
  boundary in a partial capture. It never becomes "the peer is unavailable".
- Echo Response without a visible Echo Request — the capture may simply
  start after the request. An observed Echo Response proves only that the
  response was observed at the capture point; it never proves that all
  GTP-U tunnels are functioning.
- Supported Extension Headers Notification observed — the advertised types
  are preserved. An advertisement is not proof that any particular tunnel
  is actively using those extensions.

## TEID scope patterns

- Same numeric TEID on different endpoint pairs — kept as separate directed
  contexts. They are never merged.
- Same numeric TEID in opposite directions — kept as separate directed
  contexts, because the two directions name two different tunnel endpoints.
- Two different TEIDs between the same endpoint pair — kept as separate
  contexts.

## Cross-protocol patterns (reported, never performed)

- A PFCP-provisioned F-TEID that is not observable within this GTP-U capture
  is a **future cross-protocol analysis**, not something this Skill
  concludes. This Skill never joins GTP-U TEIDs to PFCP F-TEIDs, NGAP
  transport tunnels, or NAS PDU Session IDs.

## Application payload boundary

Application payload bytes are never persisted to events, timelines, stream
summaries, or trace projections. A structured inner packet that carries
payload fields fails loudly. Inner L4 ports are packet metadata only: a
UDP/5060 observation does not become "SIP" inside this Skill, and no HTTP,
DNS, RTP, TLS or QUIC content is decoded.

## Explicitly out of scope for causal claims

This Skill does not confirm tunnel success or failure, does not diagnose
UPF, SMF, gNB or transport defects, does not verify radio delivery, does not
infer packet loss, and does not produce an end-to-end root cause. Its
evidence ceiling for cause attribution is INFERRED, and only for
protocol-local relationships such as the observed direction of a packet.
