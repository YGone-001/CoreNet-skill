# GTP-U Stream Correlation

Protocol-local grouping of observed GTP-U traffic into directed tunnel
contexts. Deterministic, endpoint-scoped, and deliberately non-conclusive
about anything beyond observation.

## Directed context scope

A stream is scoped by:

1. capture identity (safe capture basename plus frame provenance);
2. the outer source endpoint (address and UDP port);
3. the outer destination endpoint (address and UDP port);
4. the observed header TEID.

The derived key is:

    gtpu-path:<capture>:<source>:<destination>:teid<id>

It is DERIVED and explicitly **not** a standardized GTP-U identifier. A TEID
alone is never used, because the receiving side locally assigns the TEID
value and unrelated peer pairs may reuse the same number.

## TEID reuse and direction

Two rules are enforced and tested:

- The same numeric TEID on different endpoint pairs produces **separate**
  streams. They are never merged.
- The same numeric TEID in opposite directions between the same endpoint
  pair produces **separate** streams, because the two directions name two
  different tunnel endpoints.

No stream is ever created, merged or renamed by TEID alone, and no stream
uses a globally unique TEID assumption.

## No cross-protocol session join

This Skill never matches a GTP-U TEID to a PFCP F-TEID, an NGAP transport
tunnel, or a NAS PDU Session ID. Two opposite directed contexts are not
assumed to belong to one PDU Session merely because timestamps overlap,
endpoints reverse, or TEID numbers are similar. Binding both directions
requires PFCP/NGAP context and belongs to a future Domain Skill.

## Packet and byte observation semantics

- `observed_g_pdu_packet_count` counts G-PDUs observed in the capture for
  that directed context. It is never an end-to-end delivery count.
- `observed_payload_byte_count` sums the GTP-U Length field, whose reviewed
  definition is "the length in octets of the payload, i.e. the rest of the
  packet following the mandatory part of the GTP-U header". That single
  definition is recorded in every stream and is never mixed with frame-byte
  or packet-byte definitions.
- Counts describe what was observed at one capture point. They are not
  network-wide traffic volumes.

## Sequence numbers

GTP-U sequence numbers are optional: they are present only when the S flag
is set, and their use depends on the procedure and context. This Skill
therefore:

- preserves the observed sequence numbers in order;
- exposes `sequence_discontinuity_candidate` as a **non-conclusive** flag
  when the observed values are not contiguous;
- never emits a packet-loss conclusion, and never labels a gap as loss.

A fixture with observed sequence numbers 100, 101 and 103 must therefore
produce a discontinuity candidate and nothing stronger. Tests enforce this.

## Duplicate observations

Identical G-PDU observations may have several explanations. This Skill never
calls them retransmissions: when two G-PDUs in one stream carry the same
sequence number, the later frames are listed as
`duplicate_observation_candidates` with the basis stated, and every observed
frame is preserved.

## One-way evidence

When packets are observed in only one directed context, the correct
statement is "traffic was observed only in this direction within the
available capture". It is never "downlink failed", "uplink works but
downlink is broken", or any similar conclusion: those require
higher-layer role and observation-point evidence that this Skill does not
own.

## Ordering and partial captures

Input order is not authoritative. Timeline and summary output sort
deterministically by timestamp and frame number while preserving the
original provenance of each record.

A capture can begin or end mid-tunnel. Absence of an End Marker, an Error
Indication, or reverse-direction G-PDU is not automatically abnormal, and
the summary states the observation boundary instead of drawing a
conclusion.

## Capture-point limitation

GTP-U analysis is observation-point specific. Packets observed on a
UPF-facing interface do not prove they were transmitted over the radio to
the UE, and no G-PDU in one capture does not prove that no G-PDU existed
elsewhere in the network.
