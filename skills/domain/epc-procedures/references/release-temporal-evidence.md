# Release Temporal Evidence

Contract for the frame-aware temporal reporting of the EPC release narrative
(`analyze_epc_release_narrative.py`). It consumes the accepted EPC S1-U
observation and, optionally, the detailed GTP-U events.

## Three intervals

For one release, the narrative distinguishes:

```text
before_release        frames strictly before the Delete Session Request
pending_release       frames from the request through the confirmation, inclusive
after_confirmation    frames strictly after the Delete Session Response
```

The intervals are exclusive by construction: every G-PDU frame falls into exactly
one of them, so a frame is never counted twice inside one narrative.

The pending-release interval is an observation window, not a claim. Traffic
inside it is not evidence that forwarding continued after the request, and its
absence is not evidence that forwarding stopped. The confirmation frame is a
control-plane anchor and never the forwarding-stop instant.

## Two evidence bases

```text
FRAME_LEVEL_EVENTS
  Detailed GTP-U events resolve individual packets. Counts are computed from the
  actual events and each partition publishes its own G-PDU count, payload octets
  and frame bounds.

AGGREGATE_STREAM_ONLY
  Only an aggregate directed-stream summary is available. The stream is published
  whole, with temporal_placement_status TEMPORAL_PLACEMENT_NOT_ESTABLISHED, and
  no packet or octet count is divided across windows.
```

Proportional interpolation is forbidden. An aggregate count carries no temporal
placement, and the narrative says so rather than inventing one.

## Partition conservation

When frame-level events are used, the three partitions must reproduce the accepted
aggregate stream count and octet count exactly. The result is published as
`partition_conserved`. If they do not reproduce it, the aggregate stays
authoritative, the partition is published as a separate observation and a
limitation names the discrepancy. The narrative never adjusts the source
accounting.

## G-PDU identity

Only GTP-U `G-PDU` messages are counted. `Echo Request`, `Echo Response`,
`End Marker` and `Error Indication` keep their own message types and are never
counted as G-PDUs. The stream key is the accepted one: capture, outer source
address, outer destination address and header TEID. A TEID alone never identifies
a stream.

## Global temporal accounting

```text
observed_g_pdu_event_count        distinct G-PDU events supplied
assigned_to_release_window_count  events placed in some release narrative
unassigned_g_pdu_event_count      events no narrative claims
duplicate_assignment_count        events claimed twice; must be zero
conserved                         duplicate_assignment_count == 0
```

A cross-interface narrative view may reference the same underlying observation,
but a frame claimed twice is not counted twice: the duplicate is dropped from the
second narrative and counted in `duplicate_assignment_count`, which makes
`conserved` false and publishes a limitation.

## Frame order and timestamps

Frame ordering is valid inside one capture file. The narrative never imposes a
global order across unrelated captures, and every record is capture-scoped.

Timestamps are observed metadata only. Timestamp proximity never establishes
identity, never places a packet and never links two captures.

## Post-confirmation traffic

Traffic observed after the confirmation frame is published as an observation
requiring interpretation. It is not automatically packet loss, not automatically
delivered traffic and not evidence of a faulty network function. A proved
generation boundary does not forbid a later observed G-PDU: the boundary is a
reviewed control-plane relationship, and the physical forwarding state at that
instant remains unproven.

## Missing evidence

When the release request or its confirmation frame is unavailable, no window is
constructed, `partitions` is `null`, and the record publishes
`TEMPORAL_PLACEMENT_NOT_ESTABLISHED` with the reason. A missing anchor is reported,
never filled in.
