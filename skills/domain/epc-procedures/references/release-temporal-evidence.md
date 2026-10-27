# Release Temporal Evidence

Contract for the frame-aware temporal reporting of the EPC release narrative
(`analyze_epc_release_narrative.py`). It consumes the accepted EPC S1-U
observation, the accepted EPC bearer lifecycle and, optionally, the detailed
GTP-U events.

## Three intervals

For one release, the narrative distinguishes:

```text
before_release        frames strictly before the Delete Session Request
pending_release       frames from the request through the confirmation, inclusive
after_confirmation    frames strictly after the Delete Session Response
```

The intervals are exclusive by construction: every counted G-PDU frame falls into
exactly one of them inside one narrative, and no frame is counted in two
narratives.

The pending-release interval is an observation window, not a claim. Traffic
inside it is not evidence that forwarding continued after the request, and its
absence is not evidence that forwarding stopped. The confirmation frame is a
control-plane anchor and never the forwarding-stop instant.

## Capture ownership

The capture is part of the endpoint identity. A stream is only considered for a
narrative when the stream's own `capture_file` equals the narrative's
`capture_file`:

```text
the same receiving address and TEID in two captures are two different endpoints
the same frame number in two captures is two different frames
```

A stream whose receiving endpoint equals a proved generation's endpoint but whose
capture differs is never attributed. It is published as `unbound_evidence` with
kind `stream_endpoint_matches_a_proved_generation_in_another_capture`, whatever
the endpoint values say and whoever the lifecycle names.

An equal receiving TEID with a different receiving address in the same capture is
published as `stream_shares_a_teid_with_a_proved_generation_without_its_receiving_address`.
An equal TEID is not a bearer identity.

## Generation attribution

An endpoint match is a candidate, not an ownership proof. The narrative attributes
a stream to a proved generation only when every one of the following holds:

```text
the stream's capture equals the narrative capture
exactly one proved generation of that narrative owns the endpoint
the stream's association_status is SUPPORTED
the stream publishes a stream_reference
the lifecycle generation_scoped_s1u_observations collection proves its own declared
  count: present, nonnegative, not boolean, equal to the published record array
exactly one generation_scoped_s1u_observation names this capture, this generation
  and this stream_reference, with association_status SUPPORTED and a
  receiving_endpoint_role equal to both the generation's role and the stream's role
the named generation resolves to exactly one capture
no other proved generation claims the same stream
```

The lifecycle generation-scoped S1-U observation is the only accepted producer
contract that establishes generation-level user-plane ownership: a `SUPPORTED`
S1-U stream association names a default-bearer subject, never a bearer
generation. The narrative therefore never equates the two.

### Collection completeness

The scoped-attribution collection is assessed on its own declared count
(`generation_scoped_observation_count`), because the accepted producer truncates
the published array at 256 records while publishing the full count. A visible
subset is not a complete ownership candidate set:

```text
declared > published     SOURCE_CANDIDATES_TRUNCATED
declared < published     SOURCE_CANDIDATES_METADATA_INVALID
missing / null / boolean / negative / non-integer
                         SOURCE_CANDIDATES_METADATA_INVALID
```

While the collection is incomplete, no stream is attributed and no packet is
assigned, but the release outcome, the release-session binding and any
independently proved generation closure are unaffected. Closure completeness and
temporal-attribution completeness are distinct evidence requirements, and the
scoped collection is deliberately not part of the closure gate.

### One internally consistent record

The accepted producer emits at most one scoped record per accepted stream, so a
repeated `(capture, generation, stream)` key is always a contradiction. The
narrative keeps every record and refuses the attribution:

```text
conflicting_lifecycle_generation_scoped_attribution
```

It never selects the first record, the last record or the record with the
strongest-looking status, and the verdict is identical for every input ordering.

A record must also publish the mandatory ownership fields. A missing
`receiving_endpoint_role` does not bypass the role check:

```text
lifecycle_generation_scoped_attribution_publishes_no_receiving_endpoint_role
lifecycle_generation_scoped_attribution_names_another_receiving_role
lifecycle_generation_scoped_attribution_names_another_receiving_role_than_the_stream
lifecycle_generation_scope_is_not_unique
```

### Refusal record

When the gate fails, the record is still published as diagnostic traffic:

```text
generation_attribution_status    NOT_ESTABLISHED
generation_attribution_basis     endpoint_equality_alone_is_not_generation_ownership
attribution_failures             closed-vocabulary reasons
partitions                       null
observed_g_pdu_count             the accepted aggregate, unchanged
```

No packet of an unattributed stream is assigned to a release window, and the
stream's aggregate counts are never discarded or upgraded.

## Evidence bases

```text
FRAME_LEVEL_EVENTS
  Detailed GTP-U events resolve every counted packet. The three partitions
  reproduce the accepted aggregate count and octet count exactly, and each
  publishes its own G-PDU count, payload octets and frame bounds.
  partition_scope is COMPLETE_STREAM and temporal_placement_status is ESTABLISHED.

FRAME_LEVEL_EVENTS_INCOMPLETE
  Detailed GTP-U events exist but do not reproduce the accepted aggregate. The
  observed frames keep their own positions with partition_scope OBSERVED_SUBSET,
  while temporal_placement_status stays TEMPORAL_PLACEMENT_NOT_ESTABLISHED.

FRAME_LEVEL_EVENTS_CONFLICTED
  Another release narrative claims at least one of these G-PDU frames. No
  partition is published and the record fails closed.

AGGREGATE_STREAM_ONLY
  Only an aggregate directed-stream summary is available. The stream is published
  whole, with temporal_placement_status TEMPORAL_PLACEMENT_NOT_ESTABLISHED, and
  no packet or octet count is divided across windows.

GENERATION_ATTRIBUTION_NOT_ESTABLISHED
  The stream could not be attributed to the generation, so no temporal claim is
  made about it.
```

Proportional interpolation is forbidden. An aggregate count carries no temporal
placement, and the narrative says so rather than inventing one.

## Partition proof

An observed frame set and a complete partition are two different facts. Individually
observed frames always have a valid temporal position, but the complete stream is
only partitioned when the frame set reconciles with the accepted aggregate:

```text
partition_conserved = counted G-PDUs == aggregate G-PDUs
                  and counted payload octets == aggregate payload octets
```

When it does not reconcile, `partition_conserved` is `false`,
`temporal_placement_status` is `TEMPORAL_PLACEMENT_NOT_ESTABLISHED`,
`partition_scope` is `OBSERVED_SUBSET`, and a limitation names the discrepancy. The
observed subset is preserved, the aggregate stays authoritative, and no missing
packet or octet is interpolated. The narrative never adjusts the source accounting
and never claims conservation while the counts disagree.

## Duplicate ownership

A G-PDU frame belongs to exactly one release window. Before any partition is
published the narrative builds an ownership map over `(capture, frame_number)`.
When two candidate narratives claim the same frame:

```text
both records publish duplicate_frame_ownership = true
both records publish partition_basis FRAME_LEVEL_EVENTS_CONFLICTED
neither record publishes a partition
the frame is assigned to no release window
duplicate_assignment_count counts the conflicted frames
```

Publishing two incompatible established partitions for one packet is never
permitted, even when both candidates look individually well-formed.

## G-PDU identity

Only GTP-U `G-PDU` messages are counted. `Echo Request`, `Echo Response`,
`End Marker` and `Error Indication` keep their own message types and are never
counted as G-PDUs. The stream key is the accepted one: capture, outer source
address, outer destination address and header TEID. A TEID alone never identifies
a stream.

## Global temporal accounting

```text
observed_g_pdu_event_count        distinct G-PDU events supplied
assigned_to_release_window_count  events placed in exactly one established partition
unassigned_g_pdu_event_count      events no established partition claims
duplicate_assignment_count        events claimed by two or more narratives
attributed_observation_count      records whose attribution gate passed
unattributed_observation_count    records whose attribution gate refused
conserved                         duplicate_assignment_count == 0 and every event
                                  is accounted for
```

A cross-interface narrative view may reference the same underlying observation,
but a frame claimed twice is counted in neither partition.

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

When no detailed GTP-U events are supplied, every record stays
`TEMPORAL_PLACEMENT_NOT_ESTABLISHED` and the global accounting reports
`frame_level_evidence_supplied = false`.
