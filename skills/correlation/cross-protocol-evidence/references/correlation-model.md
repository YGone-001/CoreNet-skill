# Correlation Model

Deterministic grouping of protocol events by shared capture provenance.
The layer decides what belongs together; it never decides what happened.

## Input

Already-extracted detailed events from the authoritative Protocol
Skills: NGAP detailed events (from `ngap`) and NAS-5GS detailed events
(from `nas-5gs`). This layer parses neither protocol; each event is
validated only for provenance fields (timestamp, frame_number,
capture_file) and sensitive-data policy, then treated as foreign
evidence to be preserved verbatim.

## Strength levels

- STRONG — at least two events share `capture_file` and
  `frame_number`. This is the strongest join: both protocol Skills
  extracted observations from the same captured frame.
- MEDIUM — events in the same capture whose adjacent timestamps differ
  by at most the bounded window (default 1.0 second; configurable with
  `--window-seconds` within 0..3600). Chaining is pairwise: each
  adjacent pair in the group is within the window, and the window is
  documented rather than inferred. MEDIUM groups never claim the events
  describe the same frame.
- WEAK — a single event with only capture context. Weak evidence is
  never merged automatically; it forms its own single-event group so
  the partial timeline stays visible. A single event never receives
  STRONG or MEDIUM because no join actually occurred.

## Determinism and single membership

Every input event lands in exactly one group. Grouping runs per capture
in three deterministic stages: same-frame clusters first (STRONG),
then a timestamp-window pass over the remaining events in stable time
order (MEDIUM), then singletons (WEAK). Groups are emitted sorted by
capture, first frame, strength, and first timestamp; embedded events
are sorted by frame, timestamp, protocol, and input order. Identical
input always yields byte-identical output.

Duplicates are preserved as separate observations: repeating an event
in the input repeats it in the output with stable ordering. Observations
are never silently deduplicated, because dropping one could drop
evidence.

## Foreign protocol metadata

Embedded events keep their original fields. NGAP UE-context identifiers
(AMF-UE-NGAP-ID, RAN-UE-NGAP-ID) are foreign metadata: preserved
verbatim, never parsed, renamed, reinterpreted, or copied into generic
subscriber or session concepts. NAS identity values are accepted only
in redacted form; a non-null identity value is rejected at load time.

## What this model does not do

No subscriber correlation, no session correlation, no registration
correlation, no transaction or procedure state machine, no cross-capture
identifier merging. Numeric identifier matches across captures or
protocols are meaningless here; only provenance joins and bounded time
proximity are used.
