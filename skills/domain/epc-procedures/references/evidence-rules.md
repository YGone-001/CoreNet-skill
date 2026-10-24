# Evidence and Association Rules

## Binding

1. A NAS-EPS event binds to an S1AP event only when both share the capture file and
   frame number and that S1AP event carries a NAS-PDU.
2. Exactly one such S1AP event is required. Zero yields `unbound_evidence`; more than
   one yields `ambiguous_evidence` with the candidate list.
3. Timestamps are never used. Sequence adjacency is never used.
4. The S1AP event and the NAS-EPS event on one frame describe one signaling
   observation, not two transactions.

## Context extension

A context with only an eNB identifier is extended to an MME identifier only when
exactly one MME-UE-S1AP-ID is observed for the same capture, association and eNB
identifier. Otherwise the context stays separate and is marked `AMBIGUOUS` with the
reason recorded.

## Attempt boundaries

A terminal decision closes an attempt. A later `Attach request` on the same context
opens a new attempt with `attempt_index` incremented. Reuse of numeric identifiers
across different contexts never merges them.

## Evidence references

Every stage, observation and deviation carries frame-anchored references:
protocol, frame number, message type and evidence level. A deviation without a frame
is only permitted for derived limitations such as insufficient terminal evidence, and
it is then marked `DERIVED` with an observation window.

## Privacy

No field of this output derives from subscriber identity, authentication parameters or
payload bytes. Only message identities, numeric S1AP identifiers, frames, causes and
pseudonymous references appear.
