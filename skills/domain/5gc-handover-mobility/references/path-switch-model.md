# Path Switch Attempt Model

## Formation and independence

PathSwitchRequest opens an attempt in one serving context (capture, SCTP
association, RAN-UE-NGAP-ID); PathSwitchRequestAcknowledge and
PathSwitchRequestFailure attach to the latest attempt whose initiation
precedes them. A PathSwitchRequestAcknowledge observed without a visible
Request forms a bounded partial attempt (PARTIAL_CAPTURE); the Request is
never fabricated.

A Path Switch attempt with no handover evidence in the capture is a valid
independent attempt — no MISSING_HANDOVER_REQUIRED deviation is ever
produced. It may for example belong to an Xn handover whose Xn signaling
this Skill does not own; the model does not claim that either.

## Outcomes and resource roles

- PathSwitchRequestAcknowledge is direct successful NGAP elementary-
  procedure outcome evidence. It never proves PFCP acceptance, UPF path
  change, N3 traffic movement, old-tunnel removal, or end-to-end mobility
  success.
- PathSwitchRequestFailure is direct unsuccessful-outcome evidence. The
  reviewed NGAP basis defines no message-level Cause for this message and
  no Cause is invented from released-item presence; released-item causes
  live inside opaque transfers and bind only from structured input.
- Resource roles (TO_BE_SWITCHED, FAILED, SWITCHED, RELEASED) are
  preserved item-scoped exactly as supplied by ngap >=0.3.0. One
  acknowledge with a SWITCHED item and a RELEASED item stays two
  independent observations; it never becomes "all sessions switched".

## Relationship to handover attempts

`related_handover_attempt_id` is set only when exactly one handover
attempt in the same scoped AMF-UE-NGAP-ID context is compatible (the Path
Switch starts after the handover initiation, and the handover has not
already reached a failed or cancelled terminal). The relationship strength
is SUPPORTED, never CONFIRMED. Multiple compatible attempts stay AMBIGUOUS
with all candidates preserved; none leaves the attempt independent with
`related_handover_attempt_id: null` and strength UNBOUND.
