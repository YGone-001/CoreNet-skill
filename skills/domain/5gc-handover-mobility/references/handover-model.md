# Handover Attempt Model

## Formation

A source half opens at every observed `HandoverRequired` within one
(capture, SCTP association, RAN-UE-NGAP-ID) context; subsequent
source-role messages (HandoverCommand, HandoverPreparationFailure,
HandoverCancel, HandoverCancelAcknowledge) attach to the latest half whose
initiation precedes them. A target half opens at every observed
`HandoverRequest`; target-role outcomes (HandoverRequestAcknowledge,
HandoverFailure, HandoverNotify) attach the same way. Events that arrive
before any compatible half form bounded partial halves (late capture);
initiations are never fabricated.

## Branches and stage coverage

- Handover Preparation: HandoverRequired with HandoverType, Cause,
  TargetID metadata, source-to-target transparent-container presence, and
  the to-be-handed-over resource list. HandoverRequired observed means
  only that the message was observed: it is not a radio, source-gNB, or
  handover-necessity finding.
- Preparation outcome: HandoverCommand (successful branch, preparation
  progress only) or HandoverPreparationFailure (direct unsuccessful
  outcome, PROTOCOL_NEGATIVE_OUTCOME_OBSERVED).
- Target resource allocation: HandoverRequest, HandoverRequestAcknowledge
  (with admitted and possibly failed resource items), HandoverFailure.
- Execution notification: HandoverNotify is bounded target-side progress
  evidence and never an end-to-end success.
- Cancellation: HandoverCancel (with Cause) and HandoverCancelAcknowledge
  form their own branch. Cancellation is never automatically a failure;
  once a safely associated cancel branch exists, the model stops requiring
  HandoverCommand or HandoverNotify as though execution must continue.

## Missing-evidence rules (branch-aware)

Normatively mandatory counterparts only: HandoverRequired expects
HandoverCommand or HandoverPreparationFailure (unless a cancel branch was
observed); HandoverRequest expects HandoverRequestAcknowledge or
HandoverFailure; HandoverCancel expects HandoverCancelAcknowledge.
HandoverNotify and HandoverCommand carry no mandatory counterpart. Every
missing-evidence deviation carries OBSERVATION_WINDOW provenance and
capture-termination framing: expected-but-not-observed is never reported
as "the network did not send it".

## Terminal observations

Bounded terminal/progress observations: HANDOVER_PREPARATION_FAILURE_OBSERVED,
HANDOVER_RESOURCE_FAILURE_OBSERVED, HANDOVER_COMMAND_OBSERVED,
HANDOVER_NOTIFY_OBSERVED, HANDOVER_CANCEL_OBSERVED,
HANDOVER_CANCEL_ACK_OBSERVED, NO_TERMINAL_MOBILITY_OBSERVATION, and
PARTIAL_CAPTURE for attempts anchored on partial evidence. No
HANDOVER_SUCCESS or end-to-end failure label exists.

## HandoverType scope

The reviewed ngap mapping (0 intra5gs; 1 fivegs-to-eps; 2 eps-to-5gs;
3 fivegs-to-utran) yields the domain scope: value 0 is INTRA_5GS
(supported); values 1..3 are INTER_SYSTEM_OR_OTHER with
UNSUPPORTED_HANDOVER_TYPE_FOR_DOMAIN_PROCEDURE and an explicit attempt
limitation; no inter-system or 5GS-EPS procedure semantics are applied.
