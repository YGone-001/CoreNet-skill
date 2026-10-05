# Deviation Model

Deviations are bounded, neutral, and compatible with the current
Domain-to-Orchestration contract. Every deviation carries a
machine-readable `evidence_refs` array; human-readable description and
limitation text are never a machine identity contract.

## Boundary-eligible deviations

These may become boundary candidates in Analysis Orchestration:

- PROTOCOL_NEGATIVE_OUTCOME_OBSERVED — NGAP unsuccessfulOutcome branches
  (HandoverPreparationFailure, HandoverFailure, PathSwitchRequestFailure)
  and safely associated PFCP Session Modification Responses with negative
  cause. OBSERVED, EVENT refs.
- RESOURCE_FAILED_ITEM_OBSERVED — an NGAP resource item with role
  FAILED. OBSERVED, EVENT ref with the item's field binding.
- MISSING_EXPECTED_COUNTERPART — a branch-aware mandatory counterpart
  not observed within the window. DERIVED, OBSERVATION_WINDOW refs.
- FIELD_CONFLICT — contradictory resource roles across safely linked
  stages. DERIVED, FIELD_FINDING refs preserving both observations.

## Evidence-quality deviations (never boundary candidates)

PARTIAL_CAPTURE, CORRELATION_AMBIGUITY, CORRELATION_CONFLICT,
LIFECYCLE_AMBIGUITY, OUT_OF_ORDER_EVIDENCE,
DUPLICATE_OR_RETRANSMITTED_EVIDENCE, and
UNKNOWN_OR_RESERVED_PROTOCOL_VALUE (lower-layer UNSUPPORTED/UNKNOWN
reports). These describe evidence quality or association limits.

## Deliberate non-deviations

HandoverCancel/HandoverCancelAcknowledge are branch and terminal
observations, not deviations. HandoverNotify is progress evidence. A
missing End Marker, missing G-PDU, missing N11 transaction, or a PFCP
acceptance is never a deviation. An inter-system HandoverType is a scope
limitation on the attempt, not a protocol anomaly.

## Earliest procedure-local deviation

Each attempt exposes `earliest_observed_deviation`: the deviation whose
observed provenance (capture, frame) comes first, preferring OBSERVED
evidence. It is procedure-local only — never a cross-Domain first
abnormal boundary and never a root cause; Analysis Orchestration owns
cross-Domain boundary selection.
