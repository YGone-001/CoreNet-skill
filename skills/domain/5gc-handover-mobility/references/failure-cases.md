# Failure Cases

Protocol-local abnormal or inconclusive patterns this Skill reports, with
the hard boundary against causal overreach.

- Handover Preparation Failure observed — direct NGAP unsuccessful
  outcome with Cause. Never an AMF, source-gNB, target-gNB, or radio
  root cause.
- Handover Failure observed — target resource allocation unsuccessful
  outcome. Boundary-eligible; never implementation blame.
- Path Switch Failure observed — unsuccessful outcome without a
  message-level Cause in the reviewed basis; no Cause is invented from
  released-item presence.
- Mixed resource outcomes — ADMITTED + FAILED or SWITCHED + RELEASED in
  one message stay item-scoped; no message-wide resource verdict.
- Resource role conflict — contradictory roles across linked stages are
  preserved with FIELD_CONFLICT; the model does not adjudicate.
- Ambiguous source/target association — multiple compatible candidates
  keep the association AMBIGUOUS; no nearest-in-time choice is made.
- AMF-UE-NGAP-ID reuse — distinct lifetimes with the same numeric ID stay
  separate unless compatible active-procedure context exists; competing
  candidates stay ambiguous.
- RAN-UE-NGAP-ID equality across associations — never identity evidence.
- Cancellation observed — a bounded branch (HANDOVER_CANCEL_OBSERVED /
  HANDOVER_CANCEL_ACK_OBSERVED), never automatically a failure.
- Notify without Path Switch — no false missing-Path-Switch deviation.
- Path Switch without handover evidence — valid independent attempt; no
  MISSING_HANDOVER_REQUIRED deviation.
- Truncated capture — attempts anchored mid-procedure carry
  PARTIAL_CAPTURE and capture-termination framing; missing outcomes are
  never reported as network absence.
- Duplicate mobility messages — preserved as
  DUPLICATE_OR_RETRANSMITTED_EVIDENCE; no packet-loss speculation.
- Out-of-order input — ordering normalized with OUT_OF_ORDER_EVIDENCE and
  original provenance preserved.
- Unrelated PFCP / redacted N11 / mismatched TEID endpoints — preserved
  as unbound supporting evidence; never force-associated.
- Unsupported or unknown NGAP mobility procedures — preserved in
  `unbound_mobility_evidence` with lower-layer support status; no
  semantics invented.
- Inter-system HandoverType — preserved with
  UNSUPPORTED_HANDOVER_TYPE_FOR_DOMAIN_PROCEDURE; no inter-system
  semantics applied.

## Explicitly out of scope for causal claims

The Skill does not confirm: handover or Path Switch success, UPF
relocation, user-plane health, radio/RRC diagnosis, AMF/gNB/UPF/SMF
implementation behavior, or any end-to-end root cause. Its deviation
vocabulary is evidence-bounded procedure observation only.
