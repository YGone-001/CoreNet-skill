# Telecom Core-Network Failure-Boundary Context

## Boundary Model

Use this conceptual investigation path: UE, access/RAN, core control plane,
session/policy/subscriber services, user plane, then external service, IMS, or
data network. It is a map for selecting evidence points, not a message sequence.

Start with expected outcome, last observed good boundary, first missing or
abnormal boundary, evidence from both sides, hypotheses, and controlled
validation. Do not blame the network function that emitted the last visible
message. Compare successful and failing subscribers, versions, and equivalent
observation points when available. Treat configuration, transport,
interoperability, implementation, and external dependencies as hypotheses; do
not change multiple network functions together.

## Evidence-Safe Examples

- OBSERVED: A release is visible on one signaling path.
- INFERRED: That path initiated the observed release action.
- HYPOTHESIS: It may be related to the failure boundary, not necessarily its cause.
- NEXT EVIDENCE: Gather corresponding evidence from adjacent boundaries.

## Handoff to Higher Layers

This Skill identifies a defensible boundary but does not define Registration,
Attach, INVITE, or other procedures. Future Protocol, Domain, Implementation,
and Orchestration Skills supply semantic and source-specific analysis.
