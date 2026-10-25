# Orchestration Skills

Analysis Orchestration Skills compose already-produced Domain analysis outputs
into cross-procedure, confidence-aware diagnostic views. Implemented packages:
`5gc-failure-boundary` (v0.2.0), evidence-safe first abnormal boundary
localization across currently supported 5GC Domain analyses
(`5gc-registration-mobility`, `5gc-pdu-session`, `5gc-handover-mobility`),
with separately addressable handover and Path Switch attempts and
Domain-authorized source/target context bridges. `epc-failure-boundary` (v0.2.0)
provides per-subject EPC abnormal-boundary selection over already-produced EPS
Attach and EPC session-control Domain analyses: machine-readable candidates built
only from explicit negative Domain deviations, exact-frame ordering, explicit
ambiguity and insufficiency, and downstream observations that are ordered but
never attributed as effects. Neither package owns protocol decoding, procedure
semantics, root-cause reasoning, or implementation mapping.
