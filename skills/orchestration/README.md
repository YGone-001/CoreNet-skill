# Orchestration Skills

Analysis Orchestration Skills compose already-produced Domain analysis outputs
into cross-procedure, confidence-aware diagnostic views. Implemented package:
`5gc-failure-boundary` (v0.2.0), evidence-safe first abnormal boundary
localization across currently supported 5GC Domain analyses
(`5gc-registration-mobility`, `5gc-pdu-session`, `5gc-handover-mobility`),
with separately addressable handover and Path Switch attempts and
Domain-authorized source/target context bridges. The concrete package does not
own protocol decoding, procedure semantics, root-cause reasoning, or
implementation mapping.
