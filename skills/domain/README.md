# Domain Skills

Implemented packages are `procedure-evidence`, the generic
procedure-evidence framework, `5gc-registration-mobility`, a bounded N1/N2
registration and access analysis Skill, and `5gc-pdu-session` (v0.3.0),
performing bounded PDU Session Establishment, Modification, and Release lifecycle
analysis (with lifecycle generation handling for PDU Session ID reuse) across
N1/N2/N3/N4/N11, and `5gc-handover-mobility` (v0.1.0), performing bounded N2
handover and Path Switch procedure analysis from already-extracted NGAP/PFCP/
GTP-U/SBI evidence with separate handover and path-switch attempt families,
evidence-bounded source/target association, branch-aware stages, item-scoped
PDU Session resource outcomes, bounded N11/N4/N3 supporting evidence, and
structured deviation provenance, and `epc-procedures` (v0.4.0), performing bounded
EPS Attach procedure evidence analysis, bounded EPC session-control transaction analysis
and bounded EPS default-bearer signalling analysis from already-extracted S1AP, NAS-EPS
and GTPv2-C events, with frame-anchored UE association, conditional stage evaluation,
item-scoped E-RAB and bearer evidence, evidence-safe cross-interface identity links,
bounded S1-U GTP-U stream observation, procedure-local deviations and explicit
limitations (no bearer, PDN or service verdict, no delivery verdict, and no global
EPC boundary). The concrete packages do not own protocol
decoding, implementation mapping, or end-to-end root-cause diagnosis.
