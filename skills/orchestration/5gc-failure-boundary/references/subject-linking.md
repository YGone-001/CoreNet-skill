# Subject Linking

## Diagnostic Groups

A diagnostic group represents Domain analyses that are sufficiently linked to
be treated as observations of the same diagnostic subject. A group may contain
one registration/mobility procedure instance and zero or more PDU Session
lifecycle instances; every source Domain instance remains separately
addressable with its `source_domain`, `source_instance_id`,
`source_attempt_id` where applicable, and lifecycle generation where
applicable. No global timeline across every UE or session is ever formed.

## Strong Subject Links

Two source instances link only when all of the following are present and equal:

- capture file;
- SCTP association - compared contract-equivalently because
  `5gc-registration-mobility` emits `sctp-assoc-<id>` strings while
  `5gc-pdu-session` emits the numeric association id; the numeric forms must
  be equal;
- RAN-UE-NGAP-ID;
- AMF-UE-NGAP-ID.

A missing component never links. Groups of more than one source instance carry
subject-link strength `STRONG` with basis
`capture_sctp_association_and_ngap_ue_context_exact_match`.

## Isolation Rules

- Two UEs with the same numeric RAN-UE-NGAP-ID or AMF-UE-NGAP-ID on different
  SCTP associations remain separate.
- One numeric identifier alone never joins anything.
- Timestamp proximity alone never joins a registration analysis and a PDU
  Session analysis.
- Analyses from different capture files stay independent: this version has no
  external capture-equivalence mapping.
- PDU Session lifecycle generations (equal numeric PDU Session IDs) remain
  distinct source procedure instances inside a group.

## Unbound Analyses

A source instance that links to nothing forms a single-source diagnostic group
with subject-link strength `UNBOUND`; it still evaluates its own candidates.
Such analyses are additionally listed under `unbound_domain_analyses`.

## Handover Source / Target Context Bridges

A handover attempt may expose two exact contexts: `source_context` and
`target_context`. They are not interchangeable and their roles stay explicit.
The anchoring rule:

- the source context anchors when present and complete;
- otherwise a directly observed complete `target_context` anchors (bounded
  late-capture attempts; no source context is ever fabricated);
- a Path Switch attempt anchors through its `serving_context`.

The source and target contexts are joined into one diagnostic group only when
the Handover Domain itself has already established the source/target
association with strength `STRONG` or `SUPPORTED`, both contexts are
structurally complete, and both sides share the same capture file. This is
consumed Domain output (DERIVED Domain evidence), never a new Orchestration
correlation heuristic. The bridged group's subject-link strength stays
`SUPPORTED` with basis `domain_supported_handover_context_bridge` and
structured `context_bridges` provenance (source domain, source instance,
bridge type/strength/basis, from/to contexts); it is never upgraded to
`STRONG`.

An `AMBIGUOUS` or `UNBOUND` association never bridges, no association
candidate is ever chosen, and no unsafe transitive merge crosses unrelated
groups. Equal RAN/AMF-UE-NGAP-IDs on different associations and different
capture files stay isolated.

Two procedure attempts in one diagnostic group remain two separately
addressable attempts: group membership never implies one procedure, a
Handover-to-Path-Switch relationship is never inferred, and an independent
Path Switch with no handover evidence stays valid without any missing-handover
candidate.
