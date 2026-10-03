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
