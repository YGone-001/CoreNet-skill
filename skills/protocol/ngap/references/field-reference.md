# NGAP Field Reference

Each extracted field: normalized name, semantic meaning, source tshark
field(s), optionality in the detailed event, evidence level, and version
caveats. Reviewed against TShark 4.7.1 (v4.7.1-0-g667ab240e6de) via
`tshark -G fields` / `-G values`; other Wireshark versions may differ and
were not reviewed.

## Frame and capture provenance

| Field | Meaning | Source field | Optionality | Evidence |
| --- | --- | --- | --- | --- |
| timestamp | UTC ISO-8601, microsecond precision | frame.time_epoch | required | DERIVED (deterministic conversion) |
| frame_number | capture frame number | frame.number | required | OBSERVED |
| capture_file | basename only; workstation paths are never recorded | input artifact | required | OBSERVED |

## Identity

| Field | Meaning | Source field(s) | Optionality | Evidence |
| --- | --- | --- | --- | --- |
| procedure_code | NGAP procedure code (0..255) | ngap.procedureCode | required | OBSERVED |
| procedure_name | reviewed name for the code | derived from reviewed 38.413 table | required (null when UNKNOWN) | DERIVED |
| message_type | concrete message name | procedure branch mapping | required (null unless resolved) | DERIVED |
| pdu_type | initiatingMessage / successfulOutcome / unsuccessfulOutcome | see below | required (null unless resolved) | OBSERVED (structured-input) or DERIVED (message-name) |
| pdu_type_basis | structured-input or message-name | — | required (null when pdu_type null) | DERIVED |
| support_status | SUPPORTED / UNSUPPORTED / UNKNOWN | derived | required | DERIVED |
| result | local label: REQUEST / SUCCESS / FAILURE / COMMAND / COMPLETE | derived from message identity | required (null when message unresolved) | DERIVED |
| sender_role | amf / ng-ran, derived from message identity; null for either-side messages | derived | required (null when unresolved) | DERIVED |

PDU category note: TShark 4.7.1 exposes no filterable NGAP PDU-category
field. `pdu_type` comes from an explicit structured-input value
(`pdu_type`, basis `structured-input`) or from exact Info-column message
matching (`_ws.col.Info`, basis `message-name`). TShark Info-column wording
is Wireshark-version dependent; if it changes, `pdu_type` becomes null and
the event still validates. Never infer the category from ports, direction,
or timing.

## UE-context identifiers

| Field | Meaning | Source field(s) | Optionality | Evidence |
| --- | --- | --- | --- | --- |
| amf_ue_ngap_id | AMF-assigned UE NGAP ID | ngap.AMF_UE_NGAP_ID | required in event, null when absent in frame | OBSERVED |
| ran_ue_ngap_id | NG-RAN-assigned UE NGAP ID | ngap.RAN_UE_NGAP_ID | required in event, null when absent in frame | OBSERVED |

Both are integers when present. A missing identifier stays null and is
never substituted, hashed, or synthesized. They are never written into
generic subscriber or session fields of the shared trace schema.

## Cause

| Field | Meaning | Source field(s) | Optionality | Evidence |
| --- | --- | --- | --- | --- |
| cause.category | radioNetwork / transport / nas / protocol / misc (or extension/unknown as observed) | ngap.cause (CHOICE index); ngap.Cause fallback | object null when absent | OBSERVED |
| cause.value | category-local numeric value | ngap.radioNetwork / ngap.transport / ngap.nas / ngap.protocol / ngap.misc | null when category absent | OBSERVED |

Category indexes reviewed from TShark 4.7.1: 0 radioNetwork, 1 transport,
2 nas, 3 protocol, 4 misc, 5 choice-Extensions. Values are preserved
numerically; value-name expansion is intentionally not implemented, so no
vocabulary drift can be introduced by this Skill.

## NAS boundary

| Field | Meaning | Source field(s) | Optionality | Evidence |
| --- | --- | --- | --- | --- |
| nas_pdu_present | NAS-PDU IE present in the frame | ngap.NAS_PDU non-empty | required | OBSERVED |
| nas_pdu_length | byte length of the NAS-PDU octets | computed from ngap.NAS_PDU | null when absent | DERIVED |

The NAS-PDU value itself is never retained, decoded, or summarized.
Registration, 5GMM causes, SUCI/SUPI, 5G-GUTI, NSSAI, and DNN semantics
belong to the future nas-5gs Skill; the detailed event deliberately carries
presence and length only so that Skill can take the payload handoff.

## Auxiliary observations

| Field | Meaning | Source field(s) | Optionality | Evidence |
| --- | --- | --- | --- | --- |
| rrc_establishment_cause | RRC establishment cause as exported (integer enum or string) | ngap.RRCEstablishmentCause | null when absent | OBSERVED |
| user_location_information_present | user-location IE presence | ngap.UserLocationInformation or ngap.TAC non-empty | required boolean | OBSERVED |
| paging_identity_present | paging identity presence (no identity value retained) | ngap.UEPagingIdentity or ngap.fiveG_TMSI non-empty | required boolean | OBSERVED |

Container caveat: tshark often exports container-type IEs
(ngap.UserLocationInformation, ngap.UEPagingIdentity) as empty strings, so
presence detection also accepts the value-carrying child fields ngap.TAC
(FT_UINT24) and ngap.fiveG_TMSI (FT_UINT32), both verified in 4.7.1.
Presence is recorded; TAC/TMSI values are not emitted.

## Transport metadata

| Field | Meaning | Source field(s) | Optionality | Evidence |
| --- | --- | --- | --- | --- |
| source / destination | address and SCTP port | ip.src/ip.dst, ipv6.src/ipv6.dst, sctp.srcport/sctp.dstport | omitted when nothing observed | OBSERVED |
| sctp.association_id | tshark association index | sctp.assoc_index | null when not exposed | OBSERVED |
| sctp.stream_id | SCTP data stream id | sctp.data_sid | null when not exposed | OBSERVED |
| sctp.srcport / sctp.dstport | SCTP ports | sctp.srcport / sctp.dstport | null when not exposed | OBSERVED |

`sctp.assoc_index` is a TShark-session-local ordinal, not a 3GPP
identifier; it is used only to scope correlation within one capture.

## Evidence and derivations bookkeeping

- evidence.level is always OBSERVED for the detailed event; every
  deterministic transformation is enumerated in `derivations`
  (procedure_name, message_type, pdu_type, result, sender_role) so the
  observed/derived split stays auditable.
- evidence.source names the capture frame and the procedure code, plus the
  Info-column text when it drove PDU resolution.
