# NGAP Field Reference

Each extracted field: normalized name, semantic meaning, source tshark
field(s), optionality in the detailed event, evidence level, and version
caveats. Procedure-code and cause vocabularies were verified against TShark
4.7.1 (v4.7.1-0-g667ab240e6de) via `tshark -G fields` / `-G values`. The
PDU Session resource fields added in 0.2.0 were originally taken from the
published Wireshark NGAP display-filter reference because the then-reviewed
environment had no local tshark; during the 0.3.0 review a local TShark
4.7.1 installation became available and **all** of those field names were
re-verified by local introspection, closing that verification debt. The
mobility fields added in 0.3.0 were verified the same way and additionally
cross-checked against the TS 38.413 ASN.1 sources packaged with the
dissector (NGAP-PDU-Descriptions.asn, NGAP-PDU-Contents.asn). No field name
was invented. Other Wireshark versions may differ and were not reviewed.

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

## PDU Session resource fields

Added in 0.2.0. Field names come from the published Wireshark NGAP
display-filter reference (local `tshark -G fields` was not available in the
reviewed environment). Nesting is **not** guaranteed by the flattened
export; see the binding column.

| Field | Meaning | Source field(s) | Nesting / binding | Evidence |
| --- | --- | --- | --- | --- |
| pdu_session_resources[].pdu_session_id | PDU Session identity (0..255) | structured `pdu_session_resources[].pdu_session_id`, or ngap.pDUSessionID | structured-input, or single-list-message when exactly one list indicator is present | OBSERVED |
| pdu_session_resources[].resource_operation | SETUP / MODIFY / RELEASE / INITIAL_CONTEXT_SETUP / HANDOVER_PREPARATION / HANDOVER_RESOURCE_ALLOCATION / PATH_SWITCH | derived from message identity | DERIVED | DERIVED |
| pdu_session_resources[].resource_list_role | REQUEST / SUCCESS / FAILED / COMMAND / RESPONSE / REQUIRED / HANDOVER / TO_RELEASE / ADMITTED / TO_BE_SWITCHED / SWITCHED / RELEASED | structured input, or the single observed list indicator | null when several lists are observed and the role is not provable | OBSERVED (indicator) / DERIVED (label) |
| pdu_session_resources[].snssai.sst / .sd | slice service type and differentiator | structured `snssai_sst` / `snssai_sd` only | structured-input only; no verified dissector field name was available in the reviewed environment | OBSERVED (structured input) |
| pdu_session_resources[].nas_pdu_present / .nas_pdu_length | PDU Session NAS-PDU presence and octet length | structured item, or ngap.pDUSessionNAS_PDU when exactly one item exists | length is DERIVED from the exported octets; contents are never kept | OBSERVED / DERIVED |
| pdu_session_resources[].transfer.present / .kind / .length | transfer container presence, reviewed kind, octet length | ngap.pDUSessionResource*Transfer fields, or structured item | body never parsed; `kind` is null or `multiple` when not singular | OBSERVED / DERIVED |
| pdu_session_resources[].qfi_values | QFI values bound to that item | structured item `qfi_values`, or ngap.qosFlowIdentifier when exactly one item exists | a repeated field is kept as an ordered list and never zipped by position | OBSERVED |
| pdu_session_resources[].cause | item-level NGAP Cause | structured `cause_category` / `cause_value` only | the item Cause normally lives inside the encoded unsuccessful transfer, so it is bound only from structured input | OBSERVED (structured input) |
| pdu_session_resources[].binding_basis | structured-input / single-resource-message / single-list-message / unbound | derived | makes the association basis auditable per item | DERIVED |
| unbound_resource_metadata.qfi_values | QFI values with no provable parent item | ngap.qosFlowIdentifier when the binding is ambiguous, or structured `unbound_qfi_values` | never silently discarded | OBSERVED |
| unbound_resource_metadata.cause_values | item-level Causes with no provable parent item | structured `unbound_cause` | never attached to an arbitrary item | OBSERVED (structured input) |
| unbound_resource_metadata.pdu_session_ids | observed PDU Session identities not covered by items | ngap.pDUSessionID not covered by the structured array | — | OBSERVED |
| unbound_resource_metadata.resource_list_roles | list roles observed in the message | resource list indicators | — | OBSERVED |
| unbound_resource_metadata.limitations | explicit reasons the nested values stay unbound | derived | — | DERIVED |

Resource-list indicator fields and the operation/role they represent are
tabulated in `procedure-map.md`. `ngap.pDUSessionID` is a repeated field, so
the extractor requests all occurrences; the flattened export still does not
prove which list an identity came from, which is why multiple list
indicators leave item roles null.

## N2 mobility fields

Added in 0.3.0; all names verified by local `tshark -G fields` /
`-G values` on 4.7.1 and against the packaged TS 38.413 ASN.1. The
`mobility` object is emitted only for supported mobility messages
(procedure codes 10, 11, 12, 13, 25) and stays optional in the schema.

| Field | Meaning | Source field(s) | Optionality | Evidence |
| --- | --- | --- | --- | --- |
| mobility.family | reviewed elementary-procedure family: handover-preparation / handover-resource-allocation / handover-notification / handover-cancel / path-switch | derived from the procedure code | required in the mobility object | DERIVED |
| mobility.handover_type_value | observed HandoverType enumerated value | ngap.HandoverType | null when absent | OBSERVED |
| mobility.handover_type_name | reviewed symbolic name (0 intra5gs, 1 fivegs-to-eps, 2 eps-to-5gs, 3 fivegs-to-utran) | derived for values in the reviewed mapping only | null otherwise | DERIVED |
| mobility.target_id_present | TargetID IE presence | ngap.TargetID non-empty | required boolean | OBSERVED |
| mobility.target_id_type | reviewed CHOICE alternative (0 targetRANNodeID, 1 targeteNB-ID, 2 choice-Extensions) | ngap.TargetID, derived for verified indexes; observed text when exported symbolically | null when absent or unverified | OBSERVED / DERIVED |
| mobility.source_to_target_container | transparent-container presence and octet length | ngap.SourceToTarget_TransparentContainer | required in the mobility object | OBSERVED / DERIVED (length) |
| mobility.target_to_source_container | transparent-container presence and octet length | ngap.TargetToSource_TransparentContainer | required in the mobility object | OBSERVED / DERIVED (length) |
| mobility.target_to_source_failure_container | failure transparent-container presence and octet length | ngap.TargettoSource_Failure_TransparentContainer | required in the mobility object | OBSERVED / DERIVED (length) |

Transparent-container content is never decoded and its bytes are never
retained; TargetID never yields site, node, or vendor identity; Handover
Type never explains why a handover occurred. Mobility resource lists and
transfer containers use the same item model as the PDU Session resource
fields above; their list fields and transfer kinds are tabulated in
`procedure-map.md`. Structured input binds item-level values exactly as in
0.2.0; flattened nested values attach only when exactly one resource item
exists, and are preserved as unbound evidence otherwise.

The `derivations` array additionally enumerates `mobility_family`,
`handover_type_name`, and `target_id_type` when those values were derived
rather than observed.

## Evidence and derivations bookkeeping

- evidence.level is always OBSERVED for the detailed event; every
  deterministic transformation is enumerated in `derivations`
  (procedure_name, message_type, pdu_type, result, sender_role) so the
  observed/derived split stays auditable.
- evidence.source names the capture frame and the procedure code, plus the
  Info-column text when it drove PDU resolution.
