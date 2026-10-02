# NAS-5GS Field Reference

Extracted fields, their reviewed sources, optionality, and evidence
class. Field names follow the NAS-5GS dissector of Wireshark/TShark
4.7.1 (v4.7.1-0-g667ab240e6de) as published in the Wireshark display
filter reference; other Wireshark versions may expose different names and
were not reviewed. The reviewed environment did not have a local tshark
installation, so field names were taken from the published Wireshark
field reference rather than re-dumped with `tshark -G fields`; this is a
tool-verification limitation, not a specification claim. Message types,
causes, and coded values come from the normative specification tables
cited in each row.

## Frame provenance

| Field | Meaning | Source | Evidence |
| --- | --- | --- | --- |
| frame_number | capture frame number | frame.number | OBSERVED |
| timestamp | UTC ISO-8601, microsecond precision | frame.time_epoch | DERIVED (deterministic conversion) |
| capture_file | basename only | input artifact name | OBSERVED |

## Security envelope (`nas-5gs.security_header_type` family)

| Field | Meaning | Source | Evidence |
| --- | --- | --- | --- |
| security.header_type | 0..4 observed code | nas-5gs.security_header_type | OBSERVED |
| security.header_name | reviewed header name | reviewed table | DERIVED |
| security.integrity_protected | derived protection state (codes 1-4) | derived | DERIVED |
| security.ciphered | derived ciphering state (codes 2, 4) | derived | DERIVED |
| security.new_security_context | derived new-context flag (codes 3, 4) | derived | DERIVED |
| security.sequence_number | NAS COUNT low octet as exported | nas-5gs.seq_no | OBSERVED |
| security.message_authentication_code_present | MAC present (value never exported) | nas-5gs.msg_auth_code | OBSERVED (presence), DERIVED (boolean) |
| security.security_parameter_index | key-set index of the envelope | nas-5gs.security_parameter_index | OBSERVED |
| security.inner_message_available | inner message decoded or not | derived from inner message-type presence | DERIVED |
| security.decode_basis | plain-message / dissector-decoded / null | derived | DERIVED |

The envelope is preserved independently of inner semantics and applies to
both 5GMM and 5GSM. A protected envelope without a decoded inner message
stays `inner_message_available: false`; the inner message is never
guessed. This Skill does not derive keys, verify MACs, or
cipher/decipher.

## Message identity

| Field | Meaning | Source | Evidence |
| --- | --- | --- | --- |
| nas_family | 5GMM or 5GSM | which sublayer message-type the dissector exposed | DERIVED |
| protocol_discriminator | extended protocol discriminator: 126 for 5GMM, 46 for 5GSM | nas-5gs.epd when observed, else derived from family | OBSERVED / DERIVED |
| message_type_code | numeric message identity | nas-5gs.mm.message_type or nas-5gs.sm.message_type | OBSERVED |
| message_type | reviewed message name | reviewed TS 24.501 table | DERIVED |
| support_status | SUPPORTED / UNSUPPORTED / UNKNOWN / DEFERRED | Skill-local classification | DERIVED |
| result | local result label (REQUEST, REJECT, and similar) | derived from message identity | DERIVED |
| direction | ue-to-amf / amf-to-ue / ue-to-smf / smf-to-ue / null | message definition or carrier_direction input | DERIVED |
| direction_basis | message-definition or observed-carrier | derived | DERIVED |
| procedure_family | bounded procedure grouping | derived from message identity | DERIVED |

`nas-5gs.epd` is read when the export provides it; a value that
contradicts the observed family fails loudly.

## Registration IEs

| Field | Meaning | Source | Evidence |
| --- | --- | --- | --- |
| registration.type_code | 5GS registration type value | nas-5gs.mm.5gs_reg_type | OBSERVED |
| registration.type_name | reviewed type name; UNKNOWN outside table | reviewed table | DERIVED |
| registration.follow_on_request | follow-on request bit | nas-5gs.mm.for | OBSERVED (bit), DERIVED (boolean) |
| ngksi.key_set_id | NAS key set identifier | nas-5gs.mm.nas_key_set_id | OBSERVED |

## Identity IEs (sensitive)

| Field | Meaning | Source | Evidence |
| --- | --- | --- | --- |
| identity.present | mobile identity IE present | type_id or IMEI/IMEISV fields observed | DERIVED from OBSERVED |
| identity.type_code | reviewed identity type value | nas-5gs.mm.type_id | OBSERVED |
| identity.type_name | SUCI, 5G-GUTI, IMEI, 5G-S-TMSI, IMEISV; UNKNOWN outside table | reviewed table | DERIVED |
| identity.value | raw identity value; null unless explicitly opted in | identity_value structured field only | OBSERVED (opt-in only) |

Default behavior redacts raw values. The opt-in flag carries
identity_value from structured input only. IMEI/IMEISV are presence-only
even with opt-in. SUCI is never treated as SUPI.

## Cause

| Field | Meaning | Source | Evidence |
| --- | --- | --- | --- |
| cause.code | 5GMM cause value or 5GSM cause value | nas-5gs.mm.5gmm_cause or nas-5gs.sm.5gsm_cause | OBSERVED |
| cause.name | reviewed cause name; null when outside table | reviewed table | DERIVED |
| cause.family | 5GMM or 5GSM | derived from the observed family | DERIVED |

The `family` field keeps the two cause namespaces distinct so a 5GMM
cause and a 5GSM cause cannot be confused. Adding it is a
backward-compatible enrichment: earlier events keep their
`{code, name}` semantics, and every field keeps its established meaning.
A cause is protocol evidence of a stated rejection reason and is never an
end-to-end root cause.

## Authentication and security-mode metadata

| Field | Meaning | Source | Evidence |
| --- | --- | --- | --- |
| authentication.rand_present / autn_present / res_present / auts_present | parameter presence only | structured input flags | OBSERVED (structured input) |
| security_mode.ciphering_algorithm_code / name | selected NAS ciphering algorithm | nas-5gs.mm.nas_sec_algo_enc + reviewed table | OBSERVED / DERIVED |
| security_mode.integrity_algorithm_code / name | selected NAS integrity algorithm | nas-5gs.mm.nas_sec_algo_ip + reviewed table | OBSERVED / DERIVED |

Authentication RAND/AUTN/RES*/AUTS values are never emitted in any mode.

## Service access

| Field | Meaning | Source | Evidence |
| --- | --- | --- | --- |
| service.type_code | control-plane service type value | nas-5gs.mm.serv_type | OBSERVED |
| service.type_name | reviewed service type name | reviewed table | DERIVED |

## Session management (5GSM only)

Present only for 5GSM observations; absent from 5GMM events.

| Field | Meaning | Source | Evidence |
| --- | --- | --- | --- |
| session_management.pdu_session_id | PDU session identity (0..255) | nas-5gs.pdu_session_id | OBSERVED |
| session_management.pti | procedure transaction identity (0..255) | nas-5gs.proc_trans_id | OBSERVED |
| session_management.request_type.code / name | request type value and reviewed name | nas-5gs.mm.req_type + TS 24.501 table 9.11.3.47.1 | OBSERVED / DERIVED |
| session_management.pdu_session_type.code / name | PDU session type value and reviewed name | nas-5gs.sm.pdu_ses_type (or nas-5gs.sm.pdu_session_type) + table 9.11.4.11.1 | OBSERVED / DERIVED |
| session_management.ssc_mode.code / name | SSC mode value and reviewed name | nas-5gs.sm.sc_mode or nas-5gs.sm.sel_sc_mode + table 9.11.4.16.1 | OBSERVED / DERIVED |
| session_management.dnn | data network name | nas-5gs.cmn.dnn | OBSERVED |
| session_management.snssai.sst / sd | slice/service type and slice differentiator | nas-5gs.mm.sst / nas-5gs.mm.mm_sd | OBSERVED |
| session_management.pdu_address | UE PDU address | nas-5gs.sm.pdu_addr_inf_ipv4, or the structured `pdu_address` field for unambiguous IPv6/IPv4v6 fixtures | OBSERVED |
| session_management.always_on.requested / indicated | always-on PDU session requested / indicated | nas-5gs.sm.apsr / nas-5gs.sm.apsi | OBSERVED |
| session_management.authorized_qos_rules.present / rule_ids | authorized QoS rules present and rule identifiers | nas-5gs.sm.qos_rule_id (or structured `qos_rules_present`) | OBSERVED |
| session_management.qos_flow_descriptions.present / qfi_values / five_qi_values | QoS flow descriptions present, QFI and 5QI values | nas-5gs.sm.qfi / nas-5gs.sm.5qi (or structured `qos_flow_descriptions_present`) | OBSERVED |
| session_management.epco_present | extended protocol configuration options present | structured `epco_present` field | OBSERVED (structured input) |

Notes:

- A repeated QFI or 5QI field is preserved as an ordered list; it is
  never collapsed into one arbitrary value. The extractor requests all
  occurrences from tshark so multi-QFI sessions are not truncated.
- The IPv6 PDU address is only taken from the explicit structured
  `pdu_address` field because the dissector renders the IPv6 address as a
  byte sequence whose textual form is not unambiguous.
- `epco_present` has no verified filterable dissector field in the
  reviewed environment and is therefore accepted from structured input
  only.
- Request type is read from `nas-5gs.mm.req_type`, the reviewed
  dissector's registration for that shared IE.

## Derivations bookkeeping

Each event lists its derived aspects in `derivations` (nas_family,
message_type, direction, procedure_family, result, cause_name,
algorithm_names). OBSERVED-versus-DERIVED stays auditable per event; a
derived label is never presented as wire observation.
