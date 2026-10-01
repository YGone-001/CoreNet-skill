# NAS-5GS Field Reference

Extracted fields, their reviewed sources, optionality, and evidence
class. Verified against TShark 4.7.1 (v4.7.1-0-g667ab240e6de) via
`tshark -G fields` / `-G values`; other Wireshark versions may expose
different names and were not reviewed.

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

The security envelope is preserved independently of inner semantics. A
protected envelope without a decoded inner message stays
`inner_message_available: false`; the inner message is never guessed
from sequence numbers or timing. This Skill does not derive keys, verify
MACs, or cipher/decipher: no KSEAF/KAMF/KNAS derivation, no AKA
cryptography, no MAC validation exists in this package.

## Message identity

| Field | Meaning | Source | Evidence |
| --- | --- | --- | --- |
| nas_family | 5GMM or 5GSM | which sublayer message-type the dissector exposed | DERIVED |
| protocol_discriminator | extended protocol discriminator (0x7E) | structural constant of 5GS NAS | DERIVED |
| message_type_code | numeric message identity | nas-5gs.mm.message_type or nas-5gs.sm.message_type | OBSERVED |
| message_type | reviewed message name | reviewed TS 24.501 table | DERIVED |
| support_status | SUPPORTED / UNSUPPORTED / UNKNOWN / DEFERRED | Skill-local classification | DERIVED |
| result | local result label (REQUEST, REJECT, and similar) | derived from message identity | DERIVED |
| direction | ue-to-amf / amf-to-ue / null | message definition or carrier_direction input | DERIVED |
| direction_basis | message-definition or observed-carrier | derived | DERIVED |
| procedure_family | bounded procedure grouping | derived from message identity | DERIVED |

## Registration IEs

| Field | Meaning | Source | Evidence |
| --- | --- | --- | --- |
| registration.type_code | 5GS registration type value | nas-5gs.mm.5gs_reg_type | OBSERVED |
| registration.type_name | reviewed type name; UNKNOWN outside table | reviewed table | DERIVED |
| registration.follow_on_request | follow-on request bit | nas-5gs.mm.for | OBSERVED (bit), DERIVED (boolean) |
| ngksi.key_set_id | NAS key set identifier | nas-5gs.mm.nas_key_set_id | OBSERVED |

The ngKSI is protocol context identifying a security context; it is not
a key and no key material exists in this package.

## Identity IEs (sensitive)

| Field | Meaning | Source | Evidence |
| --- | --- | --- | --- |
| identity.present | mobile identity IE present | type_id or IMEI/IMEISV fields observed | DERIVED from OBSERVED |
| identity.type_code | reviewed identity type value | nas-5gs.mm.type_id | OBSERVED |
| identity.type_name | SUCI, 5G-GUTI, IMEI, 5G-S-TMSI, IMEISV; UNKNOWN outside table | reviewed table | DERIVED |
| identity.value | raw identity value; null unless explicitly opted in | identity_value structured field only | OBSERVED (opt-in only) |

Default behavior redacts raw values. The opt-in flag
(`--include-sensitive-identifiers`) carries identity_value from
structured input only; capture-based extraction never exports identity
values through this package. IMEI/IMEISV are presence-only even with
opt-in. SUCI is never treated as SUPI; 5G-GUTI is never treated as a
permanent identity.

## Cause

| Field | Meaning | Source | Evidence |
| --- | --- | --- | --- |
| cause.code | 5GMM cause value | nas-5gs.mm.5gmm_cause | OBSERVED |
| cause.name | reviewed cause name; null when outside table | reviewed table | DERIVED |

A 5GMM cause is protocol evidence of a stated rejection reason. It is
not an end-to-end root cause and never becomes one by itself.

## Authentication and security-mode metadata

| Field | Meaning | Source | Evidence |
| --- | --- | --- | --- |
| authentication.rand_present / autn_present / res_present / auts_present | parameter presence only | structured input flags (auth_rand_present and similar) | OBSERVED (structured input) |
| security_mode.ciphering_algorithm_code / name | selected NAS ciphering algorithm | nas-5gs.mm.nas_sec_algo_enc + reviewed table | OBSERVED / DERIVED |
| security_mode.integrity_algorithm_code / name | selected NAS integrity algorithm | nas-5gs.mm.nas_sec_algo_ip + reviewed table | OBSERVED / DERIVED |

Authentication RAND/AUTN/RES*/AUTS values are never emitted in any
mode; TShark 4.7.1 does not export them as filterable fields and the
structured input format accepts presence flags only. Algorithm names are
protocol identifiers, not cryptographic assessments.

## Service access

| Field | Meaning | Source | Evidence |
| --- | --- | --- | --- |
| service.type_code | control-plane service type value | nas-5gs.mm.serv_type | OBSERVED |
| service.type_name | reviewed service type name | reviewed table | DERIVED |

## Derivations bookkeeping

Each event lists its derived aspects in `derivations` (nas_family,
message_type, direction, procedure_family, result, cause_name,
algorithm_names). OBSERVED-versus-DERIVED stays auditable per event; a
derived label is never presented as wire observation.
