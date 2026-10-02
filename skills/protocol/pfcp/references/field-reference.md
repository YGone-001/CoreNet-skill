# PFCP Field Reference

Each extracted field: normalized output field, meaning, source
Wireshark/TShark field name, TS 29.244 basis, optionality, evidence level,
hierarchy/binding guarantee, and tool-version caveat.

Reviewed environment note: the PFCP dissector field names below come from
the published Wireshark PFCP display-filter reference. **LOCAL TSHARK NOT
RUN** — no tshark installation was available, so these names are
published-reference verified and not locally re-dumped. No field name is
invented: where the reference exposes no field, the value is accepted from
structured input only and that is stated explicitly.

## Frame and capture provenance

| Field | Meaning | Source field | Optionality | Evidence |
| --- | --- | --- | --- | --- |
| timestamp | UTC ISO-8601, microsecond precision | frame.time_epoch | required | DERIVED (deterministic conversion) |
| frame_number | capture frame number | frame.number | required | OBSERVED |
| capture_file | basename only; workstation paths are never recorded | input artifact | required | OBSERVED |

## Header

| Field | Meaning | Source field | Optionality | Evidence |
| --- | --- | --- | --- | --- |
| header.version | PFCP version (octet 1 bits 6-8) | structured `pfcp.version` only | required (null for capture-only input) | OBSERVED |
| header.s_flag | S flag: SEID field present | pfcp.s | required (null when absent) | OBSERVED |
| header.mp_flag | MP flag: message priority present | pfcp.mp_flag | required (null when absent) | OBSERVED |
| header.message_type_code | message type code | pfcp.msg_type | required | OBSERVED |
| header.message_type | reviewed message name | derived from table 7.3-1 | required (null when UNKNOWN) | DERIVED |
| header.message_length | message length (octets, excluding the mandatory header part) | pfcp.length | required (null when absent) | OBSERVED |
| header.seid | header SEID (the peer's SEID; 0 when the peer SEID is unavailable) | pfcp.seid | required (null when absent) | OBSERVED |
| header.sequence_number | three-octet transaction sequence number | pfcp.seqno (fallback pfcp.sequence_number) | required (null when absent) | OBSERVED |
| header.priority | message priority (octet 16 when MP=1) | pfcp.mp | required (null when absent) | OBSERVED |
| header.seid_expected_zero | whether the reviewed message definition requires a zero header SEID | derived from clause 7.2.2.4.2 | required | DERIVED |

The reviewed reference lists no filterable PFCP version field, so `version`
is read from structured input only. `pfcp.seqno` (24 bits) is preferred over
`pfcp.sequence_number` (32 bits) because the former matches the wire field.

## Endpoints

| Field | Meaning | Source field | Optionality | Evidence |
| --- | --- | --- | --- | --- |
| source / destination | address and UDP port | ip.src/ip.dst, ipv6.src/ipv6.dst, udp.srcport/udp.dstport | omitted when nothing observed | OBSERVED |

PFCP commonly uses UDP port 8805, but a port never determines a
network-function role. No endpoint is ever labelled SMF or UPF from its
address or port.

## Node context

| Field | Meaning | Source field | Optionality | Evidence |
| --- | --- | --- | --- | --- |
| node.node_id.ipv4 / .ipv6 / .fqdn | Node ID | pfcp.node_id_ipv4 / pfcp.node_id_ipv6 / pfcp.node_id_fqdn | node_id null when absent | OBSERVED |
| node.recovery_time_stamp | Recovery Time Stamp | pfcp.recovery_time_stamp | null when absent | OBSERVED |

## Session identifiers

| Field | Meaning | Source field | Optionality | Evidence |
| --- | --- | --- | --- | --- |
| session.cp_f_seid | control-plane F-SEID (seid + address) | structured `cp_f_seid`, or pfcp.f_seid.ipv4/ipv6 with role from the message definition | null when absent | OBSERVED |
| session.up_f_seid | user-plane F-SEID (seid + address) | structured `up_f_seid`, or pfcp.f_seid.ipv4/ipv6 with role from the message definition | null when absent | OBSERVED |

The reviewed reference exposes **no** field for the F-SEID's own 64-bit
SEID value, so `*.seid` is populated from structured input only; the
addresses may be populated from `pfcp.f_seid.ipv4` / `pfcp.f_seid.ipv6`.
The role is derived from the message definition (Establishment Request →
CP, Establishment Response → UP) and is never guessed for other messages.

## Cause

| Field | Meaning | Source field | Optionality | Evidence |
| --- | --- | --- | --- | --- |
| cause.code | PFCP cause value | pfcp.cause | null when absent | OBSERVED |
| cause.name | reviewed cause name; null when outside the reviewed table | derived from table 8.2.1-1 | null when code absent or unreviewed | DERIVED |

A PFCP Cause is protocol-defined outcome evidence, never a root cause.

## Rule groups

Rule groups are arrays. Item-level fields are bound only when the
relationship is provable; see the binding column.

| Field | Meaning | Source field | Hierarchy / binding | Evidence |
| --- | --- | --- | --- | --- |
| rule_operations.pdrs[].id | PDR identifier | structured `rule_groups.pdrs[].id`, or pfcp.pdr_id | structured-input; flattened path uses single-rule-message when exactly one PDR exists, otherwise unbound | OBSERVED |
| rule_operations.pdrs[].operation | CREATE / UPDATE / REMOVE | structured `operation`; a Session Establishment Request fixes CREATE by message definition | never inferred from the identifier | OBSERVED (structured) / DERIVED (message definition) |
| rule_operations.pdrs[].precedence | precedence | pfcp.precedence | binds only to a single PDR | OBSERVED |
| rule_operations.pdrs[].pdi_present | packet detection information present | derived from PDI child fields | binds only to a single PDR | DERIVED |
| rule_operations.pdrs[].source_interface | source interface name | pfcp.source_interface + table 8.2.2-1 | binds only to a single PDR | OBSERVED / DERIVED (name) |
| rule_operations.pdrs[].f_teid | F-TEID (teid, ipv4, ipv6, choose, choose_id) | pfcp.f_teid.teid / .ipv4_addr / .ipv6_addr / .choose_id, pfcp.f_teid_flags.ch | binds only to a single PDR | OBSERVED |
| rule_operations.pdrs[].ue_ip.ipv4 / .ipv6 | UE IP Address | pfcp.ue_ip_addr_ipv4 / pfcp.ue_ip_addr_ipv6 | binds only to a single PDR | OBSERVED |
| rule_operations.pdrs[].network_instance | Network Instance | pfcp.network_instance | binds only to a single PDR | OBSERVED |
| rule_operations.pdrs[].qfi_values | QFI values referenced by the PDR | structured `qfi_values`, or pfcp.qfi_value | flattened path binds only when the message holds exactly one rule item in total | OBSERVED |
| rule_operations.pdrs[].far_ids / .qer_ids / .urr_ids | rule references | structured only | structured-input only | OBSERVED (structured input) |
| rule_operations.fars[].id | FAR identifier | structured, or pfcp.far_id | same binding rules as PDR | OBSERVED |
| rule_operations.fars[].apply_action | DROP / FORW / BUFF / NOCP / DUPL | pfcp.apply_action.drop / .forw / .buff / .nocp / .dupl | binds only to a single FAR | OBSERVED |
| rule_operations.fars[].destination_interface | destination interface name | pfcp.dst_interface + table 8.2.2-1 | binds only to a single FAR | OBSERVED / DERIVED (name) |
| rule_operations.fars[].forwarding_parameters_present | forwarding parameters present | derived | binds only to a single FAR | DERIVED |
| rule_operations.fars[].outer_header_creation | description, teid, ipv4, ipv6 | pfcp.outer_hdr_desc, pfcp.outer_hdr_creation.teid / .ipv4 / .ipv6 | binds only to a single FAR | OBSERVED |
| rule_operations.qers[].id | QER identifier | structured, or pfcp.qer_id | same binding rules as PDR | OBSERVED |
| rule_operations.qers[].gate_status.ul / .dl | gate status | pfcp.gate_status.ulgate / pfcp.gate_status.dlgate | binds only to a single QER | OBSERVED |
| rule_operations.qers[].qfi | QFI | structured `qfi`, or pfcp.qfi_value | flattened path binds only when the message holds exactly one rule item in total | OBSERVED |
| rule_operations.qers[].ul_mbr / .dl_mbr / .ul_gbr / .dl_gbr | bit rates | pfcp.ul_mbr / pfcp.dl_mbr / pfcp.ul_gbr / pfcp.dl_gbr | binds only to a single QER | OBSERVED |
| rule_operations.urrs[].id | URR identifier | structured, or pfcp.urr_id | same binding rules as PDR | OBSERVED |
| rule_operations.urrs[].measurement_present | measurement metadata present | derived | binds only to a single URR | DERIVED |
| rule_operations.*[].binding_basis | structured-input / single-rule-message / unbound | derived | makes the association basis auditable per item | DERIVED |

## Unbound nested evidence

| Field | Meaning | Source | Evidence |
| --- | --- | --- | --- |
| unbound_ie_metadata.pdr_ids / .far_ids / .qer_ids / .urr_ids | rule identifiers observed but not covered by items | flattened identifiers, or structured `unbound_*_ids` | OBSERVED |
| unbound_ie_metadata.teids | F-TEID / Outer Header Creation TEIDs with no provable parent rule | pfcp.f_teid.teid, pfcp.outer_hdr_creation.teid, or structured `unbound_teids` | OBSERVED |
| unbound_ie_metadata.qfis | QFI values with no provable parent rule | pfcp.qfi_value, or structured `unbound_qfis` | OBSERVED |
| unbound_ie_metadata.causes | Causes observed without a provable parent rule | structured only | OBSERVED (structured input) |
| unbound_ie_metadata.limitations | explicit reasons the nested values stay unbound | derived | DERIVED |

## Evidence and derivations bookkeeping

`evidence.level` is always OBSERVED for the detailed event; every
deterministic transformation is enumerated in `derivations` (message_type,
message_kind, family, direction) so the observed/derived split stays
auditable. `evidence.source` names the capture frame and the message type
code.

## Tool-version caveat

The PFCP display-filter reference documents field availability from
Wireshark 2.6.0 to 4.6.9, and several flag fields were restructured over
that range (for example `pfcp.apply_action_flags` became
`pfcp.apply_action.*`). Re-verify every field name against the target
Wireshark release before relying on capture extraction.
