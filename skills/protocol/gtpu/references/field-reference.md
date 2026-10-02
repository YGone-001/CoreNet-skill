# GTP-U Field Reference

Each extracted field: normalized output field, meaning, source
Wireshark/TShark display-filter field, normative basis, optionality,
evidence classification, hierarchy/binding guarantee, reviewed Wireshark
version, and local verification state.

Reviewed environment note: field names come from the published Wireshark GTP
display-filter reference. **LOCAL TSHARK NOT RUN** — no tshark installation
was available, so these names are published-reference verified and not
locally re-dumped. No field name is invented: the reviewed reference exposes
no dedicated field for the encapsulated inner packet, so inner packet
metadata is accepted from structured input only and that is stated below.

## Frame and capture provenance

| Field | Meaning | Source field | Optionality | Evidence |
| --- | --- | --- | --- | --- |
| timestamp | UTC ISO-8601, microsecond precision | frame.time_epoch | required | DERIVED (deterministic conversion) |
| frame_number | capture frame number | frame.number | required | OBSERVED |
| capture_file | basename only; workstation paths are never recorded | input artifact | required | OBSERVED |

## GTP-U header

| Field | Meaning | Source field | Normative basis | Optionality | Evidence |
| --- | --- | --- | --- | --- | --- |
| header.version | GTP-U version | gtp.flags.version | TS 29.281 5.1 (shall be 1) | required (null when absent) | OBSERVED |
| header.protocol_type | PT bit: GTP (1) vs GTP' (0) | gtp.flags.payload | TS 29.281 5.1 | required (null when absent) | OBSERVED |
| header.e_flag | Extension Header flag | gtp.flags.e | TS 29.281 5.1 | required (null when absent) | OBSERVED |
| header.s_flag | Sequence Number flag | gtp.flags.s | TS 29.281 5.1 | required (null when absent) | OBSERVED |
| header.pn_flag | N-PDU Number flag | gtp.flags.pn | TS 29.281 5.1 | required (null when absent) | OBSERVED |
| header.message_type_code | message type code | gtp.message | TS 29.281 table 6.1-1 | required | OBSERVED |
| header.message_type | reviewed message name | derived from table 6.1-1 | TS 29.281 table 6.1-1 | required (null when UNKNOWN) | DERIVED |
| header.message_length | length of the payload following the mandatory header part | gtp.length | TS 29.281 5.1 | required (null when absent) | OBSERVED |
| header.teid | tunnel endpoint identifier | gtp.teid | TS 29.281 5.1 | required (null when absent) | OBSERVED |
| header.sequence_number | sequence number | gtp.seq_number | TS 29.281 5.1 (only when S=1) | null when S is clear or absent | OBSERVED |
| header.n_pdu_number | N-PDU number | gtp.npdu_number | TS 29.281 5.1 (only when PN=1) | null when PN is clear or absent | OBSERVED |
| header.next_extension_header | next extension header type | gtp.next | TS 29.281 5.1 (only when E=1) | null when E is clear or absent | OBSERVED |
| header.teid_expected_zero | whether the reviewed message definition requires an all-zeroes TEID | derived from TS 29.281 5.1 | TS 29.281 5.1 | required | DERIVED |

A field whose flag is clear is emitted as null and never replaced by an
invented zero. The observed TEID is never corrected when it deviates from
the reviewed expectation; the deviation is recorded as a limitation.

## Outer transport

| Field | Meaning | Source field | Optionality | Evidence |
| --- | --- | --- | --- | --- |
| outer.source_address / .destination_address | outer IP endpoints | ip.src / ip.dst, ipv6.src / ipv6.dst (first token) | null when absent | OBSERVED |
| outer.source_port / .destination_port | outer UDP ports | udp.srcport / udp.dstport | null when absent | OBSERVED |

The GTP dissector re-dissects the encapsulated packet, so a plain `ip.src`
export can contain both the outer and the inner address. The outer header is
parsed first, so this Skill takes the **first** token as the outer address.
Inner packet metadata is never derived this way; see below. UDP port 2152 is
the registered GTP-U port but never determines a network-function role.

## Extension headers

| Field | Meaning | Source field | Optionality | Evidence |
| --- | --- | --- | --- | --- |
| extension_headers[].type | extension header type | structured `extension_headers[].type`, or gtp.ext_hdr_type | required per item | OBSERVED |
| extension_headers[].name | reviewed type name; null when outside the reviewed table | derived from the reviewed extension header type table | required per item | DERIVED |
| extension_headers[].length | extension header length | structured `extension_headers[].length`, or gtp.ext_hdr.length | null in the flattened path when more than one header is present | OBSERVED |
| extension_headers[].next | next extension header type | structured `extension_headers[].next`, or gtp.ext_hdr.next | null in the flattened path when more than one header is present | OBSERVED |
| extension_headers[].binding_basis | structured-input / single-source-order / unbound | derived | required per item | DERIVED |

The flattened export exposes the type chain in packet order but does not
prove which length or next value belongs to which header, so a multi-header
chain keeps the types and leaves the per-header lengths unbound with an
explicit limitation. Repeated fields are never zipped by array position.

## PDU Session Container

| Field | Meaning | Source field | Normative basis | Optionality | Evidence |
| --- | --- | --- | --- | --- | --- |
| pdu_session_container.pdu_type | container PDU type | gtp.ext_hdr.pdu_ses_con.pdu_type, or structured `pdu_session_container.pdu_type` | TS 38.415 5.5.2 | container object null when absent | OBSERVED |
| pdu_session_container.pdu_type_name | DL/UL PDU SESSION INFORMATION | derived from TS 38.415 5.5.2 | TS 38.415 5.5.2 | null when pdu_type absent or unreviewed | DERIVED |
| pdu_session_container.qfi | QoS Flow Identifier | gtp.ext_hdr.pdu_ses_con.qos_flow_id, or structured `qfi` | TS 38.415 5.5.2 | null when absent | OBSERVED |
| pdu_session_container.rqi | Reflective QoS Indicator | gtp.ext_hdr.pdu_ses_con.rqi, or structured `rqi` | TS 38.415 5.4.1.1 | null when absent | OBSERVED |
| pdu_session_container.ppi | Paging Policy Indicator | gtp.ext_hdr.pdu_ses_con.ppi, or structured `ppi` | TS 38.415 5.4.1.1 (with PPP) | null when absent | OBSERVED |
| pdu_session_container.binding_basis | structured-input / single-source-order | derived | — | required | DERIVED |

When more than one container value is observed, the container object is
omitted and every observed value is preserved in
`unbound_metadata.pdu_session_container_values` with a limitation; no value
is selected arbitrarily. RQI and PPI bits are preserved as protocol
evidence only; no reflective-QoS policy or paging-policy conclusion is
drawn.

## Inner packet

| Field | Meaning | Source field | Optionality | Evidence |
| --- | --- | --- | --- | --- |
| inner_packet.ip_version | 4 or 6 | structured `inner_packet.ip_version` | inner object null when absent | OBSERVED |
| inner_packet.source_address / .destination_address | inner addresses | structured `inner_packet.*` | null when absent | OBSERVED |
| inner_packet.protocol | inner protocol / next header number | structured `inner_packet.protocol` | null when absent | OBSERVED |
| inner_packet.source_port / .destination_port | inner L4 ports | structured `inner_packet.*` | null when absent | OBSERVED |
| inner_packet.length | inner packet length | structured `inner_packet.length` | null when absent | OBSERVED |
| inner_packet.opaque | inner packet is ESP/IPsec or otherwise opaque | structured `inner_packet.opaque` | required | OBSERVED |
| inner_packet.binding_basis | structured-input | derived | required | DERIVED |

**Structured-input only.** The reviewed dissector reference exposes no
dedicated field for the encapsulated packet (only `gtp.tpdu_data`, an opaque
byte sequence), and the flattened export cannot separate the outer header
from the re-dissected inner header. Inner metadata is therefore accepted
from the explicit structured `inner_packet` object. Application payload
bytes are rejected outright: a structured `inner_packet` carrying
`payload`, `payload_bytes`, `application_payload` or `data` fails loudly.

Inner L4 ports are packet metadata only. A port number never becomes an
application protocol identity inside this Skill.

## Error Indication and End Marker

| Field | Meaning | Source field | Optionality | Evidence |
| --- | --- | --- | --- | --- |
| error_indication.affected_teid | TEID of the tunnel the peer has no context for | gtp.teid_data, or structured `gtp.teid_data` | null when absent | OBSERVED |
| error_indication.header_teid | the header TEID of the Error Indication itself | gtp.teid | null when absent | OBSERVED |
| error_indication.peer_address | peer address where directly exposed | structured `peer_address` | null when absent | OBSERVED |
| end_marker.teid | TEID of the directed context the End Marker belongs to | gtp.teid | null when absent | OBSERVED |
| recovery | Echo Recovery value | gtp.recovery | null when absent | OBSERVED |
| advertised_extension_header_count | number of advertised extension header types | gtp.num_ext_hdr_types | null unless a Supported Extension Headers Notification | OBSERVED |
| advertised_extension_headers[] | advertised type and reviewed name | structured `advertised_extension_header_types` | empty array otherwise | OBSERVED / DERIVED (name) |

The Error Indication header TEID and the affected tunnel TEID are separate
observations and are never conflated.

## Evidence and derivations bookkeeping

`evidence.level` is always OBSERVED for the detailed event; every
deterministic transformation is enumerated in `derivations` (message_type,
message_class). `evidence.source` names the capture frame and the message
type code.

## Tool-version caveat

The GTP display-filter reference documents field availability from Wireshark
1.0.0 to 4.6.9, and several flag fields were restructured over that range
(`gtp.flags.*` subfields are the current form). The PDU Session Container
fields are documented from 3.0.0 onwards, and the newer QoS-monitoring
container fields from 4.4.0. Re-verify every field name against the target
Wireshark release before relying on capture extraction.
