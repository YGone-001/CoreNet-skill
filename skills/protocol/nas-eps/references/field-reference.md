# NAS-EPS Field Reference

## Structured fields JSONL contract

One JSON object per line, values as strings exported by `tshark -T fields`. The
canonical key is the reviewed field name below; `_ws.col.info` and `_ws.col.Info` are
both accepted.

Required keys: `frame.number`, `frame.time_epoch`. A record with no NAS message
identity and no protection evidence still produces an event, classified as `UNKNOWN`
or `PROTECTED_INNER_MESSAGE_UNAVAILABLE`.

## Reviewed field set

| Field | Type | Use |
| --- | --- | --- |
| `frame.number` | integer | Frame provenance |
| `frame.time_epoch` | decimal seconds | Timestamp, normalized to UTC ISO-8601 |
| `ip.src`, `ip.dst`, `ipv6.src`, `ipv6.dst` | address | Transport endpoints |
| `sctp.srcport`, `sctp.dstport` | integer port | SCTP endpoints |
| `sctp.assoc_index` | integer | SCTP association context |
| `_ws.col.info` | string | Observed message text (never used as identity) |
| `nas-eps.nas_msg_emm_type` | integer (hex or decimal) | Message identity |
| `nas-eps.security_header_type` | integer | Protection state |
| `nas-eps.emm.cause` | integer | EMM cause |
| `nas-eps.emm.eps_att_type` | integer | EPS attach type |
| `nas-eps.emm.type_of_id` | integer | Identity type value |
| `nas-eps.emm.esm_msg_cont` | bytes | Presence and length only |
| `nas-eps.ciphered_msg` | bytes | Presence only |
| `nas-eps.msg_auth_code` | bytes | Presence only |
| `s1ap.procedureCode` | integer | Optional direction hint |

## Verified decoder behaviour (TShark 4.7.1)

- `nas-eps.nas_msg_emm_type` is exported in hexadecimal form (for example `0x41`).
  The Skill parses both hexadecimal and decimal values.
- `nas-eps.security_header_type` may be exported comma-joined when several headers
  appear in one frame; the first occurrence is used and the rest are ignored.
- The decoder exposes no standalone protocol-discriminator field. The event records
  `EPS_MOBILITY_MANAGEMENT` with basis `decoder_dissection`, because the NAS-EPS
  dissector is only selected for that discriminator.
- Identity type names are not asserted: only the numeric `identity_type_value` is
  published, because decoder naming and TS 24.301 numbering must not be conflated.
- A ciphered frame with no visible message type is `PROTECTED_INNER_MESSAGE_UNAVAILABLE`,
  never `UNKNOWN`-as-missing.
