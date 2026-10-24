# S1AP Field Reference

## Structured fields JSONL contract

One JSON object per line. Values are strings, as exported by `tshark -T fields`.
The canonical key is the reviewed field name below; `_ws.col.info` and
`_ws.col.Info` are both accepted because the decoder exports the lower-case header.

Required keys: `frame.number`, `frame.time_epoch`, `s1ap.procedureCode`.
Optional keys are ignored when absent and treated as empty when blank.

## Reviewed field set

| Field | Type | Use |
| --- | --- | --- |
| `frame.number` | integer | Frame provenance |
| `frame.time_epoch` | decimal seconds | Timestamp, normalized to UTC ISO-8601 |
| `ip.src`, `ip.dst`, `ipv6.src`, `ipv6.dst` | address | Signaling endpoints |
| `sctp.srcport`, `sctp.dstport` | integer port | SCTP endpoints |
| `sctp.assoc_index` | integer | SCTP association context |
| `_ws.col.info` | string | Observed message name (identity fallback) |
| `s1ap.procedureCode` | integer | Elementary procedure identity |
| `s1ap.initiatingMessage_element` | presence | PDU category |
| `s1ap.successfulOutcome_element` | presence | PDU category |
| `s1ap.unsuccessfulOutcome_element` | presence | PDU category |
| `s1ap.ENB_UE_S1AP_ID` | integer | eNodeB UE context identity |
| `s1ap.MME_UE_S1AP_ID` | integer | MME UE context identity |
| `s1ap.Cause` | integer | Cause presence |
| `s1ap.radioNetwork`, `s1ap.transport`, `s1ap.nas`, `s1ap.protocol`, `s1ap.misc` | integer | Cause group and value |
| `s1ap.NAS_PDU` | bytes | Presence and length only |
| `s1ap.TAC` | integer | Bounded location metadata |
| `s1ap.PLMNidentity` | bytes | Presence only |
| `s1ap.EUTRAN_CGI_element` | presence | Bounded location metadata |
| `s1ap.E_RABToBeSetupListCtxtSUReq` | presence | Initial Context Setup request list |
| `s1ap.E_RABSetupListCtxtSURes` | presence | Initial Context Setup response list |
| `s1ap.e_RAB_ID` | integer (repeated) | Observed E-RAB identifiers |

## Verified decoder behaviour (TShark 4.7.1)

- The Cause CHOICE index appears in `s1ap.Cause`; the selected group's value appears
  in the group field. The Skill reads the group field, not the choice index.
- `s1ap.e_RAB_ID` is the field name; `s1ap.ERAB_ID` does not exist.
- The S1AP dissector exposes no standalone field for the failed-to-setup E-RAB list
  inside InitialContextSetupResponse. The Skill therefore reports that bounded
  extraction limitation on those events instead of inventing item outcomes.
- Repeated fields are exported comma-joined; the first occurrence is used for
  scalar values and every occurrence for E-RAB identifiers.

## Discovery

Before extraction the Skill resolves the protocol filter from `tshark -G protocols`
and the field set from `tshark -G fields`. A required field that the installed
decoder does not expose fails loudly (exit 4). An optional field that is missing is
recorded as an empty value, never as a fabricated observation.
