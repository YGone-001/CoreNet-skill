# S1AP Failure and Boundary Cases

| Case | Behaviour |
| --- | --- |
| Procedure outside the bounded set (for example Paging) | Event emitted with the reviewed procedure name, `support_status: UNSUPPORTED`, no message identity. |
| Procedure code absent from the reviewed table | `support_status: UNKNOWN`, no procedure name invented, derivation recorded. |
| PDU category not resolvable | `pdu_type: null` with basis `unavailable`; the message identity stays `UNKNOWN`. |
| eNB-UE-S1AP-ID absent | `null`; never inferred from a neighbouring message. |
| MME-UE-S1AP-ID absent (typical for InitialUEMessage) | `null`; the context keeps its own key and `SUPPORTED` strength. |
| Conflicting identifier pairs in one association | Both contexts are kept with `AMBIGUOUS` strength and explicit reasons. |
| NAS-PDU present | Presence and length only; the payload is never read. |
| InitialContextSetupResponse | The decoder exposes no failed-to-setup list field; `extraction_limitations` records that bounded gap. |
| Malformed structured record | Exit 5 with the offending line or field. |
| Missing required field | Exit 5 naming the field. |
| No S1AP records in the input | Exit 6; no empty output file is produced. |
| Output exists without `--force` | Exit 7; the existing file is left intact. |
| `tshark` missing | Exit 3; no partial output. |
| `tshark` fails | Exit 4; no partial output. |
