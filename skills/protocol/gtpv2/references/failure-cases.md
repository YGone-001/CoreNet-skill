# Failure cases and decoder limitations

## Decoder limitations

| Limitation | Effect | Handling |
| --- | --- | --- |
| Flat `-T fields` output loses grouped-IE boundaries. | Message-scope and bearer-scope Cause, EBI and F-TEID values arrive as flat lists; `16,16` cannot be separated. | Capture input is dissected to PDML. Flat input publishes the values as `unbound_ie_metadata` and never claims bearer binding. |
| Repeated identical IEs collapse in `-T json`. | Two bearer contexts with identical display labels overwrite each other in a JSON object. | JSON output is not used for IE extraction. |
| Cause PCE/BCE/CS bits are not part of the flat field set. | Flat input cannot report them. | They are published only from PDML input. |
| `gtpv2.t` and `gtpv2.p` are nested under `gtpv2.flags`. | A protocol-root lookup returns nothing. | The extractor reads them from the flags subtree only, so an IE-scoped value is never mistaken for a header flag. |
| A message may carry several Cause IEs. | The first is not necessarily the message-scope one in flat input. | PDML input uses scope; flat input publishes the first as `message_cause` and the rest as `additional_causes` with a limitation. |
| Identity IEs are decoded by the dissector. | A naive exporter would copy IMSI/MSISDN/MEI into output. | The model drops the value at parse time and keeps a presence boolean. |

## Input failures

| Condition | Exit | Behavior |
| --- | --- | --- |
| Input path does not exist | 5 | `input file does not exist` on stderr. |
| Unknown file extension with `--input-format auto` | 5 | Asks for an explicit format. |
| Malformed JSON Lines record | 5 | Reports the line number and the JSON error. |
| Record missing `frame.number`, `frame.time_epoch` or `gtpv2.message_type` | 5 | Reports the field. |
| Message type outside 0..255 | 5 | Rejected rather than clamped. |
| PDML document not well formed | 5 | Reports the parse error. |
| No GTPv2-C records | 6 | No output file is created. |
| `tshark` missing for capture input | 3 | Names the missing dependency. |
| `tshark` exits non-zero | 4 | Includes its stderr. |
| Output equals input | 7 | Refuses to overwrite the source artifact. |
| Output exists without `--force` | 7 | Leaves the existing file untouched. |
| Output directory missing | 7 | Reports the directory. |

## Evidence-safe language

- A `Request accepted` Cause means that message was accepted. It does not mean
  the procedure, the PDN connection or the bearer succeeded.
- An `OPEN_REQUEST` transaction is not a timeout.
- An `AMBIGUOUS` transaction has no selected response; the candidates are
  listed but none is asserted.
- A bearer context without a Cause IE says nothing about that bearer's outcome.
- A missing field means the decoder or the input did not provide it. It is
  never replaced by an assumed value.

## Out of scope by design

GTPv1 and GTP-U payload, session and bearer lifecycle reconstruction,
cross-interface S11/S5-C association, Diameter, NAS, S1AP, IMS, and any
first-abnormal-boundary or root-cause conclusion.
