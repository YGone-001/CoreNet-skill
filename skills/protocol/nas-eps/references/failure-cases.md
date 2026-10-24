# NAS-EPS Failure and Boundary Cases

| Case | Behaviour |
| --- | --- |
| Message outside the bounded set (for example Tracking area update request) | Reviewed name, `support_status: UNSUPPORTED`, no procedure family. |
| Message code outside the reviewed table | `support_status: UNKNOWN`, no invented name. |
| Protected message with no visible identity | `PROTECTED_INNER_MESSAGE_UNAVAILABLE`; never reported as missing. |
| Protected message with a visible outer identity | Identity preserved, ciphered payload presence recorded. |
| ESM container present | Presence and length only; no ESM decoding. |
| Identity type observed | Numeric value only; the identity value is never read. |
| EMM cause unknown | Value published with `name: null`. |
| Direction not derivable | `direction: null`, basis `unavailable`. |
| Malformed structured record | Exit 5 with the offending line. |
| Missing required field | Exit 5 naming the field. |
| No NAS-EPS records in the input | Exit 6; no empty output file. |
| Output exists without `--force` | Exit 7; the existing file is left intact. |
| `tshark` missing or failing | Exit 3 or 4; no partial output. |
