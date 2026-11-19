# IMS session failure and ambiguity cases

| Case | Result |
| --- | --- |
| Initial INVITE without response | Attempt with `NO_FINAL_RESPONSE`; capture incompleteness |
| 100 Trying only | Provisional-only; no Early Dialog |
| Tagged 180 or 183 only | Early Dialog evidence; no confirmed session |
| 2xx without provisional | Confirmed Dialog; 180/183 not required |
| 2xx without ACK | Confirmed Dialog preserved; `TWO_XX_ACK_NOT_OBSERVED` |
| Non-2xx INVITE final | `NEGATIVE_FINAL_OBSERVED`; not successful establishment |
| Non-2xx ACK | Separate transaction-layer ACK evidence |
| Multiple 2xx branches | Independent accepted branches; no preferred branch |
| Accepted and rejected branches | Both published; neither branch invalidates the other |
| Repeated 180/183 on one tag | One branch; repeated response observations preserved |
| CANCEL without final response | CANCEL request observation; INVITE final missing |
| 200 CANCEL without INVITE final | CANCEL response observed; no INVITE outcome |
| 200 CANCEL + 487 INVITE | Sequence observed; INVITE transaction termination still not claimed |
| Unrelated 200 OK | Not associated with the attempt; unbound CANCEL observation |
| Conflicting CANCEL association | Explicit conflict; no cancel success |
| BYE with 2xx | SIP termination signaling supported |
| BYE without response | Incomplete; dialog state not promoted to terminated |
| BYE negative response | Release not established |
| BYE without dialog creator | Unbound observation; no attempt owner |
| re-INVITE / UPDATE | In-dialog observation; `NOT_INTERPRETED` |
| Mid-capture INVITE | Attempt with incomplete evidence |
| Same Call-ID, distinct initial INVITEs | Separate attempts |
| Same frame, multiple messages | Message occurrence keeps references unique |
| Cross-capture artifacts | Rejected |
| Missing source event | Rejected |
| Duplicate transaction reference | Rejected |
| Malformed event contract | Rejected |
| No INVITE | Valid zero-attempt analysis |
| Empty session evidence | Valid zero-attempt analysis |
| Bounded publication | Observed/published/omitted accounting conserved |