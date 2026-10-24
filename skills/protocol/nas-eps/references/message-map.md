# NAS-EPS Message Map

Message codes below were verified against the TShark 4.7.1 value table for
`nas-eps.nas_msg_emm_type` and cross-checked against 3GPP TS 24.301.

## Supported messages

| Code | Message | Procedure | result |
| --- | --- | --- | --- |
| 0x41 (65) | Attach request | `eps-attach` | REQUEST |
| 0x42 (66) | Attach accept | `eps-attach` | ACCEPT |
| 0x43 (67) | Attach complete | `eps-attach` | COMPLETE |
| 0x44 (68) | Attach reject | `eps-attach` | REJECT |
| 0x52 (82) | Authentication request | `authentication` | REQUEST |
| 0x53 (83) | Authentication response | `authentication` | RESPONSE |
| 0x54 (84) | Authentication reject | `authentication` | REJECT |
| 0x55 (85) | Identity request | `identity` | REQUEST |
| 0x56 (86) | Identity response | `identity` | RESPONSE |
| 0x5c (92) | Authentication failure | `authentication` | FAILURE |
| 0x5d (93) | Security mode command | `security-mode-control` | COMMAND |
| 0x5e (94) | Security mode complete | `security-mode-control` | COMPLETE |
| 0x5f (95) | Security mode reject | `security-mode-control` | REJECT |

## Known but unsupported messages

Detach request/accept, Tracking area update request/accept/complete/reject, Extended
service request, Control plane service request, Service reject/accept, GUTI
reallocation command/complete, EMM status, EMM information, Downlink/Uplink NAS
transport, CS service notification, and the generic NAS transport messages keep their
reviewed names and are reported as `UNSUPPORTED`.

A code outside the reviewed table is `UNKNOWN` and carries no invented name.

## Cause values

EMM cause names follow the reviewed TS 24.301 §9.9.3.9 table and the decoder value
table, for example `19` = ESM failure, `20` = MAC failure, `21` = Synch failure,
`22` = Congestion, `23` = UE security capabilities mismatch, `24` = Security mode
rejected, unspecified. An unknown cause value is published with `name: null`; the
numeric value is always authoritative.
