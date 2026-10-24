# Procedure map

Message type codes follow 3GPP TS 29.274 Table 6.1-1 and were checked against
the TShark 4.7.1 `gtpv2.message_type` value table.

## Supported families

| Code | Message | Family | Direction in EPC |
| --- | --- | --- | --- |
| 1 | Echo Request | `echo` | either peer |
| 2 | Echo Response | `echo` | either peer |
| 32 | Create Session Request | `create-session` | MME → SGW-C, SGW-C → PGW-C |
| 33 | Create Session Response | `create-session` | PGW-C → SGW-C, SGW-C → MME |
| 34 | Modify Bearer Request | `modify-bearer` | MME → SGW-C, SGW-C → PGW-C |
| 35 | Modify Bearer Response | `modify-bearer` | PGW-C → SGW-C, SGW-C → MME |
| 36 | Delete Session Request | `delete-session` | MME → SGW-C, SGW-C → PGW-C |
| 37 | Delete Session Response | `delete-session` | PGW-C → SGW-C, SGW-C → MME |
| 170 | Release Access Bearers Request | `release-access-bearers` | MME → SGW-C |
| 171 | Release Access Bearers Response | `release-access-bearers` | SGW-C → MME |

## Known but unsupported

These are identified by name and marked `UNSUPPORTED`; no IE or transaction
analysis is claimed for them.

| Code | Message |
| --- | --- |
| 3 | Version Not Supported Indication |
| 95 / 96 | Create Bearer Request / Response |
| 97 / 98 | Update Bearer Request / Response |
| 99 / 100 | Delete Bearer Request / Response |
| 101 / 102 | Delete PDN Connection Set Request / Response |
| 128 / 129 | Identification Request / Response |
| 130 / 131 / 132 | Context Request / Response / Acknowledge |
| 149 / 150 | Detach Notification / Detach Acknowledge |
| 176 / 177 | Downlink Data Notification / Acknowledgement |
| 179 / 180 | PGW Restart Notification / Acknowledge |

Any other code is reported as `UNKNOWN` with `message_type: null`. The numeric
code is always preserved.

## Common traps

- `149` is Detach Notification, not Release Access Bearers. Release Access
  Bearers is `170/171`.
- Downlink Data Notification is `176/177`. Codes `120/121/122` are not the DDN
  pair in this version of the specification.
- F-TEID interface type `11` is `S11/S4 SGW GTP-C`, not `S10`. Interface type
  `10` is `S11 MME GTP-C`.
- Cause `68` is `Service not supported`; `70` is `Mandatory IE missing`. Cause
  `79` is unused (`Shall not be used`), not `Service not supported`.
- Cause `80` is `GRE key not found`; `90` is `Unable to page UE`.
- Cause `128` is `S1-U Path Failure`; `17` is `Request accepted partially`.
