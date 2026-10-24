# NAS-EPS Protocol Model

## Normative basis

- 3GPP TS 24.301 — Non-Access-Stratum (NAS) protocol for Evolved Packet System.
  Reviewed for EPS mobility management message identities, the security header type,
  EMM cause values, EPS attach type values and the ESM message container.
- 3GPP TS 23.401 — GPRS enhancements for E-UTRAN access. Reviewed for procedure
  context only; it never supplies message identity.
- Wireshark/TShark 4.7.1 NAS-EPS dissector, inspected through `tshark -G fields`,
  `tshark -G values` and `tshark -G protocols`.

## Procedures in scope

| Procedure | Messages |
| --- | --- |
| `eps-attach` | Attach request, Attach accept, Attach complete, Attach reject |
| `identity` | Identity request, Identity response |
| `authentication` | Authentication request, Authentication response, Authentication failure, Authentication reject |
| `security-mode-control` | Security mode command, Security mode complete, Security mode reject |

Authentication and security mode control are separate elementary procedures with
different initiating messages and different outcomes. Consecutive occurrence in a
capture never merges them.

## Security header type and protection

| Value | Protection state | Meaning |
| --- | --- | --- |
| 0 | `PLAIN` | Plain NAS message, not security protected |
| 1 | `INTEGRITY_PROTECTED` | Integrity protected |
| 2 | `INTEGRITY_AND_CIPHERED` | Integrity protected and ciphered |
| 3 | `INTEGRITY_PROTECTED_NEW_CONTEXT` | Integrity protected with new EPS security context |
| 4 | `INTEGRITY_AND_CIPHERED_NEW_CONTEXT` | Integrity protected and ciphered with new EPS security context |
| 5 | `PARTIALLY_CIPHERED` | Integrity protected and partially ciphered |
| 11 | `EMM_TRANSPORT` | Security header for the EMM transport message |
| 12 | `SERVICE_REQUEST` | Security header for the service request message |
| 6–10, 13–15 | `RESERVED` | Reserved values |

When the protection state is not plain and no message identity is observable, the
event is `PROTECTED_INNER_MESSAGE_UNAVAILABLE`. This is a statement about what the
capture exposes, never a claim that the message is missing on the network.

## Direction

Direction is reported only when the enclosing S1AP procedure exposes it (11 downlink,
12 uplink, 13 uplink). The basis is recorded as `enclosing_s1ap_procedure`; otherwise
`direction` is null with basis `unavailable`. NAS-EPS owns no S1AP semantics and works
without that field.

## Privacy

The following are never read, stored or published: IMSI, IMEI, IMEISV, GUTI, TMSI,
RAND, AUTN, RES, XRES, key material, and the NAS payload bytes themselves. Only
presence, length, numeric type values and reviewed identities are published.
