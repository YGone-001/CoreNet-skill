# S1AP Protocol Model

## Normative basis

- 3GPP TS 36.413 — S1 Application Protocol (S1AP). Reviewed for the S1 setup,
  UE-associated signaling, Initial Context Setup and UE context release elementary
  procedures, their PDU categories and the Cause definition.
- 3GPP TS 23.401 — GPRS enhancements for E-UTRAN access. Reviewed for procedure
  context only: it explains where S1AP sits in initial attach, and it is never used
  as a source of S1AP message identity.
- Wireshark/TShark 4.7.1 S1AP dissector, inspected through `tshark -G fields`,
  `tshark -G values` and `tshark -G protocols` to confirm every field name and value
  table used by this Skill.

Specification and dissector versions are reported together because the Skill binds
decoded evidence to both: TS 36.413 defines the semantics, the dissector defines the
field identities that expose them.

## Elementary procedures in scope

| Procedure | Code | Messages |
| --- | --- | --- |
| S1 Setup | 17 | S1SetupRequest, S1SetupResponse, S1SetupFailure |
| Initial Context Setup | 9 | InitialContextSetupRequest, InitialContextSetupResponse, InitialContextSetupFailure |
| Initial UE Message | 12 | InitialUEMessage |
| Downlink NAS Transport | 11 | DownlinkNASTransport |
| Uplink NAS Transport | 13 | UplinkNASTransport |
| UE Context Release Request | 18 | UEContextReleaseRequest |
| UE Context Release | 23 | UEContextReleaseCommand, UEContextReleaseComplete |

Every other procedure code in the reviewed TS 36.413 table is reported with its
procedure name and `support_status: UNSUPPORTED`. A code outside that table is
`UNKNOWN`. In both cases no message identity is invented.

## PDU category

S1AP wraps each message in an `InitiatingMessage`, `SuccessfulOutcome` or
`UnsuccessfulOutcome` container. The category is resolved from the dissector
presence fields (`s1ap.initiatingMessage_element`, `s1ap.successfulOutcome_element`,
`s1ap.unsuccessfulOutcome_element`), falling back to the reviewed message name in the
Info column, and finally to an explicit input value. The resolution basis is
published with the event so a consumer can judge the evidence.

A procedure code alone is never enough: the same code carries a different message
identity per outcome branch, and selecting the wrong branch would misreport the
message.

## Identifiers

`eNB-UE-S1AP-ID` is allocated by the eNodeB and `MME-UE-S1AP-ID` by the MME. They are
kept as separate fields and are never substituted for one another. An absent
identifier stays `null`; it is never inferred from a neighbouring message.

The local `context_key` is derived, not standardized: it combines the capture file,
the SCTP association and the observed identifier pair. It is an evidence-scoping key,
not a protocol identity.

## Cause

S1AP Cause is a CHOICE over five groups: `radioNetwork`, `transport`, `nas`,
`protocol`, `misc`. The Skill publishes the observed group and value exactly. It
never translates a cause into a root cause, a verdict or a severity.

## Privacy

The NAS-PDU is carried as bytes. This Skill publishes presence and length only; the
payload is never decoded, stored or republished. Subscriber identity therefore cannot
leak through this Skill, because no identity field is read at all.
