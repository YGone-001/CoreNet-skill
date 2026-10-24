# S1AP Procedure and Message Map

Procedure codes and names below were verified against the TShark 4.7.1 value table
for `s1ap.procedureCode` and cross-checked against 3GPP TS 36.413.

## Supported procedures

| Code | Procedure | initiatingMessage | successfulOutcome | unsuccessfulOutcome |
| --- | --- | --- | --- | --- |
| 9 | InitialContextSetup | InitialContextSetupRequest | InitialContextSetupResponse | InitialContextSetupFailure |
| 11 | downlinkNASTransport | DownlinkNASTransport | — | — |
| 12 | initialUEMessage | InitialUEMessage | — | — |
| 13 | uplinkNASTransport | UplinkNASTransport | — | — |
| 17 | S1Setup | S1SetupRequest | S1SetupResponse | S1SetupFailure |
| 18 | UEContextReleaseRequest | UEContextReleaseRequest | — | — |
| 23 | UEContextRelease | UEContextReleaseCommand | UEContextReleaseComplete | — |

## Local result and sender roles

| Message | result | sender_role |
| --- | --- | --- |
| S1SetupRequest | REQUEST | enodeb |
| S1SetupResponse | SUCCESS | mme |
| S1SetupFailure | FAILURE | mme |
| InitialUEMessage | REQUEST | enodeb |
| UplinkNASTransport | REQUEST | enodeb |
| DownlinkNASTransport | REQUEST | mme |
| InitialContextSetupRequest | REQUEST | mme |
| InitialContextSetupResponse | SUCCESS | enodeb |
| InitialContextSetupFailure | FAILURE | enodeb |
| UEContextReleaseRequest | REQUEST | enodeb |
| UEContextReleaseCommand | COMMAND | mme |
| UEContextReleaseComplete | COMPLETE | enodeb |

`result` is a local label describing the message's position inside its elementary
procedure. It is not a 3GPP wire value and it is not a procedure verdict.

`sender_role` follows the TS 36.413 signaling direction of the message identity.
Endpoint addresses are never mapped to network-function roles.

## Unsupported and unknown procedures

Known codes outside the bounded set (for example Paging `10`, Reset `14`,
UEContextModification `21`) keep their reviewed procedure name and are reported as
`UNSUPPORTED` with no message identity. Codes absent from the reviewed table are
`UNKNOWN`. Neither case produces a guessed message name.
