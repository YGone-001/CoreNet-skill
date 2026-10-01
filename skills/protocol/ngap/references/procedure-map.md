# Supported NGAP Procedures

Basis: 3GPP TS 38.413 procedure codes as implemented by the Wireshark/TShark
4.7.1 NGAP dissector (`tshark -G values`, table `ngap.procedureCode`). This
map covers only the bounded 0.1.0 subset: UE-context signaling, NAS
transport, initial-context handling, UE-context release, and Paging.
Everything else is reported UNSUPPORTED (code known) or UNKNOWN (code not
in the reviewed table) without invented semantics.

## Supported messages

| Procedure code | Procedure | PDU branch | Message | UE NGAP IDs | Cause possible | NAS-PDU transported |
| --- | --- | --- | --- | --- | --- | --- |
| 15 | InitialUEMessage | initiatingMessage | InitialUEMessage | RAN only (AMF ID not yet assigned) | no (uses RRCEstablishmentCause) | yes |
| 46 | UplinkNASTransport | initiatingMessage | UplinkNASTransport | both | yes | yes |
| 4 | DownlinkNASTransport | initiatingMessage | DownlinkNASTransport | both | yes | yes |
| 14 | InitialContextSetup | initiatingMessage | InitialContextSetupRequest | both | on failure branch | yes |
| 14 | InitialContextSetup | successfulOutcome | InitialContextSetupResponse | both | no | no |
| 14 | InitialContextSetup | unsuccessfulOutcome | InitialContextSetupFailure | both | yes | no |
| 42 | UEContextReleaseRequest | initiatingMessage | UEContextReleaseRequest | both | yes | no |
| 41 | UEContextRelease | initiatingMessage | UEContextReleaseCommand | both | no | yes |
| 41 | UEContextRelease | successfulOutcome | UEContextReleaseComplete | both | no | no |
| 24 | Paging | initiatingMessage | Paging | none (non-UE-associated) | no | identity IEs only |
| 9 | ErrorIndication | initiatingMessage | ErrorIndication | both, presence varies | yes | no |
| 19 | NASNonDeliveryIndication | initiatingMessage | NASNonDeliveryIndication | both | yes | original NAS-PDU carried for delivery retry |

## Local protocol-state labels

`result` is a local normalized label derived from the reviewed message
identity — it is not a 3GPP wire value: REQUEST (procedure-initiating
messages), SUCCESS (successfulOutcome), FAILURE (unsuccessfulOutcome),
COMMAND (UEContextReleaseCommand), COMPLETE (UEContextReleaseComplete).
The original PDU branch remains available in `pdu_type`; the two layers
must not be conflated.

`sender_role` is derived from the reviewed message identity: the AMF sends
DownlinkNASTransport, InitialContextSetupRequest, Paging,
UEContextReleaseCommand; the NG-RAN sends InitialUEMessage,
UplinkNASTransport, InitialContextSetupResponse/Failure,
UEContextReleaseRequest, UEContextReleaseComplete. ErrorIndication can be
sent by either side, so its `sender_role` stays null. Endpoints are never
mapped to roles by address.

## Release reasoning boundary

Different entities and procedure paths can initiate a release: the NG-RAN
via UEContextReleaseRequest (with Cause), the AMF via
UEContextReleaseCommand (also without a preceding UEContextReleaseRequest in
the observed window). A UEContextReleaseRequest is not guaranteed to appear
before a UEContextReleaseCommand, and observing the initiating message does
not identify the end-to-end root cause. See `failure-cases.md`.

## Unsupported and unknown codes

Codes 0-86 map to reviewed procedure names (for example 12 HandoverPreparation,
21 NGSetup, 26 PDU Session Resource Modify). For such codes the Skill
reports the name with `support_status: UNSUPPORTED` and extracts nothing
beyond the bounded field set. Codes outside the reviewed table are
`UNKNOWN`. Neither state produces message semantics, result labels, or
sender roles.
