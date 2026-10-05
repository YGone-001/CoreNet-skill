# Supported NGAP Procedures

Basis: 3GPP TS 38.413 procedure codes as implemented by the Wireshark/TShark
4.7.1 NGAP dissector (`tshark -G values`, table `ngap.procedureCode`), for
version 0.3.0 additionally cross-checked against the TS 38.413 ASN.1 sources
packaged with that dissector (NGAP-PDU-Descriptions.asn and
NGAP-PDU-Contents.asn). This map covers only the bounded subset: UE-context
signaling, NAS transport, initial-context handling, UE-context release,
Paging, PDU Session resources, and the bounded N2 handover/path-switch
mobility subset. Everything else is reported UNSUPPORTED (code known) or
UNKNOWN (code not in the reviewed table) without invented semantics.

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
COMMAND (UEContextReleaseCommand, PDUSessionResourceReleaseCommand, and
HandoverCommand), COMPLETE (UEContextReleaseComplete). The original PDU
branch remains available in `pdu_type`; the two layers must not be
conflated. HandoverCommand carries COMMAND because its protocol role is
commanding handover execution at the source NG-RAN; its
successful-outcome branch identity stays visible in `pdu_type`.
HandoverNotify is an indication-only message with no request/outcome
relationship and carries null, like ErrorIndication. No
HANDOVER_SUCCESS, PATH_SWITCH_SUCCESS, or MOBILITY_FAILURE label exists.

`sender_role` is derived from the reviewed message identity: the AMF sends
DownlinkNASTransport, InitialContextSetupRequest, Paging,
UEContextReleaseCommand, PDUSessionResourceSetupRequest/ModifyRequest/
ReleaseCommand, HandoverCommand, HandoverPreparationFailure,
HandoverRequest, HandoverCancelAcknowledge, PathSwitchRequestAcknowledge,
and PathSwitchRequestFailure; the NG-RAN sends InitialUEMessage,
UplinkNASTransport, InitialContextSetupResponse/Failure,
UEContextReleaseRequest, UEContextReleaseComplete,
PDUSessionResourceSetupResponse/ModifyResponse/ReleaseResponse,
HandoverRequired, HandoverRequestAcknowledge, HandoverFailure,
HandoverNotify, HandoverCancel, and PathSwitchRequest. ErrorIndication can
be sent by either side, so its `sender_role` stays null. Endpoints are
never mapped to roles by address.

## Release reasoning boundary

Different entities and procedure paths can initiate a release: the NG-RAN
via UEContextReleaseRequest (with Cause), the AMF via
UEContextReleaseCommand (also without a preceding UEContextReleaseRequest in
the observed window). A UEContextReleaseRequest is not guaranteed to appear
before a UEContextReleaseCommand, and observing the initiating message does
not identify the end-to-end root cause. See `failure-cases.md`.

## Supported PDU Session resource procedures

Added in version 0.2.0. Reviewed against TS 38.413 19.4.0 clauses 9.2.x.
Resource-list indicator fields are listed with the operation and list role
they represent.

| Procedure code | Procedure | PDU branch | Message | Resource list field(s) | Operation / role |
| --- | --- | --- | --- | --- | --- |
| 29 | PDUSessionResourceSetup | initiatingMessage | PDUSessionResourceSetupRequest | PDUSessionResourceSetupListSUReq | SETUP / REQUEST |
| 29 | PDUSessionResourceSetup | successfulOutcome | PDUSessionResourceSetupResponse | PDUSessionResourceSetupListSURes; PDUSessionResourceFailedToSetupListSURes | SETUP / SUCCESS; SETUP / FAILED |
| 26 | PDUSessionResourceModify | initiatingMessage | PDUSessionResourceModifyRequest | PDUSessionResourceModifyListModReq | MODIFY / REQUEST |
| 26 | PDUSessionResourceModify | successfulOutcome | PDUSessionResourceModifyResponse | PDUSessionResourceModifyListModRes; PDUSessionResourceFailedToModifyListModRes | MODIFY / SUCCESS; MODIFY / FAILED |
| 28 | PDUSessionResourceRelease | initiatingMessage | PDUSessionResourceReleaseCommand | PDUSessionResourceToReleaseListRelCmd | RELEASE / COMMAND |
| 28 | PDUSessionResourceRelease | successfulOutcome | PDUSessionResourceReleaseResponse | PDUSessionResourceReleasedListRelRes | RELEASE / RESPONSE |
| 14 | InitialContextSetup | initiatingMessage | InitialContextSetupRequest | PDUSessionResourceSetupListCxtReq | INITIAL_CONTEXT_SETUP / REQUEST |
| 14 | InitialContextSetup | successfulOutcome | InitialContextSetupResponse | PDUSessionResourceSetupListCxtRes; PDUSessionResourceFailedToSetupListCxtRes | INITIAL_CONTEXT_SETUP / SUCCESS; INITIAL_CONTEXT_SETUP / FAILED |

Two mandatory distinctions:

- TS 38.413 defines **no** `PDUSessionResourceSetupFailure` message. A
  procedure reports failed resources through a failed-to-setup or
  failed-to-modify **item list inside a successfulOutcome response**.
  Message-level `result: SUCCESS` therefore never means every embedded
  resource succeeded.
- Initial Context Setup can carry PDU Session resources. A capture may
  establish N2 resource state without any standalone
  PDUSessionResourceSetupRequest, so both paths must be consumed.

## Supported N2 mobility procedures

Added in version 0.3.0. Procedure codes, message branch identities, and IE
membership were verified against the TS 38.413 ASN.1 sources packaged with
the reviewed 4.7.1 dissector. Note that the elementary procedure for code 11
is HandoverNotification while its message identity is `HandoverNotify` —
there is no `HandoverNotification` message in TS 38.413.

| Procedure code | Procedure | PDU branch | Message | Message-level Cause IE |
| --- | --- | --- | --- | --- |
| 12 | HandoverPreparation | initiatingMessage | HandoverRequired | yes |
| 12 | HandoverPreparation | successfulOutcome | HandoverCommand | no |
| 12 | HandoverPreparation | unsuccessfulOutcome | HandoverPreparationFailure | yes |
| 13 | HandoverResourceAllocation | initiatingMessage | HandoverRequest | yes |
| 13 | HandoverResourceAllocation | successfulOutcome | HandoverRequestAcknowledge | no |
| 13 | HandoverResourceAllocation | unsuccessfulOutcome | HandoverFailure | yes |
| 11 | HandoverNotification | initiatingMessage | HandoverNotify | no |
| 10 | HandoverCancel | initiatingMessage | HandoverCancel | yes |
| 10 | HandoverCancel | successfulOutcome | HandoverCancelAcknowledge | no |
| 25 | PathSwitchRequest | initiatingMessage | PathSwitchRequest | no |
| 25 | PathSwitchRequest | successfulOutcome | PathSwitchRequestAcknowledge | no |
| 25 | PathSwitchRequest | unsuccessfulOutcome | PathSwitchRequestFailure | no |

Boundary notes verified from the same basis:

- `HandoverSuccess` (procedure code 61) exists in the reviewed Release 19
  table but stays outside the bounded subset: it is reported UNSUPPORTED
  with identity only.
- PathSwitchRequestFailure carries **no message-level Cause IE** in the
  reviewed basis; its failure semantics are the unsuccessfulOutcome branch
  and the `PDUSessionResourceReleasedListPSFail` item list. Item causes for
  mobility messages live inside the opaque resource transfers, so a Cause is
  attributed to an item only from structured input.
- HandoverCancel is NG-RAN-initiated cancellation with a Cause; observing it
  is not a handover-failure, network-failure, or radio-failure verdict.
- HandoverNotify is NG-RAN-initiated mobility progress evidence; it never
  fabricates PathSwitchRequest, PFCP, or user-plane evidence.

### Mobility resource lists

| Message | Resource list field | Operation / role | Item fields |
| --- | --- | --- | --- |
| HandoverRequired | ngap.PDUSessionResourceListHORqd | HANDOVER_PREPARATION / REQUIRED | pDUSessionID, handoverRequiredTransfer |
| HandoverCommand | ngap.PDUSessionResourceHandoverList | HANDOVER_PREPARATION / HANDOVER | pDUSessionID, handoverCommandTransfer |
| HandoverCommand | ngap.PDUSessionResourceToReleaseListHOCmd | HANDOVER_PREPARATION / TO_RELEASE | pDUSessionID, handoverPreparationUnsuccessfulTransfer |
| HandoverRequest | ngap.PDUSessionResourceSetupListHOReq | HANDOVER_RESOURCE_ALLOCATION / REQUEST | pDUSessionID, s-NSSAI, handoverRequestTransfer |
| HandoverRequestAcknowledge | ngap.PDUSessionResourceAdmittedList | HANDOVER_RESOURCE_ALLOCATION / ADMITTED | pDUSessionID, handoverRequestAcknowledgeTransfer |
| HandoverRequestAcknowledge | ngap.PDUSessionResourceFailedToSetupListHOAck | HANDOVER_RESOURCE_ALLOCATION / FAILED | pDUSessionID, handoverResourceAllocationUnsuccessfulTransfer |
| PathSwitchRequest | ngap.PDUSessionResourceToBeSwitchedDLList | PATH_SWITCH / TO_BE_SWITCHED | pDUSessionID, pathSwitchRequestTransfer |
| PathSwitchRequest | ngap.PDUSessionResourceFailedToSetupListPSReq | PATH_SWITCH / FAILED | pDUSessionID, pathSwitchRequestSetupFailedTransfer |
| PathSwitchRequestAcknowledge | ngap.PDUSessionResourceSwitchedList | PATH_SWITCH / SWITCHED | pDUSessionID, pathSwitchRequestAcknowledgeTransfer |
| PathSwitchRequestAcknowledge | ngap.PDUSessionResourceReleasedListPSAck | PATH_SWITCH / RELEASED | pDUSessionID, pathSwitchRequestUnsuccessfulTransfer |
| PathSwitchRequestFailure | ngap.PDUSessionResourceReleasedListPSFail | PATH_SWITCH / RELEASED | pDUSessionID, pathSwitchRequestUnsuccessfulTransfer |

The HandoverCommand PDU Session list is the verified IE
`id-PDUSessionResourceHandoverList` (Wireshark field
`ngap.PDUSessionResourceHandoverList`); the reviewed ASN.1 defines no
`PDUSessionResourceListHOCmd`. A successfulOutcome mobility message may
carry admitted/switched **and** failed/released items in the same message;
both are preserved as independent item-scoped observations, never collapsed
into a message-wide resource verdict. The list roles describe the
resource's location inside the observed message, never an end-to-end
outcome: observing TO_BE_SWITCHED does not mean the session was switched,
and observing ADMITTED does not prove target-side allocation succeeded
end-to-end.

### Mobility metadata vocabulary

Verified reviewed vocabularies (`tshark -G values`):

- `ngap.HandoverType`: 0 intra5gs, 1 fivegs-to-eps, 2 eps-to-5gs,
  3 fivegs-to-utran. The observed value is preserved; the symbolic name is
  derived only for values in this mapping. Handover Type is never used to
  infer why a handover occurred, radio quality, or operator policy.
- `ngap.TargetID` CHOICE: 0 targetRANNodeID, 1 targeteNB-ID,
  2 choice-Extensions. Only presence and the reviewed choice alternative are
  recorded; no target node, site, or vendor identity is derived.
- Transparent containers (`ngap.SourceToTarget_TransparentContainer`,
  `ngap.TargetToSource_TransparentContainer`,
  `ngap.TargettoSource_Failure_TransparentContainer`): presence and octet
  length only; the embedded RRC/Xn information is never decoded.

`mobility.family` is the reviewed elementary-procedure family
(handover-preparation, handover-resource-allocation, handover-notification,
handover-cancel, path-switch). It is protocol-local identity, never a
Domain procedure stage, and no handover_attempt, handover_stage, or
mobility_terminal_state exists in this Skill's output.

## Resource item contents

Reviewed item structures (TS 38.413 19.4.0):

| Item | Fields |
| --- | --- |
| PDUSessionResourceSetupItemSUReq | pDUSessionID, pDUSessionNAS-PDU (optional), s-NSSAI, setup-request-transfer |
| PDUSessionResourceSetupItemSURes | pDUSessionID, setup-response-transfer |
| PDUSessionResourceFailedToSetupItemSURes | pDUSessionID, setup-unsuccessful-transfer |
| PDUSessionResourceSetupItemCxtReq | pDUSessionID, NAS-PDU (optional), s-NSSAI, setup-request-transfer |
| PDUSessionResourceSetupItemCxtRes | pDUSessionID, setup-response-transfer |
| PDUSessionResourceFailedToSetupItemCxtRes | pDUSessionID, setup-unsuccessful-transfer |
| PDUSessionResourceModifyItemModReq | pDUSessionID, NAS-PDU (optional), modify-request-transfer |
| PDUSessionResourceModifyItemModRes | pDUSessionID, modify-response-transfer |
| PDUSessionResourceFailedToModifyItemModRes | pDUSessionID, modify-unsuccessful-transfer |
| PDUSessionResourceToReleaseItemRelCmd | pDUSessionID, release-command-transfer |
| PDUSessionResourceReleasedItemRelRes | pDUSessionID, release-response-transfer |

The item Cause for a failed resource lives inside the encoded unsuccessful
transfer, so this Skill attributes a Cause to an item only when structured
input binds it; otherwise the Cause is preserved as unbound evidence.

## Recognized but unsupported resource procedures

Recognized by reviewed name and reported `UNSUPPORTED` with no resource
semantics: 27 PDUSessionResourceModifyIndication, 30
PDUSessionResourceNotify, and 61 HandoverSuccess. In version 0.3.0 the
bounded handover/path-switch subset (10, 11, 12, 13, 25) is supported; all
other mobility-adjacent procedures (RAN Status Transfer, UE Context
Resume/Suspend, location reporting, and similar) remain UNSUPPORTED.

## Unsupported and unknown codes

Codes 0-86 map to reviewed procedure names. For a code outside the
supported subset the Skill reports the name with
`support_status: UNSUPPORTED` and extracts nothing beyond the bounded field
set. Codes outside the reviewed table are `UNKNOWN`. Neither state
produces message semantics, result labels, or sender roles.
