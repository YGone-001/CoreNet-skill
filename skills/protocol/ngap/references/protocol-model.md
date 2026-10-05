# NGAP Protocol Model

Basis: 3GPP TS 38.413 version 19.4.0 Release 19 (NG-RAN; NG Application
Protocol, NGAP), reviewed through the NGAP dissector of Wireshark/TShark
4.7.1 (v4.7.1-0-g667ab240e6de). The 0.2.0 PDU Session resource field names
were taken from the published Wireshark NGAP display-filter reference and
have since been re-verified locally; the 0.3.0 mobility field names,
procedure branches, and vocabularies were verified by local introspection
(`tshark -G fields` / `-G values`) cross-checked against the TS 38.413
ASN.1 sources packaged with that dissector. Verification notes are recorded
per field in `field-reference.md`; universal-Release coverage is not
claimed.

## Role and context

NGAP is the application protocol between the NG-RAN (gNB) and the AMF over
the N2 reference point, carried on SCTP. This Skill answers protocol-local
questions only: which PDU, procedure, and message a frame carries, which UE
NGAP identifiers it exposes, which NGAP Cause it states, and how frames
correlate into UE contexts. It does not decide why an end-to-end procedure
failed; that belongs to higher-layer Skills once NAS-5GS and related
dependencies exist.

## PDU outcome model

Every NGAP PDU is one of three categories. The Skill preserves the category
actually resolved for a frame and never treats NGAP as plain
request/response:

- `initiatingMessage` — starts an elementary procedure.
- `successfulOutcome` — successful response branch, where the procedure
  defines one.
- `unsuccessfulOutcome` — unsuccessful response branch, where the procedure
  defines one.

Several supported procedures are indication- or message-only
(InitialUEMessage, UplinkNASTransport, DownlinkNASTransport, Paging,
UEContextReleaseRequest): they have an `initiatingMessage` and no response
branch. UEContextRelease pairs an `initiatingMessage`
(UEContextReleaseCommand) with a `successfulOutcome` (UEContextReleaseComplete).
InitialContextSetup has all three branches.

### How the PDU category is resolved

TShark 4.7.1 does not expose the NGAP PDU category as a filterable field.
The extractor therefore resolves `pdu_type` from one of two reviewed
sources, recorded in `pdu_type_basis`:

- `structured-input` — the structured input carries an explicit `pdu_type`
  value observed by the dissector export that produced it.
- `message-name` — the observed Info-column message name exactly matches a
  reviewed message name of the procedure's outcome branches.

If neither source identifies the category, `pdu_type` stays null and the
event remains valid with `support_status` unchanged. The category is never
guessed from ports, direction, or timing.

## UE-associated versus non-UE-associated signaling

- UE-associated messages carry RAN-UE-NGAP-ID and, once the AMF has
  assigned it, AMF-UE-NGAP-ID. InitialUEMessage carries only the
  RAN-UE-NGAP-ID because the AMF has not yet assigned its identifier.
- Non-UE-associated messages (for example Paging in its common form) carry
  no UE NGAP IDs. The correlator never merges them into a UE context, and
  the extractor never fabricates identifiers for them.

## Identifiers

- `RAN-UE-NGAP-ID` — assigned by the NG-RAN; unique within one NG
  interface instance (one AMF-to-NG-RAN SCTP pairing).
- `AMF-UE-NGAP-ID` — assigned by the AMF; unique within the NG interface
  instance from the AMF side.

Both are UE-context identifiers only. They are not SUPI, SUCI, IMSI,
5G-GUTI, or PDU Session IDs, and this Skill never renames or reuses them as
subscriber identity. Numeric equality of a UE NGAP ID in two different
captures or SCTP associations means nothing by itself; see
`correlation.md`.

## Cause

NGAP Cause is a CHOICE: a category (radioNetwork, transport, nas, protocol,
misc, plus extension) with a category-local value. The Skill preserves the
observed category and value exactly and stops there. A Cause is protocol
evidence; it is not an end-to-end root cause and never promotes to
CONFIRMED causation by itself.

## UE context versus PDU Session resource context

A UE NGAP context is established by the RAN-UE-NGAP-ID / AMF-UE-NGAP-ID
pair. One UE context may hold several PDU Session resources, and one NGAP
message may carry several of them at once. A PDU Session ID is therefore
meaningful only inside an established UE context: the same numeric value
may exist in another UE context, or on another SCTP association, without
referring to the same session.

Resource evidence is subordinate to the UE context and never merges it. It
also never becomes UE identity, a PFCP SEID, a GTP-U TEID, a QFI, or a PTI.

## PDU-level outcome versus resource-item outcome

The two layers are separate and must not be conflated:

- The message-level `result` label summarises the observed message's role
  in its elementary procedure (REQUEST, SUCCESS, COMMAND, COMPLETE, ...).
  It is derived from message identity only.
- Resource-item outcomes live in `pdu_session_resources[].resource_list_role`
  (REQUEST, SUCCESS, FAILED, COMMAND, RESPONSE, plus the mobility list
  roles REQUIRED, HANDOVER, TO_RELEASE, ADMITTED, TO_BE_SWITCHED, SWITCHED,
  RELEASED documented in `procedure-map.md`).

A `successfulOutcome` PDUSessionResourceSetupResponse may carry a
`PDUSessionResourceFailedToSetupListSURes`. Message-level `SUCCESS`
therefore never means that every embedded resource succeeded. The same
holds for mobility: a `HandoverRequestAcknowledge` may carry admitted and
failed items, and a `PathSwitchRequestAcknowledge` may carry switched and
released items at once. TS 38.413
defines no separate "PDU Session Resource Setup Failure" message; failure
is expressed through the failed item list inside the response.

## Resource-list binding

The dissector export used here is flattened, so repeated PDU Session IDs,
QFIs, and Causes do not carry their structural parent-child relationship.
Items are therefore built only when the binding is provable:

- structured input supplies an explicit `pdu_session_resources` array
  (basis `structured-input`); or
- exactly one reviewed resource-list indicator is observed, which
  attributes every observed PDU Session identity to that list (basis
  `single-list-message`); and
- nested QFI / NAS-PDU / transfer values attach to an item only when
  exactly one resource item exists (basis `single-resource-message`).

Anything else is preserved in `unbound_resource_metadata` with an explicit
limitation. Repeated fields are never zipped by array position.

## Transfer container boundary

PDU Session resource items carry encoded transfer IEs (setup request /
response / unsuccessful, modify request / response / unsuccessful, release
command / response, and the handover/path-switch transfers listed in
`procedure-map.md`). This Skill records transfer presence, reviewed kind,
and length only. It implements no general-purpose ASN.1 transfer decoder
and never dumps transfer payload bytes as evidence.

## Mobility evidence boundary

Version 0.3.0 adds the bounded N2 handover/path-switch subset (procedure
codes 10, 11, 12, 13, 25). The same evidence rules apply unchanged:

- Message-level `result` stays a local protocol-message role.
  `HandoverRequestAcknowledge` observed means only that the NGAP
  successfulOutcome branch was observed; it never means the handover
  completed end-to-end, the UPF path was switched, N3 traffic moved, or the
  old path was removed. No HANDOVER_SUCCESS or PATH_SWITCH_SUCCESS field
  exists in this Skill's output.
- `HandoverRequired` observed means only that an NGAP Handover Required
  message was observed; it does not prove radio degradation, source-side
  fault, or that the handover later succeeded.
- `HandoverCancel` observed is the protocol cancellation path with its
  Cause; it is not automatically a failure verdict.
- `HandoverNotify` is mobility progress evidence only; it never fabricates
  PathSwitchRequest, PFCP, or user-plane observations.
- Unsuccessful outcomes (HandoverPreparationFailure, HandoverFailure,
  PathSwitchRequestFailure) are direct protocol evidence with their Cause;
  they never become AMF, gNB, or radio root cause.
- radioNetwork Cause values stay observed protocol evidence; they do not
  confirm a radio fault.
- A successfulOutcome mobility message may carry admitted/switched **and**
  failed/released resource items at once; outcomes stay item-scoped in
  `pdu_session_resources[].resource_list_role` and are never flattened into
  a message-wide resource verdict.
- Mobility metadata (`mobility.family`, HandoverType value with reviewed
  symbolic name, TargetID presence with reviewed choice alternative,
  transparent-container presence/length) is protocol-local identity. It is
  never handover_attempt, handover_stage, mobility_terminal_state,
  path_switch_completed, or any Domain procedure state; the future Domain
  Skill owns those.
- NGAP never derives N3 tunnel identity, transport addresses, or UPF path
  state from opaque transfer containers, and owns no PFCP/SEID semantics.
  NAS-PDU inside HandoverRequest is preserved as presence and length only.

## Source and target associations

A handover involves a source NG-RAN association and a target NG-RAN
association. This Skill preserves each observed association separately and
never creates a synthetic cross-association UE identity: TS 38.413 provides
no protocol field that deterministically binds source and target signaling
into one UE context at the Protocol layer. Matching AMF-UE-NGAP-IDs, close
timestamps, sequential handover messages, or equal PDU Session IDs never
merge the two associations; future Domain correlation owns cross-procedure
source/target mobility association.

## Future N1 / N2 / N4 / N3 composition

This Skill owns N2 resource evidence only. Composing it into an end-to-end
PDU Session view requires the N1 session-management semantics owned by
`nas-5gs` plus PFCP/N4 and GTP-U/N3 evidence that do not yet exist in this
repository, and it belongs to a future `5gc-pdu-session` Domain Skill. This
Protocol Skill performs no cross-protocol N1/N2 join and no PFCP or GTP-U
mapping.

## Evidence boundary

- OBSERVED: procedure code, PDU category as resolved with its basis,
  message identity, UE NGAP IDs, Cause, SCTP metadata, frame number,
  presence flags.
- DERIVED: procedure-code-to-name mapping, message identity resolved
  through reviewed procedure branches, deterministic UE-context bindings,
  timeline ordering, derived context keys.
- INFERRED: only relationships strongly suggested by protocol behavior
  (for example, a release path initiated from the observed NG-RAN side).
- HYPOTHESIS: explanations needing more evidence.
- CONFIRMED: deliberately rare; this Skill does not confirm end-to-end
  root cause.

Sending side (sender_role) is derived from the reviewed message identity,
never from IP addresses. A UEContextReleaseCommand is sent by the AMF and a
UEContextReleaseRequest by the NG-RAN in the reviewed specification basis;
an observed message does not prove which implementation or operator caused
an outcome.
