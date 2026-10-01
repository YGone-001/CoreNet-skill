# NGAP Protocol Model

Basis: 3GPP TS 38.413 (NG-RAN; NG Application Protocol, NGAP), reviewed
through the NGAP dissector of Wireshark/TShark 4.7.1
(v4.7.1-0-g667ab240e6de), whose procedure-code and cause vocabularies were
inspected with `tshark -G fields` and `tshark -G values`. Version-specific
behavior is recorded per field in `field-reference.md`; universal-Release
coverage is not claimed.

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
