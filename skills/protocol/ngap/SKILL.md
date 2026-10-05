# NGAP

## Purpose

Answer WHAT an observed NGAP message, item, and field mean at the protocol
layer: PDU category, elementary procedure, concrete message identity, UE
NGAP context identifiers, NGAP Cause, bounded PDU Session resource
evidence, bounded N2 handover/path-switch mobility evidence, and
protocol-local UE-context correlation. This is a
Protocol-layer Skill for the N2 interface (NG-RAN to AMF, NGAP over SCTP),
bounded to the UE-context / NAS-transport / Initial Context / release /
paging / PDU Session resource / handover-path-switch subset of
3GPP TS 38.413 version 19.4.0 Release 19, as implemented by the
Wireshark/TShark 4.7.1 NGAP dissector.

## Scope

- Identify NGAP PDU category (initiatingMessage / successfulOutcome /
  unsuccessfulOutcome) with its resolution basis, procedure code and name,
  and concrete message type for the supported subset.
- Extract RAN-UE-NGAP-ID and AMF-UE-NGAP-ID as distinct UE-context
  identifiers; never fabricate, merge, or rename them.
- Preserve NGAP Cause category and value exactly; never expand it into a
  root cause.
- Preserve bounded PDU Session resource evidence: PDU Session Resource
  Setup (request/response), Modify (request/response), Release
  (command/response), and PDU Session resources embedded in Initial
  Context Setup, as an array of resource items with PDU Session ID, list
  role, S-NSSAI, NAS-PDU presence, transfer presence/type, bound QFI
  values, item Cause, and the binding basis.
- Keep message-level outcomes and resource-item outcomes separate: an
  NGAP successfulOutcome never implies that every embedded PDU Session
  resource succeeded.
- Preserve nested QFI / Cause / transfer values that cannot be safely
  attributed to one resource item as unbound evidence instead of zipping
  them by position.
- Support the bounded N2 mobility subset with exact reviewed message
  identities: HandoverRequired / HandoverCommand / HandoverPreparationFailure
  (Handover Preparation), HandoverRequest / HandoverRequestAcknowledge /
  HandoverFailure (Handover Resource Allocation), HandoverNotify (Handover
  Notification), HandoverCancel / HandoverCancelAcknowledge (Handover
  Cancel), and PathSwitchRequest / PathSwitchRequestAcknowledge /
  PathSwitchRequestFailure (Path Switch Request).
- Preserve bounded mobility metadata: the reviewed procedure family, the
  observed HandoverType value with its reviewed symbolic name, TargetID
  presence with its reviewed choice alternative, and transparent-container
  presence and octet length. Container content is never decoded.
- Preserve mobility PDU Session resource lists (REQUIRED, HANDOVER,
  TO_RELEASE, ADMITTED, TO_BE_SWITCHED, SWITCHED, RELEASED, FAILED roles)
  as item-scoped arrays: a successfulOutcome mobility message may carry
  admitted/switched and failed/released items at once, and the message
  label never becomes an all-resource verdict.
- Keep source and target NG-RAN associations separate: no timestamp,
  identifier-only, or sequence-based join ever merges them, and no
  synthetic cross-association UE identity is created.
- Correlate frames into UE contexts deterministically, scoped by capture
  and SCTP association, with STRONG / MEDIUM / SINGLE-ID strength and
  explicit conflict detection.
- Emit detailed NGAP events (JSONL) and, optionally, a shared
  trace-event projection; render a protocol-local timeline.
- Report unsupported procedures as UNSUPPORTED and unknown codes as
  UNKNOWN without invented semantics.

## Non-Goals

- Do not decode NAS-PDU contents. Registration messages, 5GMM/5GSM
  causes, SUCI/SUPI, 5G-GUTI, NSSAI, DNN, PDU Session Type, SSC mode, and
  PTI belong to the nas-5gs Skill.
- Do not implement a generic ASN.1 transfer-container or
  transparent-container decoder and do not dump transfer payloads.
  Transfer presence, reviewed kind, and length only.
- Do not determine whether a PDU Session procedure succeeded; no
  request/response state engine and no PDU Session lifecycle exists here.
- Do not own GTP-U/TEID, PFCP/SEID, N3 tunnel, or SBI/N11 semantics, and
  never derive N3 tunnel identity or UPF path state from opaque NGAP
  transfer containers.
- Do not model handover or path-switch procedure outcomes: no
  handover_attempt, handover_stage, mobility_terminal_state,
  path_switch_completed, handover_success, path_switch_success, or
  mobility verdict fields; no source/target mobility association. Those
  belong to a future Domain Skill.
- Do not decode NAS inside mobility messages; a HandoverRequest NAS-PDU is
  preserved as presence and length only.
- Do not diagnose radio layers (RRC timers, RLC/MAC/PHY measurements) or
  interpret a radioNetwork Cause as proof of radio fault.
- Do not map behavior to AMF, gNB, SMF, or UPF implementations; no
  product source paths, functions, or configurations.
- Do not claim end-to-end root cause. A UEContextReleaseRequest observed
  from the NG-RAN side supports only that the observed release path was
  initiated from the NG-RAN signaling side (INFERRED); the NG-RAN being
  the root cause of a problem is NOT CONFIRMED by this Skill.
- Do not claim paging failed merely because no response is visible in the
  same capture; absence from one capture is not network-wide absence.
- Do not assume UEContextReleaseRequest always precedes
  UEContextReleaseCommand; release can be initiated from either side.
- Do not treat PDU Session ID as UE identity or as a global session
  identity; it is meaningful only inside an established UE context.

## Inputs

- An authorized PCAP/PCAPNG capture containing NGAP over SCTP, parsed with
  a user-installed tshark (never auto-installed), or
- a structured NGAP fields JSONL export with the documented fields in
  `references/field-reference.md` (deterministic offline input; unit tests
  use only this form). The structured form may carry an explicit
  `pdu_session_resources` array, which is the only form that binds a
  resource item's nested fields by construction, or
- optionally, pre-classified frames from `core-network-pcap` — note that
  its generic events lack NGAP semantics, so semantic extraction still
  requires raw capture access through tshark or a structured export.

## Outputs

- `scripts/extract-ngap.py <input> --output ngap-events.jsonl
  [--trace-output trace-events.jsonl]` — detailed NGAP event JSONL
  (schema `schemas/ngap-event.schema.json`, evidence OBSERVED with
  documented derivations), the optional `pdu_session_resources` array,
  and the optional `unbound_resource_metadata` object; plus the optional
  trace-event projection.
- `scripts/correlate-ngap.py ngap-events.jsonl --output correlation.json`
  — UE-context correlation summary: bindings, strengths, conflicts,
  non-UE-associated events. PDU Session resource metadata is preserved
  verbatim and never establishes a UE context.
- `scripts/ngap_timeline.py ngap-events.jsonl [--format text|json]` —
  protocol-local timeline with association, PDU Session IDs, resource
  outcomes, bound QFI values, transfer presence, mobility family, handover
  type, and container presence; no NAS interpretation and no
  session or mobility verdict.

## Dependencies

None required. Optional: `core-network-pcap` (capture provenance and
generic classification), `nas-5gs` (sibling Protocol Skill that owns N1
session-management semantics), `wireshark-analysis`,
`protocol-reverse-engineering`, `systematic-debugging` (investigation
methods), `tshark` (direct capture parsing; user-installed). The package
is standalone: normal runtime needs nothing outside this directory,
including no repository root, docs, or shared assets.

## Workflow

1. Confirm capture authorization and observation point; record the capture
   boundary and its limits.
2. Run the extractor on the capture or structured input; treat every
   detailed event as OBSERVED capture evidence with its derivations listed.
3. Read the resource array, not the message-level result, to learn what
   happened to each PDU Session resource; check `unbound_resource_metadata`
   for nested values that could not be attributed.
4. Run the correlator to obtain UE contexts, bindings, strengths, and
   conflicts; keep contexts scoped by capture and association.
5. Render the timeline for protocol-local ordering.
6. Interpret only within the evidence rules: last supported protocol-local
   event, first abnormal or missing local outcome, failure boundary — then
   hand off to higher-layer Skills for procedure semantics and root cause.
7. When NAS transport is observed, report `nas_pdu_present` with length
   only and state that NAS semantics require the nas-5gs Skill.

## Evidence Rules

- OBSERVED: procedure code, PDU category with resolution basis, message
  identity, UE NGAP IDs, Cause, PDU Session IDs, resource list indicators,
  QFI values, transfer containers, mobility procedure family input values,
  HandoverType and TargetID observed values, transparent-container
  presence, SCTP metadata, frame number, presence flags.
- DERIVED: procedure-name mapping, message identity via reviewed branches,
  local result/sender-role labels, resource operation/role labels, mobility
  family, HandoverType and TargetID reviewed symbolic names, binding
  basis, deterministic bindings and context keys, timestamp conversion,
  timeline ordering.
- INFERRED: protocol-local relationships strongly suggested but not
  directly proven (for example, release initiated from the observed NG-RAN
  side).
- HYPOTHESIS: candidate explanations needing more evidence.
- CONFIRMED: used conservatively; this Skill does not confirm end-to-end
  root cause.

Causation language must stay behind the evidence. Observed release
initiation direction is not root cause; an NGAP Cause category is not a
diagnosis; a failed resource item is not a root cause.

## Failure Handling

Missing or malformed structured input, empty input, unavailable or failing
tshark, and unsafe output replacement produce a readable error on stderr
and a non-zero exit code (tool unavailable 3, tshark failure 4, malformed
input 5, no events 6, output failure 7). Unsupported procedures are
reported UNSUPPORTED, unknown codes UNKNOWN. If evidence is insufficient
to close a protocol-local outcome (for example, a release with no visible
completion, or QFI values whose parent resource item is not provable),
report the open boundary and name the additional capture or log evidence
that would resolve it — do not fill gaps with assumptions.

## Validation

Run `python tests/test_ngap.py` from this package for the fixture suite
(supported messages, unknown/unsupported codes, identifier extraction,
binding and conflict behavior, association isolation, cause preservation,
paging without fabricated context, NAS boundary, PDU Session resource
setup/modify/release, Initial Context embedded resources, multi-resource
messages, mixed success/failed lists, QFI binding and ambiguity, bounded
handover/path-switch mobility evidence, sender roles, HandoverType and
TargetID handling, transparent-container presence, item-scoped mobility
resource outcomes, source/target association isolation, trace projection,
timeline, schema conformance, deterministic output, malformed input,
tshark-unavailable behavior, standalone copy). Repository checkouts also
run `python scripts/validate-ngap.py` for the package contract.

## References

Read `README.md`, `references/protocol-model.md`,
`references/procedure-map.md`, `references/field-reference.md`,
`references/correlation.md`, and `references/failure-cases.md`. Reviewed
protocol basis: 3GPP TS 38.413 version 19.4.0 Release 19, as implemented
by the Wireshark/TShark 4.7.1 NGAP dissector; verify filter and field
names per `filters/wireshark.txt` when using another Wireshark version.
