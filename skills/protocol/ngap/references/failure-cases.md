# NGAP Failure Cases

Protocol-local abnormal or inconclusive patterns this Skill can report.
Each pattern names what is OBSERVED, what is DERIVED, and the hard boundary
against causal overreach.

## Abnormal protocol-local patterns

- Unknown procedure code — `ngap.procedureCode` outside the reviewed
  38.413 table. Reported as UNKNOWN; no message semantics are attached.
- Unsupported procedure — code inside the reviewed table but outside the
  bounded subset (handover, path switch, NG setup, PDU Session Resource
  Notify / Modify Indication, and similar). Reported as UNSUPPORTED with
  the reviewed procedure name and no message mapping.

## PDU Session resource patterns

- Setup Response with a failed resource item —
  `PDUSessionResourceFailedToSetupListSURes` carries one or more
  `pdu_session_id` values with role FAILED while the message itself is a
  `successfulOutcome`. Both facts are preserved; the failed item is not a
  root cause.
- Mixed success and failure in one response — a single
  PDUSessionResourceSetupResponse (or Modify Response, or Initial Context
  Setup Response) contains both SUCCESS and FAILED resource items. The
  Skill reports the message-level result and the per-item roles; it never
  collapses the message into an all-success or all-failure verdict.
- Resource Cause observed but not attributable — an item Cause exists in
  the capture yet the parent resource item cannot be proven from the
  extraction format. The Cause is preserved in
  `unbound_resource_metadata.cause_values` with an explicit limitation
  instead of being attached to an arbitrary item.
- QFI visible but not safely bound — repeated QFI values are observed
  alongside repeated PDU Session IDs without structural proof of the
  parent-child relationship. Every QFI is preserved in
  `unbound_resource_metadata.qfi_values`; none is zipped to an item by
  array position, and `session.qfi` is omitted.
- Unsupported transfer semantics — a transfer container is present but its
  encoded body is out of scope. Presence, reviewed kind, and length are
  recorded; the payload is never parsed or dumped.
- Unknown resource procedure — a procedure code outside the reviewed table
  with a PDU Session resource payload is UNKNOWN; nothing is decoded.
- Missing resource counterpart — a PDUSessionResourceReleaseCommand with no
  Release Response inside the capture window. Reported as an unclosed
  protocol-local outcome, never as a network-wide failure.
- Partial capture — the capture starts after the request that would explain
  a response, or ends before the counterpart. The observation window bounds
  every missing-evidence conclusion.
- Duplicate or retransmitted request — the same request identity observed
  more than once is preserved as separate observations in input order; the
  Skill does not deduplicate or pick a representative.
- Association conflict — the same numeric UE / PDU Session identifiers on
  two associations stay in separate contexts, as in `correlation.md`.
- Malformed extracted metadata — required fields absent or not integers
  (frame number, timestamp, procedure code, UE NGAP IDs, PDU Session ID,
  resource list role). The extractor fails loudly per record; it never
  guesses.
- Malformed extracted metadata — required fields absent or not integers
  (frame number, timestamp, procedure code, UE NGAP IDs). The extractor
  fails loudly per record; it never guesses.
- Unsuccessful outcome where supported — InitialContextSetupFailure,
  HandoverPreparationFailure, HandoverFailure, and PathSwitchRequestFailure
  observed. The failure is OBSERVED with its Cause where the reviewed
  message defines one; the end-to-end reason is not established by this
  Skill.

## N2 mobility patterns

Added in version 0.3.0. The bounded handover/path-switch evidence follows
the same rules; these patterns name the additional boundaries.

- Handover Required observed — an NGAP HandoverRequired message with
  HandoverType, Cause, TargetID, and to-be-handed-over resource items. It
  does not prove radio degradation, source-gNB fault, handover necessity,
  or later handover success.
- Handover Command observed — the successful preparation branch was
  observed. It does not mean the UE reached the target, the path switch
  completed, or the user plane moved.
- Handover Preparation Failure / Handover Failure observed — protocol
  unsuccessful outcomes with a message-level Cause. The Cause (for example
  radioNetwork) stays protocol evidence; it never becomes a source-gNB,
  AMF, or radio root cause.
- Path Switch Request Failure observed — unsuccessful outcome. The reviewed
  basis defines no message-level Cause IE for this message; released-item
  causes live inside the opaque transfers, so only structured input can
  bind them. The unsuccessful branch itself is the failure evidence.
- Handover Cancel observed — the protocol cancellation path with its Cause.
  It is not automatically a handover, network, or radio failure verdict;
  procedure-local interpretation belongs to a future Domain Skill.
- Handover Notify observed — mobility progress evidence only. The Skill
  never fabricates PathSwitchRequest, PathSwitchRequestAcknowledge, PFCP,
  or user-plane observations from it.
- Path Switch Acknowledge observed — the NGAP successfulOutcome branch
  observed. It does not prove UPF relocation, PFCP modification success,
  that all switched resources succeeded end-to-end, or that old GTP-U
  tunnels are gone, and it never fabricates N3 observations.
- Mixed mobility resource outcomes — a HandoverRequestAcknowledge with
  ADMITTED and FAILED items, or a PathSwitchRequestAcknowledge with
  SWITCHED and RELEASED items, preserves both item outcomes
  independently; no message-wide resource success or failure is inferred.
- Source and target associations — handover evidence on two SCTP
  associations (source and target NG-RAN) stays in separate contexts even
  when AMF-UE-NGAP-IDs match, timestamps are close, or the same
  transparent container appears on both sides. The Skill never creates a
  synthetic cross-association UE identity.
- Mobility transfer containers present — presence, reviewed kind, and
  octet length are recorded; the encoded transfer body (including any
  embedded transport-layer information) is never decoded, and no N3
  tunnel identity or UPF endpoint is ever derived from NGAP.
- Unsupported known mobility procedure — for example HandoverSuccess
  (code 61). Reported UNSUPPORTED with identity only; RAN Status Transfer
  and other mobility-adjacent procedures remain deferred.
- Cause stated in a failure or release message — the category/value pair
  is preserved (for example radioNetwork value 3, reviewed as
  release-due-to-ngran-generated-reason). This is protocol evidence, not a
  confirmed end-to-end root cause.
- Release initiation from the NG-RAN side — UEContextReleaseRequest
  observed with sender_role derived as ng-ran. INFERRED at most: the
  observed release path was initiated from the NG-RAN signaling side. It
  is NOT confirmed that the NG-RAN caused any user-visible failure; RRC,
  NAS, core, or transport evidence may be required.
- Conflicting UE-ID binding — a frame observes a RAN/AMF ID pair that
  contradicts an earlier derived binding in the same association. The
  conflict is reported with the first binding retained; the Skill does not
  adjudicate which observation is correct.
- Duplicate or ambiguous identity — the same UE NGAP ID pair reappearing
  with contradictory metadata, or a numeric ID collision across
  associations. Association scoping keeps contexts separate; the report
  shows both contexts instead of merging them.
- Expected outcome missing from the capture window — for example, a
  UEContextReleaseRequest with no UEContextReleaseCommand visible. This is
  reported as an unclosed protocol-local outcome under the observed
  capture boundary.

## Capture-boundary uncertainty

"Outcome not observed" must never be reported as "the network did not send
the outcome." Absence from one capture is not absence from the network.
Typical limits that preserve uncertainty:

- capture point (N2 observed at one side only),
- capture filters and truncation,
- SCTP reassembly or segmentation effects,
- timing skew and capture loss,
- encrypted or tunneled segments leaving the observed segment.

Reports built from this Skill's output must keep the capture window
explicit and phrase missing outcomes as unobserved-in-capture.

## Explicitly out of scope for causal claims

The Skill does not confirm: registration success or failure (NAS-5GS and
the future 5GC domain Skills own that), radio-layer diagnosis (RRC timers,
RLC/MAC/PHY measurements), AMF or gNB implementation defects (no product
or source mapping belongs here), or any end-to-end root cause. Its
evidence ceiling for cause attribution is INFERRED, and only for
protocol-local paths such as release initiation direction.
