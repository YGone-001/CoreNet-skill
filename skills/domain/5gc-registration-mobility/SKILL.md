# 5GC Registration & Mobility

## Purpose

Analyze bounded 5GC registration and access/mobility signaling at the
procedure level: which stages of the reviewed TS 23.502 registration
procedure were directly observed, which conditional branches were
entered, which expected counterpart evidence is missing, which
protocol-defined reject or unsuccessful outcome was observed, which
lower-layer message and field supports each procedure-local deviation,
and what cannot be concluded from the available capture. The Skill
consumes already-extracted evidence from the ngap, nas-5gs, and
cross-protocol-evidence Skills plus the generic procedure-evidence
contract; it answers procedure questions, never implementation
questions.

## Scope

- Form evidence-safe procedure instances from NGAP UE-context evidence
  (capture, SCTP association, RAN-UE-NGAP-ID; AMF-UE-NGAP-ID bound when
  observed), joining NAS events only through shared frame provenance.
- Evaluate the conditional registration model: initiation, identity,
  authentication, security mode, decision, completion, N2 context
  establishment, context release, paging, and service access. An
  unentered conditional branch is never a deviation; an entered branch
  activates its expected outcomes.
- Recognize protocol-defined rejections and unsuccessful outcomes with
  the Cause fields supplied by lower layers.
- Classify procedure-local deviations (protocol reject, unsuccessful
  outcome, missing expected counterpart, unknown or reserved values,
  correlation conflict, protected inner message unavailable, partial
  capture, out-of-order evidence, duplicates) and expose the exact
  lower-layer field finding supporting each.
- Emit generic procedure-evidence stage JSONL and a deterministic
  analysis summary JSON, plus a per-instance registration timeline.

## Non-Goals

- No PCAP parsing and no NAS or NGAP decoding; lower-layer Skills stay
  authoritative and no new field decoding happens here.
- No subscriber identity requirement or exposure: NGAP UE context
  identifiers are signaling context, not subscriber identity.
- No success, failure, or root-cause verdicts: a procedure-local
  deviation is not an end-to-end root cause; release initiator is not
  root cause; implementation blame is never derivable here.
- No 5GSM PDU session semantics, no complete mobility coverage
  (handover, path switch), no Open5GS/free5GC/vendor source mapping, no
  external logs required.

## Inputs

- `--ngap` NGAP detailed event JSONL (repeatable).
- `--nas` NAS-5GS detailed event JSONL (repeatable).
- `--correlation` cross-protocol-evidence correlation-event JSONL
  (optional; preferred for NAS joins, otherwise a minimal direct frame
  join is performed and labeled DERIVED).

## Outputs

- `scripts/analyze-registration.py --ngap F --nas F [--correlation F]
  --output analysis.json [--stage-output stages.jsonl]`
- `scripts/registration_timeline.py analysis.json [--format text|json]`
- The analysis summary conforms to
  schemas/5gc-registration-analysis.schema.json; stage JSONL conforms to
  the generic procedure-evidence schema (byte-identical package-local
  copy under schemas/).

## Dependencies

None required. Optional: procedure-evidence, cross-protocol-evidence,
ngap, nas-5gs, core-network-pcap as upstream evidence producers. The
package is standalone: runtime needs nothing outside this directory.

## Workflow

1. Obtain structured events from the Protocol Skills and correlation
   output from cross-protocol-evidence for the same capture.
2. Run the analyzer; review procedure instances, their terminal
   observations, deviations, and field findings.
3. Check observation-window limitations: capture start and end bound
   every missing-evidence conclusion.
4. Render the timeline for per-instance ordering.
5. Hand combined interpretation across procedures to Analysis
   Orchestration; this Skill stops at procedure-local analysis.

## Evidence Rules

- OBSERVED: protocol events, their causes, support statuses, and
  envelope states as supplied by lower layers.
- DERIVED: instance formation, frame joins, stage assignment,
  missing-counterpart determination, duplicate detection, ordering
  normalization, confidence, the derived instance identifier.
- INFERRED: only procedure interpretation strongly supported but not
  directly determined.
- HYPOTHESIS: explicitly marked possible explanations needing more
  evidence.
- CONFIRMED: never used as shorthand for implementation root cause.

## Failure Handling

Malformed lower-layer events, missing provenance, 5GSM-family records,
verdict wording, and unsafe output replacement fail loudly with
non-zero exits. Unsupported or unknown lower-layer messages are
preserved with the UNKNOWN_OR_RESERVED deviation and limit procedure
interpretation; no semantics are invented. When context cannot resolve
a record to a procedure instance, it stays UNBOUND.

## Validation

Run python tests/test_5gc_registration.py from this package.
Repository checkouts also run
scripts/validate-5gc-registration-mobility.py.

## References

references/procedure-model.md, references/registration.md,
references/authentication-security.md,
references/context-release-paging.md, references/service-access.md,
references/field-findings.md, references/limitations.md, rules/.
