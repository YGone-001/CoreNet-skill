# NGAP

## Purpose

Answer WHAT an observed NGAP message means at the protocol layer: PDU
category, elementary procedure, concrete message identity, UE NGAP context
identifiers, NGAP Cause, and protocol-local UE-context correlation. This is
a Protocol-layer Skill for the N2 interface (NG-RAN to AMF, NGAP over
SCTP), bounded to the UE-context / NAS-transport / initial-context /
release / paging subset of 3GPP TS 38.413 as reviewed on Wireshark/TShark
4.7.1.

## Scope

- Identify NGAP PDU category (initiatingMessage / successfulOutcome /
  unsuccessfulOutcome) with its resolution basis, procedure code and name,
  and concrete message type for the supported subset.
- Extract RAN-UE-NGAP-ID and AMF-UE-NGAP-ID as distinct UE-context
  identifiers; never fabricate, merge, or rename them.
- Preserve NGAP Cause category and value exactly; never expand it into a
  root cause.
- Correlate frames into UE contexts deterministically, scoped by capture
  and SCTP association, with STRONG / MEDIUM / SINGLE-ID strength and
  explicit conflict detection.
- Emit detailed NGAP events (JSONL) and, optionally, a shared
  trace-event projection; render a protocol-local timeline.
- Report unsupported procedures as UNSUPPORTED and unknown codes as
  UNKNOWN without invented semantics.

## Non-Goals

- Do not decode NAS-PDU contents. Registration messages, 5GMM causes,
  SUCI/SUPI, 5G-GUTI, NSSAI, and DNN belong to the future nas-5gs Skill.
- Do not model 5GC registration, authentication, security mode, or PDU
  session state; no request/response state engine exists here.
- Do not diagnose radio layers (RRC timers, RLC/MAC/PHY measurements) or
  interpret a radioNetwork Cause as proof of radio fault.
- Do not map behavior to AMF or gNB implementations; no product source
  paths, functions, or configurations.
- Do not claim end-to-end root cause. A UEContextReleaseRequest observed
  from the NG-RAN side supports only that the observed release path was
  initiated from the NG-RAN signaling side (INFERRED); the NG-RAN being
  the root cause of a registration problem is NOT CONFIRMED by this Skill.
- Do not claim paging failed merely because no response is visible in the
  same capture; absence from one capture is not network-wide absence.
- Do not assume UEContextReleaseRequest always precedes
  UEContextReleaseCommand; release can be initiated from either side.

## Inputs

- An authorized PCAP/PCAPNG capture containing NGAP over SCTP, parsed with
  a user-installed tshark (never auto-installed), or
- a structured NGAP fields JSONL export with the documented fields in
  `references/field-reference.md` (deterministic offline input; unit tests
  use only this form), or
- optionally, pre-classified frames from `core-network-pcap` — note that
  its generic events lack NGAP semantics, so semantic extraction still
  requires raw capture access through tshark or a structured export.

## Outputs

- `scripts/extract-ngap.py <input> --output ngap-events.jsonl
  [--trace-output trace-events.jsonl]` — detailed NGAP event JSONL
  (schema `schemas/ngap-event.schema.json`, evidence OBSERVED with
  documented derivations) and optional trace-event projection.
- `scripts/correlate-ngap.py ngap-events.jsonl --output correlation.json`
  — UE-context correlation summary: bindings, strengths, conflicts,
  non-UE-associated events.
- `scripts/ngap_timeline.py ngap-events.jsonl [--format text|json]` —
  protocol-local timeline; no NAS interpretation.

## Dependencies

None required. Optional: `core-network-pcap` (capture provenance and
generic classification), `wireshark-analysis`, `protocol-reverse-engineering`,
`systematic-debugging` (investigation methods), `tshark` (direct capture
parsing; user-installed). The package is standalone: normal runtime needs
nothing outside this directory, including no repository root, docs, or
shared assets.

## Workflow

1. Confirm capture authorization and observation point; record the capture
   boundary and its limits.
2. Run the extractor on the capture or structured input; treat every
   detailed event as OBSERVED capture evidence with its derivations listed.
3. Run the correlator to obtain UE contexts, bindings, strengths, and
   conflicts; keep contexts scoped by capture and association.
4. Render the timeline for protocol-local ordering.
5. Interpret only within the evidence rules: last supported protocol-local
   event, first abnormal or missing local outcome, failure boundary — then
   hand off to higher-layer Skills for procedure semantics and root cause.
6. When NAS transport is observed, report `nas_pdu_present` with length
   only and state that NAS semantics require the nas-5gs Skill.

## Evidence Rules

- OBSERVED: procedure code, PDU category with resolution basis, message
  identity, UE NGAP IDs, Cause, SCTP metadata, frame number, presence
  flags.
- DERIVED: procedure-name mapping, message identity via reviewed branches,
  local result/sender-role labels, deterministic bindings and context
  keys, timestamp conversion, timeline ordering.
- INFERRED: protocol-local relationships strongly suggested but not
  directly proven (for example, release initiated from the observed NG-RAN
  side).
- HYPOTHESIS: candidate explanations needing more evidence.
- CONFIRMED: used conservatively; this Skill does not confirm end-to-end
  root cause.

Causation language must stay behind the evidence. Observed release
initiation direction is not root cause; an NGAP Cause category is not a
diagnosis.

## Failure Handling

Missing or malformed structured input, empty input, unavailable or failing
tshark, and unsafe output replacement produce a readable error on stderr
and a non-zero exit code (tool unavailable 3, tshark failure 4, malformed
input 5, no events 6, output failure 7). Unsupported procedures are
reported UNSUPPORTED, unknown codes UNKNOWN. If evidence is insufficient
to close a protocol-local outcome (for example, a release with no visible
completion), report the open boundary and name the additional capture or
log evidence that would resolve it — do not fill gaps with assumptions.

## Validation

Run `python tests/test_ngap.py` from this package for the fixture suite
(supported messages, unknown/unsupported codes, identifier extraction,
binding and conflict behavior, association isolation, cause preservation,
paging without fabricated context, NAS boundary, schema conformance,
deterministic output, malformed input, tshark-unavailable behavior,
standalone copy). Repository checkouts also run
`python scripts/validate-ngap.py` for the package contract.

## References

Read `README.md`, `references/protocol-model.md`,
`references/procedure-map.md`, `references/field-reference.md`,
`references/correlation.md`, and `references/failure-cases.md`. Reviewed
protocol basis: 3GPP TS 38.413 as implemented by the Wireshark/TShark 4.7.1
NGAP dissector; verify filter and field names per `filters/wireshark.txt`
when using another Wireshark version.
