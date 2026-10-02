# PFCP

## Purpose

Answer WHAT an observed PFCP message and information element mean at the
protocol layer: the PFCP header, the transaction sequence number, the
header SEID, the CP and UP F-SEIDs, bounded PDR/FAR/QER/URR rule groups and
their operations, the PFCP Cause, and protocol-local request/response
transaction correlation. This is a Protocol-layer Skill for the N4
interface, bounded to the Heartbeat, Association Setup, Session
Establishment, Session Modification, and Session Deletion subset of 3GPP
TS 29.244 version 19.6.0 Release 19.

## Scope

- Identify the PFCP message type from the reviewed table 7.3-1 and mark it
  SUPPORTED, UNSUPPORTED (known, semantically out of scope) or UNKNOWN.
- Preserve header fields: version, S flag, MP flag, message type code and
  name, message length, SEID, sequence number, and message priority.
- Keep header SEID, CP F-SEID and UP F-SEID as three distinct pieces of
  protocol evidence, and record whether the reviewed message definition
  requires a zero header SEID.
- Preserve bounded rule groups as arrays: PDR, FAR, QER and URR, each with
  its identifier, explicit CREATE/UPDATE/REMOVE operation, binding basis,
  and bounded type-specific attributes.
- Preserve bounded F-TEID and Outer Header Creation provisioning metadata,
  Network Instance, UE IP Address, and QFI evidence.
- Preserve PFCP Cause code and name without promoting it to a root cause.
- Correlate requests and responses into endpoint-scoped transactions, with
  explicit partial/open and duplicate-candidate reporting.
- Emit detailed PFCP events (JSONL), an optional shared trace-event
  projection, and a protocol-local timeline.

## Non-Goals

- Do not implement a raw PFCP byte parser or any hand-written binary
  decoder. Only tshark dissector output or structured offline input is
  used.
- Do not decode NAS or NGAP payloads, and do not map a PFCP SEID to a NAS
  or NGAP PDU Session ID.
- Do not inspect GTP-U G-PDU traffic. An F-TEID observed in PFCP is
  control-plane provisioning evidence; it never proves that a tunnel
  forwards traffic.
- Do not interpret SBI, N11, Nsmf_PDUSession, HTTP/2, or SM Context.
- Do not determine whether a PDU session was established, modified or
  released, and do not claim that user-plane forwarding works.
- Do not build a complete PFCP node-state engine.
- Do not implement Session Report or downlink-data-report semantics.
- Do not implement full PDI packet-filter matching semantics.
- Do not implement policy, PCC, ARP, or charging/usage-accounting
  semantics.
- Do not map behavior to SMF, UPF, or vendor implementations.
- Do not claim end-to-end root cause. A PFCP Cause is protocol-defined
  outcome evidence, not a diagnosis.

## Inputs

- An authorized PCAP/PCAPNG capture containing PFCP over UDP, parsed with a
  user-installed tshark (never auto-installed), or
- a structured PFCP fields JSONL export with the documented fields in
  `references/field-reference.md` (deterministic offline input; unit tests
  use only this form). The structured form may carry explicit `rule_groups`
  and explicit `cp_f_seid` / `up_f_seid` objects, which are the only forms
  that bind nested values by construction.

## Outputs

- `scripts/extract-pfcp.py <input> --output pfcp-events.jsonl
  [--trace-output trace-events.jsonl]` — detailed PFCP event JSONL
  (schema `schemas/pfcp-event.schema.json`) plus the optional trace-event
  projection.
- `scripts/correlate-pfcp.py pfcp-events.jsonl --output correlation.json`
  — endpoint-scoped transaction correlation summary (schema
  `schemas/pfcp-correlation.schema.json`).
- `scripts/pfcp_timeline.py pfcp-events.jsonl [--format text|json]` —
  protocol-local timeline; never prints a session or user-plane verdict.

## Dependencies

None required. Optional: `core-network-pcap` (capture provenance),
`wireshark-analysis`, `protocol-reverse-engineering`,
`systematic-debugging` (investigation methods), `tshark` (direct capture
parsing; user-installed). The package is standalone: normal runtime needs
nothing outside this directory, including no repository root, docs, or
shared assets.

## Workflow

1. Confirm capture authorization and observation point; record the capture
   boundary and its limits.
2. Run the extractor on the capture or structured input; treat every
   detailed event as OBSERVED capture evidence with its derivations listed.
3. Read `header`, `session` and `rule_operations` separately. Never treat
   the header SEID as a session identity by itself, and never merge the CP
   and UP F-SEIDs.
4. Run the correlator to obtain endpoint-scoped transactions; keep open and
   partial transactions explicit.
5. Render the timeline for protocol-local ordering.
6. Interpret only within the evidence rules: last supported protocol-local
   event, first abnormal or missing local outcome, failure boundary — then
   hand off to higher-layer Skills for procedure semantics and root cause.

## Evidence Rules

- OBSERVED: message type code, header flags, SEID, sequence number,
  priority, message length, endpoints, Cause, PDU/FAR/QER/URR identifiers,
  F-TEID and Outer Header Creation values, Network Instance, UE IP Address,
  QFI, rule operations declared by structured input.
- DERIVED: message name, procedure family, logical direction, message-level
  result label, source-interface names, transaction keys, correlation
  strength, binding basis.
- INFERRED: protocol-local relationships strongly suggested but not
  directly proven.
- HYPOTHESIS: candidate explanations needing more evidence.
- CONFIRMED: used conservatively; this Skill does not confirm end-to-end
  root cause.

## Failure Handling

Missing or malformed structured input, empty input, unavailable or failing
tshark, and unsafe output replacement produce a readable error on stderr
and a non-zero exit code (tool unavailable 3, tshark failure 4, malformed
input 5, no events 6, output failure 7). Unsupported messages are reported
UNSUPPORTED, unknown codes UNKNOWN. When nested rule evidence cannot be
attributed, it is preserved in `unbound_ie_metadata` with an explicit
limitation instead of being guessed. An open transaction is reported as a
capture boundary, never as a network failure.

## Validation

Run `python tests/test_pfcp.py` from this package for the fixture suite
(header semantics, SEID/F-SEID model, establishment identity transition,
session procedures, rule model, grouped hierarchy safety, transaction
correlation, endpoint isolation, trace projection, schema conformance,
deterministic output, malformed input, tshark-unavailable behavior,
standalone copy). Repository checkouts also run
`python scripts/validate-pfcp.py` for the package contract.

## References

Read `README.md`, `references/protocol-model.md`,
`references/message-map.md`, `references/field-reference.md`,
`references/session-identifiers.md`, `references/rule-model.md`,
`references/correlation.md`, and `references/failure-cases.md`. Reviewed
protocol basis: 3GPP TS 29.244 version 19.6.0 Release 19, cross-checked
against the Wireshark/TShark PFCP dissector reference; verify filter and
field names per `filters/wireshark.txt` when using another Wireshark
version.
