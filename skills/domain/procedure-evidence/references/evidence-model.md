# Procedure Evidence Model

The generic evidence model for Domain/Procedure Skills. The framework
answers: **What evidence is required to determine whether a telecom
procedure progressed through expected stages?** It never answers whether
a procedure succeeded, which network element caused a failure, or which
implementation code failed.

## Record

One JSONL record per stage observation:

- `procedure_name` / `procedure_version` — the procedure under
  examination (authored by the consuming Domain Skill; the framework
  implements none).
- `observation_group` — the observation context (for example the capture
  group whose provenance backs the evidence).
- `stage` — the expected observation point: `stage_id`, `stage_name`,
  `expected_protocols`, and `expected_message_types`. Stage names are
  generic; the framework owns no telecom procedure catalog.
- `expected_evidence` — what the stage should show if it progresses as
  expected.
- `observed_evidence` — what the lower layers actually showed, worded as
  observations with their source context.
- `missing_evidence` — expected items not observed. These stay missing
  evidence under the observation boundary.
- `evidence_basis` — OBSERVED when the record's evidence comes directly
  from lower layers; DERIVED when it is created from correlation output.
- `confidence` — HIGH/MEDIUM/LOW coverage of the expected evidence.
  This is evidence confidence only; the framework has no causal
  confidence.
- `limitations` — observation-boundary notes (capture window, extraction
  gaps, redaction) that qualify the record.

## Evidence rules

- OBSERVED: directly provided by lower layers (protocol event records).
- DERIVED: created from correlation output (for example a provenance
  join that groups two protocol observations).
- Never: convert missing evidence into failure. Allowed: "The
  confirmation-stage evidence was not observed." Forbidden: "The
  procedure failed."

## Verdict boundary

The words success, successful, failed, and root cause (any letter case)
are rejected in record fields and never emitted in timelines. The
output carries no success, failure, or root-cause field. Interpreting
the evidence — including any end-to-end outcome — belongs to Analysis
Orchestration, not to this framework.

## Ordering

Timelines render records in input order; the record author owns stage
ordering. Rendering is deterministic: identical input yields identical
output.

## Relationship to lower layers

Domain Skills consume protocol evidence and correlation output; this
framework does not replace protocol decoding or correlation. Protocol
references inside records (expected_protocols, expected_message_types,
evidence statements) are opaque strings; the framework never decodes
NAS, NGAP, or any other protocol, and it handles no subscriber or
session identity.
