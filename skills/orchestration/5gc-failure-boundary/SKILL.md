# 5GC Failure Boundary

## Purpose

Compose already-produced 5GC Domain analysis JSON from `5gc-registration-mobility`
and `5gc-pdu-session` into evidence-safe diagnostic groups and identify the
earliest safely orderable abnormal evidence boundary for each group across the
currently implemented 5GC procedure path. The Skill answers: which diagnostic
subject is being analyzed, which Domain procedure instances are safely related,
which abnormal-boundary candidates exist, which candidate is the first safely
orderable abnormal evidence boundary, what exact lower-layer evidence supports
that boundary, what later observations followed, what limitations prevent a
stronger conclusion, and what additional evidence would resolve an ambiguity.
It never claims an implementation root cause, never ranks candidates by
severity, and never reports network or procedure success.

## Scope

- Consume Domain analysis JSON only: `5gc-registration-mobility` (>=0.2.0) and
  `5gc-pdu-session` (>=0.4.0) analysis summaries. No raw protocol events, no
  PCAP parsing, no log parsing. Source versions are verified structurally and
  known older versions fail loudly (no prose-parsing fallback).
- Form diagnostic groups by exact common context only: capture file + SCTP
  association (contract-equivalent across the two Domain output formats) +
  RAN-UE-NGAP-ID + AMF-UE-NGAP-ID, all present and equal. Timestamp proximity,
  a single numeric UE identifier, equal PDU Session IDs, or similar procedure
  sequences never link analyses.
- Keep different capture files independent: no automatic cross-capture
  correlation exists in this version.
- Preserve PDU Session lifecycle generation identity (`session_generation`,
  `reuse_status`, `lifecycle_boundary_basis`) per source instance; generations
  are never collapsed by equal numeric PDU Session IDs.
- Build boundary candidates only from deviations already emitted by a Domain
  Skill, consuming their structured `evidence_refs` as the sole provenance
  contract (human-readable text is presentation only, never parsed), mapped
  exactly: `PROTOCOL_REJECT_OBSERVED`,
  `UNSUCCESSFUL_OUTCOME_OBSERVED`, `PROTOCOL_NEGATIVE_OUTCOME_OBSERVED`,
  `RESOURCE_FAILED_ITEM_OBSERVED`, `DELIVERY_FAILURE_NOTIFICATION_OBSERVED`,
  `MISSING_EXPECTED_COUNTERPART`, and `FIELD_CONFLICT` (as a deviation).
- Preserve evidence-quality deviations as evidence limitations, never selected
  as the first abnormal network-procedure boundary: `PARTIAL_CAPTURE`,
  `CORRELATION_AMBIGUITY`, `CORRELATION_CONFLICT`, `LIFECYCLE_AMBIGUITY`,
  `PROTECTED_OR_UNAVAILABLE_PAYLOAD`, `PROTECTED_INNER_MESSAGE_UNAVAILABLE`,
  `OUT_OF_ORDER_EVIDENCE`, `DUPLICATE_OR_RETRANSMITTED_EVIDENCE`, and
  `UNKNOWN_OR_RESERVED_PROTOCOL_VALUE` (supporting anomaly).
- Select the first boundary by evidence ordering only (frame provenance,
  bounded observation windows, source stage order) with outcomes `SELECTED`,
  `NO_ABNORMAL_BOUNDARY_OBSERVED`, `AMBIGUOUS_FIRST_BOUNDARY`, and
  `INSUFFICIENT_COMPARABLE_EVIDENCE`. No severity ranking exists.
- Block derived missing-evidence candidates from selection when the source
  Domain marks the observation window partial; `MISSING_EXPECTED_COUNTERPART`
  stays `DERIVED`, never an observed negative response.
- Classify boundary confidence (`HIGH`/`MEDIUM`/`LOW`) as selection and
  ordering confidence, explicitly not causal confidence.
- Report downstream observations with the neutral relation
  `OBSERVED_AFTER_BOUNDARY`, never as caused by the selected boundary.
- Emit deterministic `additional_evidence_needed` entries for ambiguous or
  insufficient cases and fixed not-confirmed statements bounding what the
  analysis does not establish.

## Non-Goals

- No implementation root-cause attribution, no root-cause hypothesis ranking.
- No vendor or network-function blame; no source-code mapping.
- No Handover, Path Switch, or UPF relocation; no IMS, EPC, policy, or charging.
- No raw protocol event interpretation, PCAP parsing, or log parsing.
- No success, failure, health, or end-to-end verdicts:
  `NO_ABNORMAL_BOUNDARY_OBSERVED` never means success.
- No causal relation between the selected boundary and downstream evidence.

## Inputs

- `--registration`: 5gc-registration-mobility analysis summary JSON (repeatable).
- `--pdu-session`: 5gc-pdu-session analysis summary JSON (repeatable).
- `--input-dir`: directory of Domain analysis JSON files, auto-detected by
  documented file-name substrings (`registration`, `pdu`).

## Outputs

- `scripts/analyze_failure_boundary.py [INPUTS] --output analysis.json [--report report.txt]`
- `scripts/failure_boundary_report.py analysis.json [--format text]`
- The analysis summary conforms to
  `schemas/5gc-failure-boundary-analysis.schema.json`; the text report renders
  the diagnostic subject, first abnormal evidence boundary, supporting
  evidence, earlier context, downstream observations, evidence limitations,
  additional evidence needed, and not-confirmed statements.

## Dependencies

Required: `[]` (standalone package; consumes only already-generated Domain JSON).
Optional: `5gc-registration-mobility >=0.1.0`, `5gc-pdu-session >=0.3.0`,
`procedure-evidence >=0.1.0`.

## Workflow

1. Obtain Domain analysis summaries from the supported Domain Skills.
2. Run `analyze_failure_boundary.py` to form diagnostic groups, extract
   boundary candidates, order them by evidence provenance, and select the
   first abnormal evidence boundary per group.
3. Render `failure_boundary_report.py` for the investigation report.
4. Treat boundary confidence as selection confidence only; hand root-cause
   reasoning to authorized external analysis.

## Evidence Rules

- OBSERVED: deviations and anchors directly emitted by a Domain Skill with
  exact frame provenance.
- DERIVED: missing-evidence boundaries bounded by source observation windows,
  diagnostic group formation, and ordering-basis resolution.
- No INFERRED/HYPOTHESIS/CONFIRMED claims are produced: causal reasoning is
  intentionally deferred.

## Failure Handling

Malformed or unsupported Domain input fails loudly with non-zero exit codes.
Duplicate identical Domain inputs are deduplicated deterministically. Ambiguous
orderings remain ambiguous; incomparable provenance is reported as
`INSUFFICIENT_COMPARABLE_EVIDENCE`; nothing is silently dropped.

## Validation

Run `python -m unittest tests/test_5gc_failure_boundary.py` from this package.
Repository checkouts also run `scripts/validate-5gc-failure-boundary.py`.

## References

- `references/boundary-model.md`: candidate classes and boundary anchors.
- `references/subject-linking.md`: diagnostic group formation and isolation.
- `references/ordering-model.md`: evidence ordering and selection statuses.
- `references/confidence-model.md`: boundary confidence semantics.
- `references/failure-cases.md`: bounded failure-case catalog.
