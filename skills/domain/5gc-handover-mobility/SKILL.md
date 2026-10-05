# 5GC Handover Mobility

## Purpose

Form bounded 5GC mobility procedure attempts from already-produced NGAP,
PFCP, GTP-U, and SBI-HTTP2 evidence and answer: which handover attempts and
Path Switch attempts exist, which source and target contexts are safely
associated, which conditional stages were observed, which protocol outcomes
and item-scoped PDU Session resource outcomes were observed, which expected
counterparts are missing under the capture boundary, which bounded N11/N4/N3
supporting evidence is safely associated, and which procedure-local
deviations exist with structured provenance. This is a Domain-layer Skill
consuming Protocol-layer outputs; it never re-decodes protocols, never
claims handover or path-switch success, never attributes blame, and never
selects the cross-Domain first abnormal boundary (that belongs to Analysis
Orchestration).

## Scope

- Maintain two separate attempt families: `handover_attempts[]` and
  `path_switch_attempts[]`. Neither is mandatory for the other; a Path
  Switch without N2 handover evidence is a valid independent attempt.
- Associate source and target contexts only through the same capture, a
  scoped AMF-UE-NGAP-ID context, compatible reviewed message roles, and
  temporal sanity. Strengths: STRONG, SUPPORTED, AMBIGUOUS, UNBOUND.
  Timestamp proximity alone, equal RAN-UE-NGAP-IDs, equal PDU Session IDs,
  and AMF-UE-NGAP-ID alone never associate anything.
- Protect against AMF-UE-NGAP-ID reuse: identifier reuse across distinct
  context lifetimes never merges attempts; competing candidates keep the
  association AMBIGUOUS instead of nearest-in-time selection.
- Model conditional handover stages (initiation, preparation outcome,
  target resource allocation, execution notification, cancellation) and
  Path Switch stages (request, outcome, session/user-plane updates).
  Missing-evidence rules are branch-aware: a safely associated cancel
  branch stops requiring Command/Notify as though execution must continue.
- Preserve HandoverType as INTRA_5GS or INTER_SYSTEM_OR_OTHER; inter-system
  types carry `UNSUPPORTED_HANDOVER_TYPE_FOR_DOMAIN_PROCEDURE` and no
  inter-system semantics are applied.
- Keep PDU Session resource outcomes item-scoped: ADMITTED/FAILED and
  SWITCHED/RELEASED items in one message stay independent observations;
  FAILED items produce `RESOURCE_FAILED_ITEM_OBSERVED`; contradictory roles
  across linked stages produce `FIELD_CONFLICT` with both preserved.
- Associate N11 `Nsmf_PDUSession UpdateSMContext`, N4 PFCP Session
  Modification, and N3 GTP-U evidence only through safe session and tunnel
  context (PDU Session ID + capture + window; PDU-session-context header
  SEID; TEID + directed endpoints). An HTTP 2xx or PFCP accepted response
  never becomes mobility success; missing supporting evidence never becomes
  mobility failure; no End Marker and no G-PDU stay neutral.
- Label bound tunnels with neutral TUNNEL_A/TUNNEL_B roles; an old/new path
  role requires reviewed tunnel lifecycle context this version does not
  establish.
- Link a Path Switch attempt to a handover attempt only when a unique
  compatible, non-failed/cancelled handover attempt exists in the same
  scoped context (relationship SUPPORTED); multiple candidates stay
  AMBIGUOUS; none stays independent with `related_handover_attempt_id: null`.
- Emit procedure-local deviations with structured `evidence_refs` (EVENT,
  FIELD_FINDING, OBSERVATION_WINDOW) consumable by Analysis Orchestration
  without prose parsing.

## Non-Goals

- No protocol decoding: NGAP, PFCP, GTP-U, SBI, and NAS semantics stay in
  their Protocol Skills; NGAP opaque mobility transfer bytes are never
  parsed and no N3 tunnel identity is derived from NGAP.
- No end-to-end verdicts: no HANDOVER_SUCCESS, PATH_SWITCH_SUCCESS,
  HANDOVER_FAILED_END_TO_END, UPF-relocation success, or user-plane
  validation exists in any output.
- No radio, RRC, MAC, or PHY diagnosis; a radioNetwork Cause stays observed
  protocol evidence.
- No RAN Status Transfer, inter-system or 5GS-EPS mobility procedure
  semantics, Xn protocol ownership, N9, indirect data-forwarding diagnosis,
  or QoS-policy semantics.
- No subscriber identity handling; AMF-UE-NGAP-ID is never a SUPI, SUCI,
  permanent UE identity, cross-AMF identity, or cross-capture identity.
- No implementation, vendor, or product mapping; no root-cause reasoning.
- No cross-Domain first abnormal boundary selection (Orchestration owns it).

## Inputs

- `--ngap`: NGAP detailed event JSONL (repeatable), from the ngap Skill
  (>=0.3.0 mobility evidence).
- `--pfcp`: PFCP detailed event JSONL (repeatable; optional supporting N4).
- `--gtpu`: GTP-U detailed event JSONL (repeatable; optional supporting N3).
- `--sbi`: SBI-HTTP2 detailed event JSONL (repeatable; optional N11).
- `--pdu-session`: optional 5gc-pdu-session analysis summary JSON (>=0.4.0)
  for lifecycle-generation and N4/N3 binding context; never a mandatory
  runtime dependency; its deviations are never reinterpreted.

## Outputs

- `scripts/analyze_handover_mobility.py [INPUTS] --output analysis.json
  [--stage-output stages.jsonl] [--force]` — analysis summary JSON
  (`schemas/5gc-handover-mobility-analysis.schema.json`) and optional
  generic procedure-evidence stage JSONL.
- `scripts/mobility_timeline.py analysis.json [--format text|json]` —
  bounded mobility timeline; no mobility success or root-cause wording.

## Dependencies

Required: `[]` (standalone; consumes only already-generated evidence files).
Optional: `procedure-evidence >=0.1.0`, `ngap >=0.3.0`, `pfcp >=0.1.0`,
`gtpu >=0.1.0`, `sbi-http2 >=0.2.0`, `cross-protocol-evidence >=0.1.0`,
`5gc-pdu-session >=0.4.0`. Dependencies describe semantic contracts, not
runtime imports; no repository-sibling modules are imported. NAS evidence is
not consumed in this version.

## Workflow

1. Obtain already-extracted protocol event files from the Protocol Skills
   (and optionally the PDU Session Domain summary).
2. Run `analyze_handover_mobility.py` to form attempts, associate
   source/target contexts, evaluate branch-aware stages, and classify
   procedure-local deviations.
3. Read the attempt records: association strength and basis, stages,
   item-scoped `pdu_session_resources`, terminal observation, deviations,
   `earliest_observed_deviation`, and plane bindings.
4. Render `mobility_timeline.py` for the bounded timeline.
5. Treat every deviation as procedure-local protocol evidence; hand
   cross-Domain boundary selection and root-cause reasoning to authorized
   higher layers.

## Evidence Rules

- OBSERVED: NGAP message identities, PDU branches, Causes, HandoverType and
  TargetID metadata, resource roles, PFCP/GTP-U/SBI observations, and every
  value carried by the lower-layer events.
- DERIVED: attempt formation, source/target association, stage evaluation,
  missing-evidence statements, attempt identifiers, timeline ordering,
  neutral tunnel labels.
- INFERRED: only relationships strongly suggested but not directly proven
  (for example a Path Switch belonging to an in-progress observed handover);
  always carried with an explicit basis and strength.
- HYPOTHESIS / CONFIRMED: deliberately unused; this Skill does not confirm
  end-to-end mobility causes.

## Failure Handling

Malformed or missing evidence files fail loudly with non-zero exit codes
(malformed input 5, no events 6, output failure 7). Duplicate observations
are preserved as `DUPLICATE_OR_RETRANSMITTED_EVIDENCE`. Ambiguous
associations stay ambiguous with all candidates preserved; nothing is
silently dropped and no gap is filled with assumptions.

## Validation

Run `python tests/test_5gc_handover_mobility.py` from this package.
Repository checkouts also run `scripts/validate-5gc-handover-mobility.py`.

## References

- `references/procedure-model.md`: attempt families and stage vocabulary.
- `references/handover-model.md`: handover branches, terminal observations.
- `references/path-switch-model.md`: Path Switch attempts and independence.
- `references/source-target-association.md`: association rule and strengths.
- `references/pdu-session-resource-model.md`: item-scoped resource findings.
- `references/n11-n4-n3-evidence.md`: supporting-plane association rules.
- `references/deviation-model.md`: deviation vocabulary and provenance.
- `references/failure-cases.md`: bounded failure-case catalog.
