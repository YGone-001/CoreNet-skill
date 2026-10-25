# EPC Procedures

## Purpose

Answer HOW an observed EPS Attach procedure behaves at the procedure layer: which
UE contexts ran an Attach attempt, which conditional stages were observed, which
explicit protocol rejection or failure the network or the UE emitted, and which
evidence is missing or protected.

This is a Domain-layer Skill with four independently executable capabilities. The
EPS Attach capability consumes already-extracted S1AP and NAS-EPS events. The EPC
session-control capability consumes already-extracted GTPv2-C events and
transactions. The EPS default-bearer capability consumes already-extracted NAS-EPS
ESM evidence, S1AP E-RAB items and GTPv2-C tunnel endpoints. The S1-U observation
capability consumes already-extracted GTP-U events and stream summaries. Both produce procedure-local evidence and explicit limitations. The
Skill never decodes protocols, never reads subscriber identity, and never produces a
verdict about bearer, PDN or service success.

## Scope

Bounded EPS Attach signaling evidence model:

- Attach initiation (`Attach request`).
- Conditional identity procedure (`Identity request`/`Identity response`).
- Conditional EPS AKA authentication (`Authentication request`/`response`/`failure`/`reject`).
- Conditional NAS security mode control (`Security mode command`/`complete`/`reject`).
- Attach decision (`Attach accept`/`Attach reject`).
- Attach completion (`Attach complete`).
- Associated S1AP Initial Context Setup evidence (request/response/failure).
- Associated S1AP UE context release observations.
- Protected-envelope and partial-capture limitations.

## Non-Goals

- No Diameter, S6a, Gx or Gy signalling. Bounded GTPv2-C session-control
  evidence is provided by `scripts/analyze_epc_session.py`; full ESM decoding and
  the complete EPS bearer lifecycle remain out of scope.
- No S1-U user-plane validation.
- No success, failure or root-cause verdict, and no network-function blame.
- No global EPC first-abnormal-boundary selection. Per-subject selection belongs
  to the `epc-failure-boundary` Orchestration Skill; this Domain keeps its own
  `boundary_selection_status` at `NOT_EVALUATED`.
- No subscriber identity handling of any kind.
- No vendor or implementation-specific mapping.

## Inputs

| Input | Description |
| --- | --- |
| S1AP event JSONL | Detailed events from the `s1ap` Protocol Skill. |
| NAS-EPS event JSONL | Detailed events from the `nas-eps` Protocol Skill. |

Both inputs are validated for required provenance before analysis. A malformed event
fails loudly instead of being skipped.

## Outputs

| Output | Description |
| --- | --- |
| Analysis JSON | Procedure instances, stages, observations, deviations, limitations (`schemas/epc-attach-analysis.schema.json`). |
| Stage timeline JSONL | One row per procedure stage. |
| Text timeline | Protocol-local rendering of the same evidence. |

## Association Rules

A NAS-EPS event is bound to an S1AP UE context only when the same capture contains
exactly one S1AP message on the same frame that carries a NAS-PDU. A NAS event with
no such enclosing message is reported as unbound; a frame with several NAS-carrying
S1AP messages is reported as ambiguous. Timestamps are never used for binding.

A context observed before the MME allocates its identifier is extended to that
identifier only when exactly one MME-UE-S1AP-ID is observed for the same capture,
association and eNB identifier. Conflicting identifiers stay separate and are marked
ambiguous.

## Evidence and Deviations

Every deviation carries `deviation_type`, `procedure_stage`, `protocol`,
`message_type`, `frame_number`, `evidence_level`, `evidence_refs`,
`observation_window`, `explanation` and `limitations`.

An explicit `Attach reject` is reported as `ATTACH_REJECT_OBSERVED` with the observed
EMM cause. Authentication failure, authentication reject, security mode reject and S1
context setup failure are reported as procedure-local deviations. A protected
envelope is reported as `PROTECTED_INNER_MESSAGE_UNAVAILABLE`; the inner message is
unavailable, not absent. An attempt without a terminal decision is reported as
`INSUFFICIENT_TERMINAL_EVIDENCE`.

`global_boundary_evaluation` is always `NOT_EVALUATED` and
`global_first_abnormal_boundary` is always `null`.

## Session-Control Analysis

Version 0.2.0 adds a second, independently executable capability inside the same
Domain package: `scripts/analyze_epc_session.py`. It consumes the accepted
`gtpv2` Protocol Skill output (detailed events plus transaction correlation) and
reconstructs bounded EPC session-control subjects.

```bash
python3 scripts/analyze_epc_session.py \
  --gtpv2 gtpv2-events.jsonl \
  --transactions gtpv2-transactions.json \
  --output epc-session-analysis.json \
  --timeline-output epc-session-timeline.jsonl
```

It reports Create Session, Modify Bearer, Delete Session, Release Access Bearers
and Echo transactions with a correlation status and a protocol outcome kept
separate, message-scope and bearer-scope Cause kept separate, message-scope and
item-scoped F-TEID evidence, and EBI values bound to their bearer item when the
Protocol Skill proves the grouping.

An interface is published only from a non-zero control-plane F-TEID (types 10/11
for S11, 6/7 for S5/S8) or from control-plane TEID continuity with an earlier
transaction. A transport address never establishes one. Transactions are grouped
into a subject only when the resolved interface, the directed request endpoint
pair and at least one control-plane TEID agree; an accepted Delete Session closes
the generation, and later reuse of a closed TEID starts a new subject with an
explicit reuse deviation.

S11 and S5/S8 subjects stay separate, and every subject reports
`cross_interface_association` and `attach_association` as `NOT_ESTABLISHED`. The
capability publishes `not_confirmed` explicitly and keeps
`boundary_selection_status` at `NOT_EVALUATED`.

## Default-Bearer Analysis

Version 0.3.0 adds a third, independently executable capability:
`scripts/analyze_epc_default_bearer.py`. It consumes NAS-EPS events (with their
decoded ESM messages), S1AP events (with item-scoped E-RAB evidence), the EPS
Attach analysis, the EPC session-control analysis, and optionally GTPv2-C events
for exact S1-U tunnel endpoint identity only.

```bash
python3 scripts/analyze_epc_default_bearer.py \
  --nas nas-eps-events.jsonl \
  --s1ap s1ap-events.jsonl \
  --attach epc-attach-analysis.json \
  --session epc-session-analysis.json \
  --gtpv2 gtpv2-events.jsonl \
  --output epc-default-bearer-analysis.json \
  --timeline-output epc-default-bearer-timeline.jsonl
```

Only `--nas` is required. It reports six stages (`pdn-connectivity-request`,
`esm-information-exchange`, `default-bearer-activation-request`,
`default-bearer-activation-response`, `s1-erab-setup`,
`supporting-gtpv2-session-control`), each with one of `OBSERVED`, `NOT_OBSERVED`,
`UNAVAILABLE_PROTECTED`, `AMBIGUOUS` or `INSUFFICIENT_EVIDENCE`.

An ESM rejection becomes a typed, frame-anchored deviation carrying the reviewed
ESM cause code and name. A protected NAS message whose inner ESM cannot be read
produces `UNAVAILABLE_PROTECTED` and `PROTECTED_ESM_UNAVAILABLE`, never an absent
stage.

Identity links are classified `ESTABLISHED`, `SUPPORTED`, `AMBIGUOUS` or
`NOT_ESTABLISHED`. The only cross-interface tunnel basis is exact equality of the
S1-U transport layer address and GTP-TEID with a reviewed S1-U interface type, and
such a link is `SUPPORTED` rather than `ESTABLISHED` because an E-RAB identity is
never equated with an EPS bearer identity. S11 to S5/S8 and Attach to session
links stay `NOT_ESTABLISHED`.

A link publishes the interface type that the matching GTPv2-C F-TEID actually
carried (`supporting_identifiers` -> `f_teid_interface_type`), never the type its
role expects: type 1 for an `sgw_s1u` endpoint and type 0 for an `enodeb_s1u`
endpoint are documented as `expected_interface_type`, and a link with no matching
record publishes no observed type at all. The top-level
`gtpv2_supporting_evidence` inventory keeps both reviewed S1-U interface types, so
a downlink relationship never contradicts the evidence inventory it cites.

The capability publishes `not_confirmed` explicitly and keeps
`boundary_selection_status` at `NOT_EVALUATED`. See `references/default-bearer.md`
and `references/identity-linking.md`.

## S1-U Observation

Version 0.4.0 adds a fourth, independently executable capability:
`scripts/analyze_epc_s1u.py`. It consumes the accepted GTP-U events and directed
stream summary plus, optionally, the EPS default-bearer analysis and the GTPv2-C
events that advertise the SGW-U S1-U endpoint.

```bash
python3 scripts/analyze_epc_s1u.py \
  --gtpu gtpu-events.jsonl \
  --streams gtpu-streams.json \
  --default-bearer epc-default-bearer-analysis.json \
  --gtpv2 gtpv2-events.jsonl \
  --output epc-s1u-observation.json
```

Only `--gtpu` and `--streams` are required. A stream is related to a bearer only
when its outer destination address and header TEID equal an advertised S1-U
receiving endpoint inside the same capture; an outer source address, a UDP port or
a TEID value alone never establishes ownership. The association is `SUPPORTED`,
`AMBIGUOUS` or `NOT_ESTABLISHED`, and unbound streams stay observable.

The capability reports observed G-PDU counts and bounded payload-octet counts with
their documented definition. Every protocol reference names the message actually
observed in that frame, taken from the frame-anchored GTP-U event, so an Echo
Request, Echo Response, Error Indication or End Marker frame is never published as
a G-PDU; when no event is available the message identity stays null. It never
claims UE delivery, bearer service success,
application reachability or packet loss, never republishes inner packet content,
and keeps `boundary_selection_status` at `NOT_APPLICABLE`. See
`references/s1u-observation.md`.

## Failure Behavior

| Condition | Behavior |
| --- | --- |
| Missing or malformed input file | Exit 5 with the offending file and line. |
| Event missing required provenance | Exit 5 naming the field. |
| No Attach procedure instance formed | Exit 6; the analysis JSON is still written. |
| Output exists without `--force` | Exit 7; the existing file is left intact. |

## Standalone Usage

```bash
python3 scripts/analyze_epc_attach.py \
  --s1ap s1ap-events.jsonl --nas nas-eps-events.jsonl \
  --output epc-attach-analysis.json --stage-output epc-attach-stages.jsonl

python3 scripts/epc_attach_timeline.py epc-attach-analysis.json --format text
```

The package copies and runs outside the main repository; it has no external
dependency beyond the Python standard library.

## Testing

```bash
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

## Provenance

Original CoreNet Domain-layer package. No upstream material imported. Normative
references are 3GPP TS 23.401, TS 24.301 and TS 36.413, consumed through the accepted
`s1ap`, `nas-eps`, `gtpv2` and `gtpu` Protocol Skill contracts. Version 0.4.0.
