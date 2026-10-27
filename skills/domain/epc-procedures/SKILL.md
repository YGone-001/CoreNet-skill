# EPC Procedures

## Purpose

Answer HOW an observed EPS Attach procedure behaves at the procedure layer: which
UE contexts ran an Attach attempt, which conditional stages were observed, which
explicit protocol rejection or failure the network or the UE emitted, and which
evidence is missing or protected.

This is a Domain-layer Skill with seven independently executable capabilities. The
EPS Attach capability consumes already-extracted S1AP and NAS-EPS events. The EPC
session-control capability consumes already-extracted GTPv2-C events and
transactions. The EPS default-bearer capability consumes already-extracted NAS-EPS
ESM evidence, S1AP E-RAB items and GTPv2-C tunnel endpoints. The S1-U observation
capability consumes already-extracted GTP-U events and stream summaries. The
session-identity, bearer-lifecycle and release-narrative capabilities consume the
accepted documents those capabilities publish, never a capture. Each produces
procedure-local evidence and explicit limitations. The Skill never decodes
protocols, never reads subscriber identity, and never produces a verdict about
bearer, PDN or service success.

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

## Bearer Lifecycle

Version 0.5.0 adds a fifth, independently executable capability:
`scripts/analyze_epc_bearer_lifecycle.py`. It consumes the GTPv2-C detailed events
and their accepted transaction correlation plus, optionally, the accepted EPC
session-control, default-bearer and S1-U observation documents and the detailed
GTP-U events.

```bash
python3 scripts/analyze_epc_bearer_lifecycle.py \
  --gtpv2 gtpv2-events.jsonl \
  --transactions gtpv2-transactions.json \
  --session epc-session-analysis.json \
  --default-bearer epc-default-bearer-analysis.json \
  --s1u epc-s1u-observation.json \
  --gtpu gtpu-events.jsonl \
  --output epc-bearer-lifecycle-analysis.json \
  --timeline-output epc-bearer-lifecycle-timeline.jsonl
```

Only `--gtpv2` and `--transactions` are required; a partial input set produces
bounded, explicit limitations instead of a silent result. The capability answers
three separate questions and never collapses them:

* **Advertisement family** — repeated S1-U F-TEID advertisements are consolidated
  only when they are members of one accepted `MATCHED` transaction with a
  corroborated correlation strength whose request and response advertise the same
  endpoint under one item-scoped bearer identity, with no negative Cause and with
  the Cause read from the bearer context of the same EBI. A family keeps every source frame and is never a new
  allocation. `OPEN_REQUEST`, `RESPONSE_ONLY` and `AMBIGUOUS` transactions, weak
  correlation, conflicting bearer identities and competing allocations never
  consolidate.
* **Generation** — a generation is scoped by capture, receiving role, endpoint
  address, endpoint TEID, reviewed interface type and its first accepted
  advertisement frame, and is labelled `epc-bearer-generation-<hash>`. It closes
  only when one release transaction is `MATCHED`, carries a corroborated
  correlation strength, has exactly one correlated response with a message-scope
  accepted Cause, belongs to the same capture, names the released endpoint **and**
  names the same control-plane context as the allocation. Endpoint equality alone
  never closes a generation. In the accepted real capture every Delete Session
  request carries no S1-U F-TEID, so every generation stays
  `OPEN_AT_CAPTURE_END` with `RELEASE_STATUS_UNRESOLVED`. Repeated Modify Bearer
  evidence updates one generation and never fabricates a new one, and a numerically
  reused TEID is never a new generation without a proved boundary.
* **Release timing** — a boundary publishes `release_request_frame` (initiation),
  `release_confirmation_frame` (the correlated accepted response) and
  `release_effective_frame_proven: false`. Packets between the two belong to
  neither generation and stay `GENERATION_UNRESOLVED` with basis
  `release_in_progress_interval`.
* **Correlation strength** — only `STRONG` and `SUPPORTED` may carry a proof;
  `NONE`, a missing value and an unreviewed value are never sufficient. The
  advertisement-family and release rules use the same reviewed set.
* **Message Cause** — the outcome is read only from the accepted contract field
  `message_cause` with `scope: message` on the correlated response. A bearer-scope
  Cause, a request-side Cause, a Cause from another transaction and a missing field
  never establish an accepted release.
* **Capture-scoped identity** — evidence is identified by capture, frame and
  message occurrence, never by frame number alone. A transaction is bound only when
  the observed messages resolve to exactly one capture; a colliding frame number in
  another capture leaves the transaction unbound (`INSUFFICIENT_CAPTURE_PROVENANCE`)
  and never transfers a Cause, a control-plane context or a generation split.
* **Packet attribution** — G-PDUs are attributed from frame-level events inside a
  proved generation window. The accounting invariant is published and checked:
  aggregate G-PDU and payload octets equal the attributed plus the unresolved
  counts. Packets are never split proportionally, never assigned by stream
  proximity, and never moved to the earliest generation of a reused endpoint.
  Unresolved packets stay visible as `GENERATION_UNRESOLVED` and are neither
  packet loss nor a tunnel failure.

A lifecycle generation boundary is not an abnormal failure boundary: the
capability keeps `boundary_selection_status` at `NOT_APPLICABLE` and never selects
a first abnormal boundary. See `references/bearer-lifecycle.md` and
`references/advertisement-family.md`.

The lifecycle accepts one optional additional input, an accepted session-identity
analysis (`--session-identity`): when its release binding, session-to-generation
link and closure candidate are all `ESTABLISHED` for the same capture, a release
that names no S1-U endpoint may close a generation through the reviewed
session-context path with basis
`accepted_release_response_bound_by_reviewed_session_context`. Without that input,
in the accepted real capture every Delete Session request carries no S1-U F-TEID,
so every generation stays `OPEN_AT_CAPTURE_END` with `RELEASE_STATUS_UNRESOLVED`.

## Session Identity Bridge

Version 0.6.0 adds a sixth, independently executable capability:
`scripts/analyze_epc_session_identity.py`. It consumes the GTPv2-C detailed events
and their accepted transaction correlation plus, optionally, the accepted
session-control, default-bearer and bearer-lifecycle documents, and publishes
three strictly separated kinds of relationship:

* **Hop-local session context** — transactions of one hop (S11 or S5/S8) join a
  context only through receiver-side addressing: the request header TEID and
  destination address must equal one hop-local control-plane F-TEID published
  inside the context, and the request source address must equal a hop-local
  F-TEID address of the same context (the GTP-C path peer). Equal TEID, EBI or
  sequence values never join by themselves; a relayed F-TEID of a foreign
  interface type and a TEID-0 address hint are never join keys; competing
  candidates stay `AMBIGUOUS` and are never tie-broken.
* **Cross-interface evidence** — a relayed PGW S5/S8 GTP-C F-TEID that is equal
  and unique across the two Create Session responses of one capture establishes
  `CROSS_INTERFACE_SESSION_IDENTITY` (`ESTABLISHED`); an equal bearer-scope
  user-plane F-TEID establishes only `CROSS_INTERFACE_ENDPOINT_CORRESPONDENCE`
  (at most `SUPPORTED`) and is never displayed as session identity.
* **Release binding** — a Delete Session transaction binds to the one context its
  request addresses; the release outcome is classified from the correlated
  response only and is published beside the binding, never merged into it. A
  generation-closure candidate additionally requires an established
  session-to-bearer-endpoint relationship per receiving role; the candidate is a
  reviewed input for the lifecycle capability and never closes a generation by
  itself. Correlation, context identification, endpoint advertisement, allocation
  acceptance, bearer association, release outcome and generation closure are
  separate classification layers: a hop-local context is established only when its
  correlated allocation response carries an accepted message-scope Cause, a
  rejected or unresolved grouped bearer item blocks its endpoint's bearer
  association, one endpoint carrying two distinct assigned item-scoped bearer
  identities stays ambiguous, and the lifecycle refuses session-context closure
  entirely when the identity analysis publishes fewer records than its own counts
  (`SOURCE_CANDIDATES_TRUNCATED`). A readable item-scoped EBI is not an assigned
  bearer identity: zero is the explicit "no EPS bearer identity assigned" code
  (TS 24.007 sec 11.2.3.1.5, TS 24.301 sec 9.3.2, TS 29.274 sec 8.8) and a value
  outside the four-bit encoded domain is no identity, so neither establishes a
  bearer association, a closure candidate or a generation, and an endpoint mixing
  assigned with unassigned evidence fails closed rather than discarding the
  conflict.

See `references/session-identity-bridge.md` and `references/release-binding.md`.

## Release Narrative

Version 0.7.0 adds a seventh, independently executable capability:
`scripts/analyze_epc_release_narrative.py`. It consumes the accepted
session-identity and bearer-lifecycle documents plus, optionally, the accepted
S1-U observation, the detailed GTPv2-C events and the detailed GTP-U events, and
publishes a deterministic release narrative per reviewed hop-local session
context.

It answers, per release: which allocation and bearer relationships were actually
established, which Delete Session Request was observed and which response
confirmed it, whether the release bound to a session context, which bearer
generations were independently proved closed, and what user-plane traffic was
observed before, inside and after the release window.

Three facts are never collapsed:

```text
release_outcome_status         ACCEPTED | REJECTED_OBSERVED | UNRESOLVED
release_session_binding_status ESTABLISHED | NOT_ESTABLISHED | AMBIGUOUS | INSUFFICIENT_EVIDENCE
generation_closure_status      ESTABLISHED | NOT_ESTABLISHED | AMBIGUOUS
```

A hop-local context is never merged into a global PDN session: two contexts join
one narrative group only through an already `ESTABLISHED`
`CROSS_INTERFACE_SESSION_IDENTITY` link in the same capture, and the group is a
reporting label with the source context references preserved. A generation enters
the narrative only when the whole closure chain holds: an `ESTABLISHED`
release-to-session binding, a lifecycle boundary naming the same release
transaction, an `ESTABLISHED` closure candidate for the same context, release and
bearer endpoint, an `ESTABLISHED` session-to-generation link to that candidate's
bearer endpoint, and an affirmatively complete closure-critical candidate set.

Temporal evidence is frame-aware and conservative. Capture identity is part of the
endpoint identity, so a stream observed in one capture is never attributed to a
generation proved in another. A stream is attributed to a generation only when the
S1-U analysis accepts its association and the lifecycle publishes a
generation-scoped S1-U observation naming exactly that generation and stream;
endpoint equality alone never establishes ownership. The pending-release interval
is an observation window, the confirmation frame is never the forwarding-stop
instant, and an aggregate stream count is never divided across windows: without
frame-level GTP-U events the observation publishes
`TEMPORAL_PLACEMENT_NOT_ESTABLISHED`. A complete placement is only asserted when
the observed frames reproduce the accepted aggregate count and payload octets; an
unreconciled or doubly-claimed frame set keeps its observed subset and fails
closed. A G-PDU frame is counted in at most one partition of one narrative.

`release_effective_frame_proven` is always `false`, `boundary_selection_status` is
`NOT_APPLICABLE` and `first_abnormal_boundary` is `null`: a release narrative is
not an abnormal failure boundary and never produces a root cause.

See `references/release-narrative.md` and `references/release-temporal-evidence.md`.

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
`s1ap`, `nas-eps`, `gtpv2` and `gtpu` Protocol Skill contracts. Version 0.7.0.
