# Release Narrative

Contract for the bounded EPC session-level release narrative
(`analyze_epc_release_narrative.py`). Normative sections are cited in
`rules/epc-release-narrative-model.json`; the reviewed section numbering follows
the repository's accepted normative references, and no version-specific behaviour
beyond those sections is relied upon.

This capability consumes accepted artifacts only. It never decodes a capture,
never rebuilds a transaction correlation, never re-derives session identity and
never changes a packet or octet attribution.

## What the narrative answers

For each reviewed hop-local session context:

- which allocation transaction was observed and whether its outcome was accepted;
- which bearer relationships were actually established;
- which Delete Session Request was observed and which response confirmed it;
- whether the release bound to a session context;
- which bearer generations, if any, were independently proved closed;
- what user-plane traffic was observed around the release window;
- which conclusions remain unsupported.

It answers nothing about subscribers. A narrative subject is a control-plane
grouping, never a UE, a PDN connection or a subscriber.

## Three separate facts

The capability never collapses these into one verdict:

```text
release_outcome_status        ACCEPTED | REJECTED_OBSERVED | UNRESOLVED
release_session_binding_status ESTABLISHED | NOT_ESTABLISHED | AMBIGUOUS | INSUFFICIENT_EVIDENCE
generation_closure_status     ESTABLISHED | NOT_ESTABLISHED | AMBIGUOUS
```

An accepted release may coexist with an unproved binding, and an established
binding may coexist with an unproved generation closure. The real capture shows
both patterns at once: its five S11 releases prove two S1-U generations each,
while its five S5/S8 releases are accepted and bound but close no S1-U
generation, because the S5/S8 context advertises no S1-U endpoint.

`release_effective_frame_proven` is always `false`. The accepted model proves a
control-plane outcome and, at most, a reviewed bearer-generation boundary. It
never proves the instant at which user-plane forwarding stopped.

## Stage model

Thirteen reporting stages, of which the outcome, binding and closure stages are
mutually exclusive triples. A narrative therefore publishes nine stages:

```text
ALLOCATION_OBSERVED
ALLOCATION_ACCEPTED
SESSION_CONTEXT_ESTABLISHED
BEARER_ASSOCIATION_ESTABLISHED
RELEASE_REQUEST_OBSERVED
RELEASE_OUTCOME_{ACCEPTED|REJECTED_OBSERVED|UNRESOLVED}
RELEASE_SESSION_BINDING_{ESTABLISHED|NOT_ESTABLISHED}
GENERATION_CLOSURE_{ESTABLISHED|NOT_ESTABLISHED}
RELEASE_EFFECTIVE_INSTANT_UNPROVED
```

Every stage carries `evidence_status`, the source analysis, the source subject
reference, the transaction reference, the capture, an optional frame anchor and
message type, bounded evidence references, the association basis and its own
limitations. A stage with no available anchor publishes `null` rather than an
invented frame.

`evidence_status` is a closed vocabulary:

```text
OBSERVED  ACCEPTED  REJECTED_OBSERVED  UNRESOLVED
ESTABLISHED  NOT_ESTABLISHED  AMBIGUOUS  INSUFFICIENT_EVIDENCE  NOT_APPLICABLE
```

## Narrative subjects and groups

One subject per published hop-local context. Two contexts are placed in one
narrative group only when the accepted identity analysis publishes an
`ESTABLISHED` `CROSS_INTERFACE_SESSION_IDENTITY` link between them in the same
capture. The group reference is a deterministic hash of the capture and the
sorted member context references; the members and the bridge references stay
published beside it.

The group is a reporting label. It is never a global PDN session, and the source
context references are always preserved.

An endpoint correspondence is not a bridge. An equal TEID or EBI is not a bridge.
A missing bridge keeps the contexts separate, and competing bridges stay
`AMBIGUOUS`.

## Generation admission

A generation enters a narrative only when the whole closure chain holds:

1. the capture matches;
2. the release-to-session binding is `ESTABLISHED` for this capture and release;
3. a lifecycle subject carries a proved `generation_boundary` naming this release
   transaction;
4. the accepted identity analysis publishes an `ESTABLISHED` generation-closure
   candidate for the same session context and release transaction;
5. an `ESTABLISHED` session-to-generation link joins that context to the
   candidate's `bearer_endpoint_reference`;
6. the candidate's bearer endpoint equals the lifecycle subject's receiving
   endpoint in role, address, TEID and reviewed interface type;
7. the lifecycle subject's state is `CLOSED_BY_ACCEPTED_RELEASE`;
8. the release outcome is `ACCEPTED`;
9. every closure-critical source collection is provably complete.

A published `ESTABLISHED` candidate status is never sufficient on its own: the
narrative re-verifies the release binding and the session-to-generation link, so a
doctored or internally contradictory producer document cannot promote a closure.
Several candidates for one endpoint leave the closure `AMBIGUOUS` and publish the
competitors. A generation is never inferred from a repeated advertisement, an
equal S1-U TEID or an equal EBI.

## Candidate completeness

Before any exhaustive coverage is claimed, every material source collection is
checked: the declared count must be present, nonnegative, equal to the published
record array, and its omitted count present, valid and zero. A positive
truncation publishes `SOURCE_CANDIDATES_TRUNCATED`; every other missing, invalid,
underdeclared or nonzero-omitted metadata publishes
`SOURCE_CANDIDATES_METADATA_INVALID`. In both cases
`source_completeness.exhaustive_coverage_proven` is `false`, and no uniqueness is
inferred from the visible subset.

The lifecycle generation-scoped S1-U attribution collection is assessed the same
way, because it is the only accepted source of generation-level user-plane
ownership. Its incompleteness blocks temporal attribution, not the closure: the
two are separate evidence requirements and are never merged.

The closure-critical collections — release session bindings, session-to-generation
links, generation closure candidates and lifecycle subjects — are gated
individually, not only through the aggregate status. A unique bearer-generation
closure is a uniqueness claim about a candidate set, so it is only asserted when
the published subset provably *is* the whole set. While any of them is truncated or
its metadata is invalid:

```text
generation_closure_status  NOT_ESTABLISHED
proved_generations         []
release_outcome_status     unchanged, still the source-reported outcome
release_session_binding_status  unchanged, still the source-reported binding
```

A closure refusal never reclassifies the release outcome and never hides the
source-reported binding. The limitation names the incomplete collections.

## What the capability refuses

- A single `SUCCESS` or `FAILURE` verdict for a release.
- The release response as the forwarding-stop instant.
- An observed G-PDU as proof of UE receipt.
- An unresolved stream as packet loss or tunnel failure.
- A hop-local context merged into a global PDN session.
- A first abnormal boundary, root cause or network-function blame.

See `release-temporal-evidence.md` for the temporal contract and
`release-binding.md` for the accepted release-to-generation chain.
