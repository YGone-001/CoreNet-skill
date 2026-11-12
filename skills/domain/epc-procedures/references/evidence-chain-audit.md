# EPC Cross-Artifact Evidence Chain Audit

## Purpose

The evidence audit answers a question the evidence producers deliberately do not
answer: **does the published EPC evidence chain resolve, agree with itself, and
rest on a complete candidate set?**

It reads the accepted artifacts only. It never decodes a capture, never rebuilds a
transaction correlation, never re-derives a session identity, never recomputes a
bearer generation, never changes a packet or octet attribution and never selects a
first abnormal boundary. A source claim that cannot be validated stays visible in
its original artifact; the audit publishes a limitation or a finding beside it and
never rewrites it.

The ledger is therefore an **audit of proof**, not a new source of proof.
Reference consistency is a necessary condition; it is not a replacement for the
accepted protocol and domain evidence gates.

## Audited Artifacts

| Artifact | Role | Required |
| --- | --- | --- |
| `epc-session-identity` | hop-local contexts, identity links, release bindings, session-to-generation links, closure candidates | yes |
| `epc-bearer-lifecycle` | generations, proved boundaries, generation-scoped S1-U observations, accounting | yes |
| `epc-release-narrative` | narrative subjects, release narratives, temporal observations | yes |
| `epc-s1u-observation` | directed stream evidence and published totals | optional |
| detailed GTPv2-C events | re-observe release request and confirmation anchors | optional |
| detailed GTP-U events | re-observe frame-level temporal evidence | optional |

All inputs are consumed read-only. The standalone CLI refuses an output path that
resolves to an input path, and it refuses to overwrite an existing output without
`--force`.

## Three Audit Dimensions

The ledger never collapses the dimensions into one Boolean.

| Dimension | Question | Example |
| --- | --- | --- |
| Presence | Does the referenced record exist in the supplied artifact? | a narrative names a stream reference the S1-U document does not publish |
| Consistency | Does the referenced record agree with the referring record? | the lifecycle boundary and the identity binding publish different frames for one release |
| Proof sufficiency | Is the complete candidate set available? | the binding collection declares more records than it publishes |

A record can therefore be present and consistent while the proof remains
insufficient:

```text
Reference present:                          YES
Capture consistent:                         YES
Candidate collection complete:              NO
Established uniqueness independently audit: NO
```

Reference integrity and relationship proof are separate dimensions.
`REFERENCE_INTEGRITY` may report that a reference resolves while the relationship
stays unproved. A session-to-generation or cross-interface identity relationship is
proved only when the producer publishes `association_status = ESTABLISHED`, the
link namespace, capture, source context and target endpoint agree, the link is
unique, and both the candidate and link collections are complete. A resolvable
reference with `NOT_ESTABLISHED`, `AMBIGUOUS`, a missing status or duplicate link
records is reference-consistent but proof-insufficient.

## Audit Categories

| Category | Audited relationship |
| --- | --- |
| `SOURCE_ARTIFACT` | supplied artifact identity, expected analysis name, domain and per-collection completeness |
| `REFERENCE_INTEGRITY` | resolution of every published cross-artifact reference inside its namespace |
| `CAPTURE_SCOPE` | capture identity of every artifact, and value collisions that must not become relationships |
| `TRANSACTION_ANCHOR` | release transaction membership and frame anchors |
| `SESSION_CONTEXT_LINK` | narrative subject, release binding and hop-local context agreement |
| `CROSS_INTERFACE_BRIDGE` | narrative group membership backed by an established identity link |
| `RELEASE_SESSION_BINDING` | binding status, target context and release outcome |
| `SESSION_GENERATION_LINK` | context-to-bearer-endpoint chain |
| `GENERATION_CLOSURE` | release transaction, closed lifecycle subject and unique candidate |
| `GENERATION_STREAM_ATTRIBUTION` | generation-scoped S1-U ownership record |
| `RELEASE_NARRATIVE_STAGE` | reporting stages against the published summary |
| `TEMPORAL_FRAME_PARTITION` | partition conservation, window boundaries, frame exclusivity and frame presence |
| `ACCOUNTING_CONSERVATION` | producer conservation identities and audit-derived totals |

## Audit Status Semantics

| Status | Meaning |
| --- | --- |
| `VERIFIED_CONSISTENT` | the reference resolves, the records agree and the proof is sufficient |
| `INCONSISTENT` | a visible contradiction exists, or a published claim is unsupported by the visible chain |
| `AMBIGUOUS` | competing or unresolvable references make a unique resolution impossible |
| `SOURCE_TRUNCATED` | the collection publishes fewer records than its own declared count |
| `SOURCE_METADATA_INVALID` | the count is missing, invalid, underdeclared or the omitted count is nonzero |
| `NOT_INDEPENDENTLY_VERIFIABLE` | the producer did not expose enough information, or an optional artifact was not supplied |
| `NOT_APPLICABLE` | there is no relationship of this kind to audit |

`VERIFIED_CONSISTENT` is never a synonym for an independently proved bearer
identity, packet delivery, network correctness or forwarding-stop instant. It means
only that the audited references resolve and agree.

An inconsistent or truncated finding does not invalidate the source document. A
release that has no proved generation closure may still have a valid accepted
control-plane outcome, and the audit reports both facts separately.

## Reference Namespaces and Capture Scoping

Capture identity is part of every reference. The audit resolves:

* hop-local session contexts by `capture + session_context_reference`;
* release transactions by `capture + transaction reference`;
* bearer endpoints by `capture + role + address + TEID + reviewed interface type`,
  recomputing the published deterministic bearer-endpoint reference;
* bearer generations by `capture + generation_reference`;
* S1-U streams by `capture + stream_reference`;
* closure candidates by `capture + candidate reference`, plus the context, release
  and bearer endpoint they name;
* narrative subjects, release narratives and temporal observations by
  `capture + reference`.

The audit never joins records on an equal TEID, an equal EPS bearer identity, an
equal IP address, timestamp proximity, adjacent frame numbers or endpoint
correspondence alone. A value collision in another capture is published as a
`CAPTURE_SCOPE` record and is not turned into a relationship. A frame number from
another capture is never substituted for a missing event.

An endpoint correspondence link and a cross-interface identity link are different
relationship types. The audit verifies that an endpoint correspondence is never
used as a narrative group bridge.

## Source Completeness

At minimum the audit assesses:

* session-identity hop-local contexts, identity links, endpoint correspondence
  links, release bindings, session-to-generation links and closure candidates;
* lifecycle subjects, advertisement families, generation boundaries,
  generation-scoped S1-U observations and unresolved packet observations;
* narrative subjects, release narratives and temporal observations;
* S1-U stream observations, when supplied.

Each entry publishes `declared_count`, `published_count`, `omitted_count`, a
completeness `status` and a `condition` token that distinguishes a missing count, an
invalid count, an underdeclared count, a truncated collection, a nonzero omitted
count and an unsupplied document. No omitted count is invented for a collection
whose producer publishes none.

A complete-looking visible subset never establishes uniqueness when the source
declares more candidates than it publishes. An absent optional artifact is a
coverage limitation, not an internally inconsistent artifact.

## Release Chain

The audit walks the accepted chain without recomputing its conclusions:

```text
hop-local context
  -> release-to-session binding
  -> session-to-generation link
  -> generation-closure candidate
  -> lifecycle generation boundary
  -> release narrative closure claim
```

For every edge it resolves the reference, confirms the capture, compares the
relationship status, compares the endpoint identity where the contract requires it,
compares the release transaction identity, checks the candidate completeness and
publishes a consistency status or an explicit uncertainty.

An accepted Delete Session Response is never sufficient by itself to prove a
bearer-generation closure. A closure candidate that names another release
transaction never justifies this release's closure. Uniqueness is evaluated per
reviewed bearer-generation endpoint, not per release transaction, so one accepted
release may independently close several proved generations. Competing candidates
for one endpoint stay ambiguous, and that ambiguity never demotes a generation that
is independently proved at another endpoint. A session-to-generation link is proved
only by an explicitly `ESTABLISHED` record; the mere presence of a link record or a
matching target reference hash is never sufficient.

## Scoped S1-U Attribution

The audit preserves the accepted generation-scoped attribution gates. It does not
introduce another matching algorithm. It verifies that the narrative's published
attribution is backed by:

* exactly one lifecycle generation-scoped record for the capture, generation and
  stream;
* a receiving role equal to both the generation role and the reviewed stream role;
* a direction mapping to that role and agreeing with the accepted stream direction;
* no unresolved generation claim competing for the same stream reference;
* no second generation claiming the same stream;
* a provably complete generation-scoped collection.

Refusal reasons are first-class evidence. When the evidence contradicts itself, the
audit reports the contradiction even if the narrative correctly refused to
attribute the stream, and the published refusal stays untouched.

## Temporal and Accounting Audit

Release windows are inspected only inside one capture. The audit distinguishes
before-release, pending-release and after-confirmation frames, a missing request or
confirmation anchor, aggregate-only evidence, an observed frame-level subset, a
complete conserved partition and conflicting duplicate frame ownership.

For a complete placement it verifies that the partition counts sum to the published
frame-level total, that the payload octets reconcile, that no G-PDU frame belongs to
two exclusive partitions, that every claimed frame is present when detailed GTP-U
events are supplied and that each partition stays inside its release boundaries.
For a valid observed subset it requires the accepted
`TEMPORAL_PLACEMENT_NOT_ESTABLISHED` / `OBSERVED_SUBSET` /
`FRAME_LEVEL_EVENTS_INCOMPLETE` / non-conserved combination, verifies that the
subset totals do not exceed the aggregate, keeps every frame inside its release
window, and publishes insufficient proof for the complete stream. When detailed
GTP-U events are supplied, it independently re-derives each partition from the
events for the same capture, directed S1-U stream, receiving endpoint and release
window, and compares the published count, payload octets, first frame and last
frame. A claimed frame number in another capture, or an equal TEID on another
directed stream, never satisfies the reconciliation. When detailed evidence is
absent, the producer-published subset is preserved and independent verification is
reported unavailable rather than fabricated as an inconsistency.
The bounded subset is observed evidence, never corruption. A contradictory
complete-stream or conserved claim, a subset exceeding the aggregate, a frame
outside its window, mismatched partition totals or duplicate frame ownership stays
`INCONSISTENT`. A duplicate frame-ownership conflict is scoped to the temporal
observations that actually claim the conflicting frame: it is never applied to an
unrelated stream or capture, and an equal TEID on a distinct directed stream never
merges ownership.
It never interpolates a missing frame, never divides an aggregate stream count and
never treats the confirmation frame as the forwarding-stop instant.

Accounting checks preserve the producer counts. The audit re-states the accepted
invariants:

```text
aggregate G-PDUs       = attributed + unresolved
aggregate payload      = attributed + unresolved
observed temporal      = assigned + unassigned + duplicate assignments
```

Any audit-derived total is labelled `audit-derived` and is never written back into a
producer count. A stream is never double-counted because it belongs to a
cross-interface narrative group. Source collection completeness, Audit Ledger
completeness and Review Pack display completeness are independent: a nonzero
`audit_records_omitted`, inconsistent `audit_record_count` metadata, a false or
missing `exhaustive_coverage_proven` flag, and a bounded review display are each
disclosed separately. A visible subset never implies exhaustive audit coverage. `partition_duplicate_assignment_count` counts
distinct capture-scoped frame identities claimed by more than one established
temporal observation, and `conflicted_partition_count` counts the observations that
actually claim those frames. Both derive from structured conflict evidence, never
from limitation-text counts. Equal textual observation references in different
captures remain isolated claimants and never inherit another capture's conflict.

## Determinism and Privacy

Repeated identical inputs produce byte-identical JSON and text. No wall-clock
timestamp is published. Capture labels are reduced to a basename-like label and
arbitrary source free text is never copied into the ledger. No IMSI, MSISDN, IMEI,
subscriber identifier, APN name, assigned PDN address, inner UE address or
user-plane payload is read or published.

The ledger always publishes:

```text
boundary_selection_status = NOT_APPLICABLE
first_abnormal_boundary   = null
```

An audit finding is not a network failure. A failed audit is not by itself proof of
a failed EPC procedure.