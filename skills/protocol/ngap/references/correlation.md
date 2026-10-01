# NGAP Correlation Model

Protocol-local correlation of NGAP frames into UE contexts. Deterministic,
evidence-safe, and scoped: the strongest available identifier wins, and
weaker evidence never silently merges contexts.

## Context scope

A correlation context is scoped by:

1. capture identity (safe capture basename plus frame provenance), and
2. SCTP association context as exposed by the dissector:
   `sctp.assoc_index` when present, otherwise the observed endpoint pair
   (address:port, order-normalized).

Numeric RAN-UE-NGAP-ID or AMF-UE-NGAP-ID equality across captures or
across associations is meaningless on its own and never merges contexts.
The same numeric ID can legitimately exist in parallel associations, and
tshark association indexes are session-local ordinals, not protocol
identifiers.

## Derived context key

Context keys are built as:

    ngap-context:<capture-file>:<sctp-assoc-N|endpoint-pair-...>:r<ran-id|?>:a<amf-id|?>

The key is explicitly DERIVED, documented here, and not a standardized
NGAP identifier. It never enters any field whose semantics would claim the
key was observed on the wire; the shared trace projection carries only
observed SCTP stream identifiers in `correlation.stream_id`.

## Binding derivation

A binding RAN-UE-NGAP-ID <-> AMF-UE-NGAP-ID is derived only from a frame
where both identifiers are observed together, within one association.
Bindings are per (association, RAN ID) pairs, so several UE contexts can
share one SCTP association. The first observation wins; a later frame that
contradicts a derived binding is recorded as a conflict with the first
binding retained, and the conflicting observation is preserved verbatim —
never overwritten.

A binding is DERIVED evidence and always carries the frame number that
established it. Frames before the binding keep their own observed-ID set;
nothing retroactively claims an identifier was observed in an earlier
frame.

## Correlation strength

- STRONG — both RAN-UE-NGAP-ID and AMF-UE-NGAP-ID are observed in that
  frame, inside one association context.
- MEDIUM — one identifier is observed in the frame and the other is
  supplied by an already-derived binding of the same association. The
  supplied identifier is always reported in a `derived_*` field and the
  binding frame remains visible. A MEDIUM label does not claim the derived
  identifier appeared in that frame.
- SINGLE-ID — one identifier observed, no derived binding for it yet. The
  event forms a provisional context that stays separate until (and unless)
  a both-ID frame derives a binding. Provisional contexts are reported,
  never dropped and never merged.

Weak evidence — timestamp or endpoint proximity alone — is not used to
merge UE contexts. Non-UE-associated messages (no UE NGAP IDs, for example
Paging) are listed separately and never attached to a UE context.

## Conflicts and capture windows

Conflicts are DERIVED findings listing: the contradicting frame, the pair
observed in it, the existing binding, and the resolution
(first-binding-retained). A conflict is a protocol-local anomaly signal,
not a root cause.

An expected protocol-local outcome can be missing simply because the
capture window ends, a filter dropped frames, or signaling left the
observed point. "Outcome not observed" never becomes "network did not send
the outcome"; see `failure-cases.md`.
