# Correlation Skills

Implemented: `cross-protocol-evidence`, a Correlation-layer package that
joins already-extracted NGAP and NAS-5GS detailed events into
deterministic evidence groups and a unified observed-evidence timeline
by shared capture provenance (capture_file plus frame_number), with
bounded timestamp-window MEDIUM joins and non-merging WEAK singletons.
It preserves embedded protocol events verbatim as foreign metadata,
reports missing protocol sources as missing evidence, and never
determines registration success, failure, or root cause.

Planned: none. Correlation-layer work beyond provenance-key joins,
bounded time ordering, and timeline rendering — such as procedure-level
evidence combination — belongs to future Domain Skills, which this layer
deliberately does not pre-empt.
