# Correlation Boundaries

This package may preserve same-frame identity, endpoint pairs, temporal order,
and TCP or UDP stream identifiers only when tshark directly exposes them.
Values remain opaque and source-scoped through packet provenance and evidence
source.

It must not equate values from unrelated protocols merely because they match,
infer subscriber identity from timing, derive PFCP session identity from NGAP,
or derive an IMS dialog from RTP timing. Cross-protocol procedure correlation is
deferred to future Protocol and Domain Skills.
