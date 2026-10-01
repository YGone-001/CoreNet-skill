# Provenance

Provenance is the only thing this layer joins on. Every rule traces back
to where an observation was extracted from.

## Primary provenance key

    capture_file + frame_number

This is the strongest cross-protocol join: the NGAP Skill and the
NAS-5GS Skill both stamp their detailed events with the capture basename
and frame number, so identical values mean both Skills observed the same
captured frame. A group formed on this key is STRONG.

`capture_file` is the safe basename recorded by the producing Skills;
workstation paths never enter the pipeline.

## Secondary ordering

Timestamps order events inside groups and drive the bounded MEDIUM
window. Ordering is DERIVED: out-of-order or conflicting input
timestamps are preserved as-is and never corrected, because rewriting a
timestamp would fabricate evidence.

## Preserved context

- SCTP metadata inside embedded NGAP events (association, stream,
  ports) is preserved verbatim as foreign metadata; it may add context
  but is never used as a join key in this layer.
- Embedded NAS security-envelope fields are preserved verbatim; this
  layer does not interpret them.

## Prohibited correlations

This layer does not create:

- subscriber correlation (no SUCI/SUPI/IMSI/MSISDN joining);
- session correlation (no PDU session, DNN, or QFI joining);
- registration correlation (no procedure state, no request/response
  engine);
- cross-capture identifier merging (equal numeric identifiers in
  different captures mean nothing here).

Future Domain Skills may combine this layer's provenance-joined output
with protocol context; the correlation key model itself stays frozen to
provenance and bounded time.

## Evidence labeling

Events embedded in a group are OBSERVED evidence from their producing
Skills. The group record itself — its membership, ordering, strength,
and missing-source notes — is DERIVED, and `evidence.basis` states the
exact rule that formed the group.
