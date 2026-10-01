# Capture Model

A capture is primary evidence only for the observation point, direction,
interface, filter, time range, and packet bytes represented by that artifact.
The normalized event boundary is one frame plus directly reported metadata:
frame identity, timestamp, endpoint metadata, transport, dissector stack, and
capture provenance.

The extractor keeps the authoritative event contract unchanged. Frame number
and a safe capture basename are recorded in `packet`; the capture artifact and
reported tshark stack are retained in `evidence.source`. Timestamp conversion is
a deterministic UTC derivation from `frame.time_epoch` and rounds to
microseconds using half-even rounding.

Capture limitations are not root causes. A packet not visible in one capture
can reflect capture point, direction, interface, snap length, encryption,
offload, capture loss, filter, or selected time range.
