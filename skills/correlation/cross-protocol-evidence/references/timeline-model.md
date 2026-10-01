# Timeline Model

The unified timeline is an Observed Evidence Timeline: a deterministic
rendering of correlation groups that shows what was observed together,
in what order, and which protocol source is missing. It is not a
verdict.

## Input

Correlation-event JSONL produced by `correlate-events.py`. The timeline
renderer reads only groups; it never reads captures or raw protocol
artifacts.

## Text rendering

Each group renders as a header plus its embedded events, then a missing
evidence note when a protocol source is absent:

    capture=join-capture.pcapng frame=10 [STRONG] sources=NAS-5GS+NGAP
      frame=10 2024-01-02T03:04:10.000000Z NAS-5GS: Registration request
      frame=10 2024-01-02T03:04:10.000000Z NGAP: InitialUEMessage
    capture=join-capture.pcapng frame=30 [WEAK] sources=NGAP
      frame=30 2024-01-02T03:04:30.000000Z NGAP: InitialContextSetupRequest
      missing evidence in this group: NAS-5GS

Event labels come from the producing Skills' own identity fields
(message_type, then procedure_name, then support_status); this layer
invents no labels of its own.

## JSON rendering

The JSON form keeps the same information in a structured shape: group
header fields, `protocol_sources`, `correlation_strength`,
`missing_protocol_sources` (the expected sources absent from the group),
and per-event summary entries. No root_cause, status, success, or
failure field exists at any level.

## Ordering rules

Groups render in the deterministic order produced by the correlator
(capture, first frame, strength, first timestamp). Events render in
frame-then-timestamp order inside each group. Input timestamp values
are displayed verbatim; conflicting or out-of-order input timestamps
are preserved so uncertainty stays visible rather than corrected away.

## Verdict capability

None. The timeline does not output REGISTRATION SUCCESS, REGISTRATION
FAILURE, or any root-cause statement. Missing protocol sources are
reported as missing evidence under the capture boundary — absence from
the input events is not absence from the network. Interpreting the
timeline into procedure outcomes belongs to future Domain Skills.
