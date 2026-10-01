# Failure Boundaries

Patterns this layer reports, and the hard boundary it keeps between
joining evidence and explaining outcomes.

## Patterns and their handling

- Missing provenance fields — an input event without timestamp,
  frame_number, or capture_file fails loudly. The layer never invents
  provenance.
- Invalid values — non-integer frame numbers, empty capture names,
  non-ISO-8601 timestamps, and offsets missing fail loudly; nothing is
  guessed into validity.
- Sensitive input — events carrying subscriber identity fields
  (imsi, supi, suci, msisdn, guti), authentication material
  (rand, autn, res, auts, kseaf, kamf), or non-redacted NAS identity
  values are rejected at load time. The layer never redacts-and-passes:
  policy violations must be fixed at the producing Skill.
- NGAP present, NAS-5GS missing — the group still forms and is labeled
  with the present sources; the timeline reports missing evidence.
- NAS-5GS present, NGAP missing — symmetric handling.
- Frame gaps — frames absent from the input produce no group; gaps are
  never interpolated, and group frame lists show exactly which frames
  contributed.
- Out-of-order or conflicting timestamps — preserved verbatim; ordering
  is derived and applied, never corrected back into the evidence.
- Duplicate events — kept as separate observations with stable
  ordering; identical input yields identical output.
- Different captures with matching values — never merged. Numeric
  identifier or frame-number equality across captures has no meaning in
  this layer.

## Missing evidence is not failure

    protocol source absent from the input
    !=
    that protocol did not act on the network

A group with only NGAP events does not mean NAS was silent; it means
NAS events were not part of the input window or were not extracted.
Capture filters, window boundaries, extraction gaps, and truncation all
leave the same trace. Reports built on this layer must name the capture
boundary and phrase missing sources as missing evidence.

## Boundary against interpretation

The layer outputs no root_cause, status, success, or failure field, no
procedure state, and no causal language. Joining evidence and ordering
it is the whole job; explaining what the joined evidence means belongs
to future Domain Skills working from protocol context.
