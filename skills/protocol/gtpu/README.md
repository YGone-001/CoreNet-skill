# gtpu

`gtpu` is a standalone Protocol-layer package for bounded GTP-U evidence
extraction on the N3 interface. Version 0.1.0 implements the G-PDU, Echo
Request, Echo Response, Error Indication, End Marker and Supported
Extension Headers Notification subset of 3GPP TS 29.281 version 19.2.0
Release 19, with PDU Session Container content reviewed against 3GPP
TS 38.415 version 19.1.0 Release 19. It preserves the GTP-U header, scopes
TEID evidence by directed outer endpoints, keeps bounded PDU Session
Container / QFI evidence, and summarizes observed packet and byte volumes.

**This Skill proves only what was observed at one capture point.** Observing
a G-PDU never proves UE delivery, application delivery, remote acceptance,
or end-to-end user-plane success. It never infers packet loss from sequence
numbers, never decodes application payloads, and never correlates a TEID to
PFCP, NGAP, or NAS.

Reviewed basis: 3GPP TS 29.281 version 19.2.0 Release 19 (message types from
table 6.1-1, TEID rules from clause 5.1, extension header types from the
reviewed extension header type table) and 3GPP TS 38.415 version 19.1.0
Release 19 (PDU Session Container frame formats), cross-checked against the
GTP dissector of Wireshark/TShark as published in the Wireshark
display-filter reference. The reviewed environment had no local tshark
installation, so field names are published-reference verified rather than
locally re-dumped; that verification debt is recorded in
`references/field-reference.md`.

## Package structure

- `scripts/gtpu_model.py`: shared standalone normalization helpers, reviewed
  message/extension-header tables, TEID rules, and the container/inner
  packet model.
- `scripts/extract-gtpu.py`: capture or structured JSONL input to detailed
  GTP-U events, with optional trace projection.
- `scripts/summarize-gtpu.py`: directed stream observation summary.
- `scripts/gtpu_timeline.py`: protocol-local timeline (text or JSON).
- `schemas/gtpu-event.schema.json`: detailed event contract.
- `schemas/gtpu-stream.schema.json`: directed stream summary contract.
- `schemas/trace-event.schema.json`: byte-identical copy of the shared
  trace-event schema.
- `references/`: protocol model, message map, field reference, TEID model,
  PDU Session Container, stream correlation, failure cases.
- `filters/wireshark.txt`: reviewed display filters.
- `examples/extracted/`: synthetic structured fixtures (documentation
  address ranges only, no subscriber identities, no capture payloads).
- `examples/expected/`: deterministic expected outputs.
- `tests/`: package-local test entry point.

## Usage

```bash
python scripts/extract-gtpu.py capture.pcapng --output gtpu-events.jsonl
python scripts/extract-gtpu.py capture.pcapng --trace-output trace-events.jsonl
python scripts/extract-gtpu.py fields.jsonl --input-format fields-jsonl --output gtpu-events.jsonl
python scripts/summarize-gtpu.py gtpu-events.jsonl --output streams.json
python scripts/gtpu_timeline.py gtpu-events.jsonl --format text
```

Inputs are validated before extraction; existing outputs are refused unless
`--force` is given; outputs are deterministic (identical input, identical
bytes).

## TEID and directed context

A TEID identifies a tunnel endpoint at one peer, so the same numeric TEID
may exist on unrelated endpoint pairs and in opposite directions. Directed
contexts are therefore keyed as
`gtpu-path:<capture>:<src>:<dst>:teid<id>`, which is DERIVED and explicitly
not a standardized GTP-U identifier. Same-TEID contexts that differ by
endpoint or direction stay separate and are never merged.

Reviewed TEID rules: the Echo Request/Response, the Supported Extension
Headers Notification and the Error Indication carry an all-zeroes TEID; a
G-PDU and an End Marker carry the tunnel TEID. The observed value is never
corrected, and `header.teid_expected_zero` records the reviewed expectation.

## Observed evidence, not a verdict

- `observed_g_pdu_packet_count` counts packets observed in the capture. It
  is never an end-to-end delivery count.
- `observed_payload_byte_count` sums the GTP-U Length field, using the one
  documented definition from TS 29.281 clause 5.1. Byte-count definitions
  are never mixed.
- Sequence numbers are optional. A gap produces at most a non-conclusive
  `sequence_discontinuity_candidate`, never a packet-loss conclusion.
- Identical observations produce at most a duplicate-observation candidate.
- An End Marker is signalling evidence for one directed context, not proof
  that a teardown completed end to end.

Boundaries: no raw GTP-U decoder, no PFCP/NGAP/NAS correlation, no SBI, no
application protocol interpretation, and no vendor source mapping.
`session.teid` is projected only from a G-PDU or End Marker tunnel TEID;
`session.qfi` only when exactly one QFI is unambiguous. SEID, PDU session
ID, DNN, APN, bearer ID and subscriber fields are never populated.

## Standalone validation

Copy this directory anywhere and run `python tests/test_gtpu.py`. No
repository-root runtime files are required.
