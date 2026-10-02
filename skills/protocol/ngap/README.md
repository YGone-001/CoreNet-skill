# ngap

`ngap` is a standalone Protocol-layer package for bounded NGAP semantic
extraction on the N2 interface (NG-RAN to AMF, NGAP over SCTP). Version
0.2.0 implements the UE-context, NAS-transport, Initial Context, release,
and paging subset plus bounded PDU Session Resource Setup, Modify, and
Release semantics and PDU Session resources embedded in Initial Context
Setup. It never decodes NAS payloads, never parses transfer containers,
and never decides whether a PDU Session procedure succeeded.

Reviewed basis: 3GPP TS 38.413 version 19.4.0 Release 19, cross-checked
against the NGAP dissector of Wireshark/TShark 4.7.1
(v4.7.1-0-g667ab240e6de). The reviewed environment had no local tshark
installation, so the new field names were taken from the published
Wireshark NGAP display-filter reference rather than re-dumped with
`tshark -G fields`; that verification debt is recorded in
`references/field-reference.md`.

## Package structure

- `scripts/ngap_model.py`: shared standalone normalization helpers,
  reviewed procedure tables, and the bounded PDU Session resource model.
- `scripts/extract-ngap.py`: capture or structured JSONL input to detailed
  NGAP events, with optional trace projection.
- `scripts/correlate-ngap.py`: deterministic UE-context correlation
  summary, scoped by capture and SCTP association.
- `scripts/ngap_timeline.py`: protocol-local message timeline (text or
  JSON); never labels a PDU Session or UE procedure as succeeded or failed.
- `schemas/ngap-event.schema.json`: detailed event contract, including the
  optional `pdu_session_resources` array and `unbound_resource_metadata`.
- `schemas/trace-event.schema.json`: byte-identical copy of the shared
  trace-event schema.
- `references/`: protocol model, procedure map, field reference,
  correlation, failure cases.
- `filters/wireshark.txt`: display filters verified on 4.7.1.
- `examples/extracted/`: synthetic structured fixtures (documentation
  address ranges only, no subscriber identities, no capture payloads).
- `examples/expected/`: deterministic expected outputs.
- `tests/`: package-local test entry point.

## Usage

```bash
python scripts/extract-ngap.py capture.pcapng --output ngap-events.jsonl
python scripts/extract-ngap.py capture.pcapng --trace-output trace-events.jsonl
python scripts/extract-ngap.py fields.jsonl --input-format fields-jsonl --output ngap-events.jsonl
python scripts/correlate-ngap.py ngap-events.jsonl --output correlation.json
python scripts/ngap_timeline.py ngap-events.jsonl --format text
```

Inputs are validated before extraction; existing outputs are refused
unless `--force` is given; outputs are deterministic (identical input,
identical bytes).

## PDU Session resource evidence

A single NGAP message may carry several PDU Session resources, and a
response may carry successful and failed items at the same time. The
detailed event therefore models resources as an array:

- `pdu_session_resources[]`: `pdu_session_id`, `resource_operation`,
  `resource_list_role`, `snssai`, `nas_pdu_present`, `nas_pdu_length`,
  `transfer` (presence/kind/length), `qfi_values`, `cause`, and
  `binding_basis`.
- `unbound_resource_metadata`: QFI / Cause / PDU Session identity values
  observed in the message but not safely attributable to one item, with
  explicit limitations.

The message-level `result` stays a message/PDU-level label. It never means
that every embedded resource succeeded; a `successfulOutcome`
`PDUSessionResourceSetupResponse` may still contain a
`PDUSessionResourceFailedToSetupListSURes` item.

Structured input binds items explicitly through the
`pdu_session_resources` array. Flattened dissector output is used only
when the binding is provable: a single observed resource list attributes
every PDU Session identity to that list, and nested QFI / NAS-PDU /
transfer values attach only when exactly one resource item exists.
Repeated fields are never zipped by array position.

Boundaries: NAS payload contents are never decoded; transfer containers
are never parsed; `session.teid`, `session.seid`, `session.dnn`,
`session.apn`, and `session.bearer_id` are never populated from NGAP;
`session.pdu_session_id` and `session.qfi` are projected only when
exactly one value is unambiguously represented.

## Standalone validation

Copy this directory anywhere and run `python tests/test_ngap.py`. No
repository-root runtime files are required.
