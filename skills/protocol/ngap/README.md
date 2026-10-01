# ngap

`ngap` is a standalone Protocol-layer package for bounded NGAP semantic
extraction on the N2 interface (NG-RAN to AMF, NGAP over SCTP). It
identifies PDU category, elementary procedure, and concrete message for a
reviewed subset, extracts RAN-UE-NGAP-ID / AMF-UE-NGAP-ID as distinct UE
context identifiers, preserves NGAP Cause category/value, correlates
frames into UE contexts deterministically, and emits both detailed NGAP
events and a shared trace-event projection. It does not decode NAS and
does not diagnose procedures.

Reviewed basis: 3GPP TS 38.413 as implemented by the Wireshark/TShark
4.7.1 NGAP dissector (procedure-code and cause vocabularies verified with
`tshark -G fields` / `-G values`). Other Wireshark versions may name
fields or Info-column text differently; nothing here claims coverage of
every NGAP Release.

## Prerequisites

Python 3 standard library is sufficient for structured offline input.
Direct capture parsing additionally requires a user-installed `tshark`
(Wireshark); this package never installs it and never requires network
access.

## Package structure

- `scripts/ngap_model.py`: shared, standalone normalization helpers and
  reviewed identity tables.
- `scripts/extract-ngap.py`: capture or JSONL input to detailed NGAP
  events, with optional trace projection.
- `scripts/correlate-ngap.py`: protocol-local UE-context correlation with
  binding and conflict reporting.
- `scripts/ngap_timeline.py`: protocol-local timeline (text or JSON).
- `schemas/ngap-event.schema.json`: detailed event contract.
- `schemas/trace-event.schema.json`: byte-identical copy of the repository
  shared trace-event schema.
- `references/`: protocol model, procedure map, field reference,
  correlation rules, failure cases.
- `filters/wireshark.txt`: verified NGAP display filters with version
  basis.
- `examples/extracted/`: synthetic structured fixtures; no packet payloads.
- `examples/expected/`: deterministic expected outputs for the fixtures.
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
unless `--force` is given. Detailed events, trace projection, correlation
summaries, and timelines are deterministic: identical input yields
byte-identical output.

## Output and limits

Detailed events carry frame provenance, PDU category with its resolution
basis, procedure/message identity, support status, local result and
sender-role labels, UE NGAP IDs, Cause, NAS-PDU presence and length, SCTP
metadata, and an OBSERVED evidence record with enumerated derivations.
The trace projection writes only semantically correct shared fields —
NGAP-specific identifiers stay in the detailed event and never enter
generic subscriber, session, or dialog fields.

Supported subset (0.1.0): InitialUEMessage, UplinkNASTransport,
DownlinkNASTransport, InitialContextSetup (request/response/failure),
UEContextReleaseRequest, UEContextRelease (command/complete), Paging,
plus identity-only handling of ErrorIndication and
NASNonDeliveryIndication. Everything else reports UNSUPPORTED (reviewed
name, no semantics) or UNKNOWN (no invented identity). Handover, path
switch, NG setup, PDU session resource semantics, and all later-Release
extensions are deferred.

PDU category resolution: tshark does not expose the NGAP PDU category as a
filterable field, so it is resolved from an explicit structured-input
value or from exact Info-column message matching (`pdu_type_basis`
records which). If neither resolves it, `pdu_type` stays null and the
event remains valid.

A UEContextReleaseRequest observed from the NG-RAN side supports only
that the release path was initiated from the observed NG-RAN signaling
side. It is not proof that the NG-RAN caused any user-visible failure.
Missing outcomes inside a capture window are reported as unobserved, not
as network behavior.

## Standalone validation

Copy this directory anywhere and run `python tests/test_ngap.py`. No
repository-root runtime files are required; the package-local schemas and
references are self-sufficient.
