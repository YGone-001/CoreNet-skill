# pfcp

`pfcp` is a standalone Protocol-layer package for bounded PFCP semantic
extraction on the N4 interface. Version 0.1.1 implements the Heartbeat,
Association Setup, Session Establishment, Session Modification, and
Session Deletion subset of 3GPP TS 29.244 version 19.6.0 Release 19, with
header preservation, distinct header-SEID / CP-F-SEID / UP-F-SEID
evidence, bounded PDR/FAR/QER/URR rule groups, PFCP Cause preservation, and
protocol-local request/response transaction correlation. It includes
deterministic TShark compatibility handling (candidate field alias resolution
and dynamic header mapping) for direct-PCAP extraction. It never parses
raw PFCP bytes, never inspects GTP-U traffic, and never decides whether a
PDU session or a user-plane path works.

Reviewed basis: 3GPP TS 29.244 version 19.6.0 Release 19 (message types
from table 7.3-1, causes from table 8.2.1-1, interface values from table
8.2.2-1, header semantics from clause 7.2.2), cross-checked against the
PFCP dissector of Wireshark/TShark as published in the Wireshark
display-filter reference. The reviewed environment had no local tshark
installation, so field names are published-reference verified rather than
locally re-dumped; that verification debt is recorded in
`references/field-reference.md`.

## Package structure

- `scripts/pfcp_model.py`: shared standalone normalization helpers,
  reviewed message/cause tables, the F-SEID model, and the bounded rule
  model.
- `scripts/extract-pfcp.py`: capture or structured JSONL input to detailed
  PFCP events, with optional trace projection.
- `scripts/correlate-pfcp.py`: endpoint-scoped request/response transaction
  correlation summary.
- `scripts/pfcp_timeline.py`: protocol-local timeline (text or JSON).
- `schemas/pfcp-event.schema.json`: detailed event contract.
- `schemas/pfcp-correlation.schema.json`: transaction correlation contract.
- `schemas/trace-event.schema.json`: byte-identical copy of the shared
  trace-event schema.
- `references/`: protocol model, message map, field reference, session
  identifiers, rule model, correlation, failure cases.
- `filters/wireshark.txt`: reviewed display filters.
- `examples/extracted/`: synthetic structured fixtures (documentation
  address ranges only, no subscriber identities, no capture payloads).
- `examples/expected/`: deterministic expected outputs.
- `tests/`: package-local test entry point.

## Usage

```bash
python scripts/extract-pfcp.py capture.pcapng --output pfcp-events.jsonl
python scripts/extract-pfcp.py capture.pcapng --trace-output trace-events.jsonl
python scripts/extract-pfcp.py fields.jsonl --input-format fields-jsonl --output pfcp-events.jsonl
python scripts/correlate-pfcp.py pfcp-events.jsonl --output correlation.json
python scripts/pfcp_timeline.py pfcp-events.jsonl --format text
```

Inputs are validated before extraction; existing outputs are refused
unless `--force` is given; outputs are deterministic (identical input,
identical bytes).

## Session identity and rule evidence

- `header.seid` is the header SEID. `session.cp_f_seid` and
  `session.up_f_seid` are separate. The three are never collapsed into one
  undifferentiated identifier, and none of them is a NAS or NGAP PDU
  Session ID.
- `header.seid_expected_zero` records whether the reviewed message
  definition requires a zero header SEID (TS 29.244 clause 7.2.2.4.2, the
  PFCP Session Establishment Request). The observed value is never
  corrected.
- `rule_operations` holds `pdrs`, `fars`, `qers` and `urrs` arrays. Each
  item carries its identifier, explicit operation, binding basis, and
  bounded attributes.
- `unbound_ie_metadata` preserves repeated nested values (F-TEID TEIDs,
  QFIs, rule identifiers) that cannot be provably attributed to one rule,
  together with explicit limitations.

Flattened dissector output does not preserve grouped-IE hierarchy, so
repeated fields are never zipped by array position. Two PDRs and two
F-TEIDs stay ambiguous unless structured input or a single-item message
proves the relationship.

Boundaries: no raw PFCP byte parser, no GTP-U packet analysis, no SBI
semantics, no NAS/NGAP decoding, and no vendor source mapping. PFCP
Network Instance is never renamed to DNN or APN, and `session.teid`,
`session.seid` and `session.qfi` are projected only when a single
unambiguous value exists.

## Standalone validation

Copy this directory anywhere and run `python tests/test_pfcp.py`. No
repository-root runtime files are required.
