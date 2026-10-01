# Core Network PCAP

## Purpose

Ingest authorized PCAP/PCAPNG captures or deterministic tshark field exports,
then produce protocol-neutral normalized trace events. This is common
Protocol-layer capture infrastructure, not a protocol-semantic decoder.

## Scope

Capture inventory, frame metadata, endpoint metadata, SCTP/TCP/UDP
classification, tshark dissector-stack classification, UTC timestamp
normalization, packet provenance, and JSON Lines event output.

## Non-Goals

Do not interpret NGAP, NAS, S1AP, GTP, PFCP, Diameter, SIP, SDP, RTP, or SBI
message semantics. Do not infer subscriber identity, parse semantic session
identifiers, diagnose EPC/IMS/5GC procedures, map source code, or assert a root
cause.

## Inputs

Use an authorized `.pcap`, `.pcapng`, or `.cap` file with `tshark` installed,
or a metadata-only JSON Lines export using the documented fields in
`references/tshark-fields.md`. JSON Lines enables deterministic offline use.

## Outputs

`scripts/capture-inventory.py` reports generic capture metadata.
`scripts/extract-events.py` writes one authoritative shared-contract event per
line. Each event carries a frame number, safe capture basename, and
capture-based `OBSERVED` provenance.

## Dependencies

No CoreNet Skill is required. `tshark` is optional for direct capture parsing
and is never installed automatically. The accepted Foundation Skills may help
with investigation methodology but are optional integrations.

## Workflow

1. Confirm capture authorization and record the observation point and limits.
2. Inventory the capture or extracted fields.
3. Extract metadata-only JSON Lines events with frame provenance.
4. Treat tshark dissector-stack classification as `OBSERVED` classification.
5. Hand a classified event to the appropriate planned Protocol Skill when
   semantic interpretation is required.
6. Do not infer procedure success, failure, subscriber identity, or a network
   function role from this output.

## Evidence Rules

Capture and tshark metadata are `OBSERVED`; UTC timestamp conversion is
`DERIVED`. No port heuristic is implemented. Absence from one capture is not
absence from the network: capture point, filtering, truncation, encryption,
offload, timing, and capture loss can limit evidence.

## Failure Handling

Missing or malformed structured input, empty input, unavailable tshark, tshark
failure, and unsafe output replacement return a readable error and non-zero
exit status. Install tshark manually when direct capture parsing is needed.

## Validation

Run `python tests/test_core_network_pcap.py` from this package for local
fixtures, or use repository discovery from the repository checkout. The package
validator confirms its standalone contract and byte-identical event schema.

## References

Read `README.md`, `references/capture-model.md`, `references/classification.md`,
`references/correlation-boundaries.md`, and `references/tshark-fields.md`.
