# core-network-pcap

`core-network-pcap` is a standalone Protocol-layer package for metadata-only
capture ingestion, inventory, classification, and normalized trace-event
production. It is executable common infrastructure for later protocol Skills;
it does not decode protocol semantics or diagnose procedures.

## Prerequisites

Python 3 standard library is sufficient for offline extracted JSON Lines.
Direct `.pcap`/`.pcapng` parsing additionally requires a user-installed
`tshark`; this package never installs it.

## Package structure

- `scripts/capture-inventory.py`: generic capture/field inventory.
- `scripts/extract-events.py`: streaming normalized JSON Lines extraction.
- `schemas/trace-event.schema.json`: byte-identical standalone event contract.
- `references/`: capture, classification, correlation, and tshark field rules.
- `examples/`: synthetic metadata fixtures and expected events; no PCAP payloads.
- `tests/`: package-local test entry point.

## Usage

```bash
python scripts/capture-inventory.py examples/extracted/frames.jsonl --json
python scripts/extract-events.py examples/extracted/frames.jsonl --output events.jsonl
```

For a direct capture, use the same commands with a `.pcap` or `.pcapng` input.
Existing output is refused unless `--force` is supplied explicitly.

## Output and limits

The extractor emits JSON Lines following the package-local shared trace-event
schema. `timestamp` is UTC ISO-8601 rounded deterministically to microseconds.
`protocol` is a direct tshark stack classification or `UNKNOWN`. Packet
provenance includes frame number, safe capture basename, and `OBSERVED` source.
The shared schema does not admit an extra protocol-stack property, so the
observed stack is retained in `evidence.source`.

Extraction reads and writes one record at a time, using a temporary output file
that is atomically published only after successful completion. Inventory keeps
only aggregate sets for endpoints and classifications; its memory use grows
with the number of distinct values rather than frame count.

Only generic metadata is extracted by default: timestamps, addresses, ports,
transport, direct dissector stack, and TCP/UDP stream identifiers when exposed.
Payloads, subscriber identifiers, and telecom session fields are not parsed.
A packet absent from one capture is not proof it was absent from the network.

Observed classifications hand off to planned `ngap`, `nas-5gs`, `pfcp`,
`diameter-core`, `sip`, or `sbi-http2` Skills for semantics when those Skills
exist. They do not establish procedure correctness.

## Standalone validation

Copy this directory anywhere and run `python tests/test_core_network_pcap.py`.
No repository-root runtime files are required.
