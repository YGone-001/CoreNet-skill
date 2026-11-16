# Diameter Core — Operational Guide

## Purpose

Extract bounded Diameter base-protocol evidence from a packet capture and
correlate Request/Answer pairs without asserting any application or telecom
procedure result.

## Requirements

- Python 3.10 or later.
- TShark 4.2.2 or a compatible decoder for direct capture input.
- `jsonschema` only when running the optional schema tests locally; CI installs it.

## Commands

Extract events and an optional trace projection:

```bash
python3 skills/protocol/diameter-core/scripts/extract-diameter-core.py \
  /path/to/diameter.pcapng \
  --output /tmp/diameter-events.jsonl \
  --trace-output /tmp/diameter-trace.jsonl
```

Correlate Request/Answer evidence and render a timeline:

```bash
python3 skills/protocol/diameter-core/scripts/correlate-diameter-core.py \
  /tmp/diameter-events.jsonl \
  --output /tmp/diameter-transactions.json \
  --timeline-output /tmp/diameter-timeline.txt
```

Deterministic offline replay from sanitized dissector records:

```bash
python3 skills/protocol/diameter-core/scripts/extract-diameter-core.py \
  skills/protocol/diameter-core/examples/dissector/negative-cases.jsonl \
  --input-format fields-jsonl \
  --output /tmp/negative-events.jsonl
```

Stored PDML replay:

```bash
python3 skills/protocol/diameter-core/scripts/extract-diameter-core.py \
  skills/protocol/diameter-core/examples/pdml/base-exchange.pdml \
  --input-format pdml \
  --output /tmp/base-events.jsonl
```

## Input formats

`--input-format auto` selects by extension:

| Extension | Format |
| --- | --- |
| `.pcap`, `.pcapng` | TShark PDML dissection of the capture |
| `.pdml`, `.xml` | Stored PDML |
| `.jsonl`, `.json` | Sanitized dissector records |

A sanitized record has this shape:

```json
{
  "capture_file": "capture.pcapng",
  "frame_number": 1,
  "frame_time_epoch": "1700000000.100000000",
  "message_occurrence": 1,
  "transport": {
    "protocol": "SCTP",
    "source_address": "192.0.2.10",
    "source_port": 40001,
    "destination_address": "192.0.2.20",
    "destination_port": 3868,
    "verification_tag": "0x00000011",
    "stream_id": null,
    "association_index": 0
  },
  "header": {
    "version": 1,
    "length": 68,
    "flags": {"request": true, "proxyable": false, "error": false, "retransmitted": false},
    "command_code": 257,
    "application_id": 0,
    "hop_by_hop_id": 1,
    "end_to_end_id": 161
  },
  "avps": []
}
```

AVP records may carry `code`, `name`, `vendor_specific`, `mandatory`,
`protected`, `vendor_id`, `length`, `value`, and nested `children`. Sensitive
values are discarded again during normalization.

## Outputs

| Output | Contract |
| --- | --- |
| Event JSONL | `schemas/diameter-event.schema.json` |
| Transaction JSON | `schemas/diameter-transaction.schema.json` |
| Trace projection | `schemas/trace-event.schema.json` |
| Timeline | Plain text, one transaction per line |

All collections are deterministically ordered. AVP publication is bounded to
128 nodes per message and 4 nesting levels; omitted descendants are published in
`avps_omitted` and `children_omitted`. JSONL input above 4096 AVP nodes or 64
nesting levels is rejected as malformed.

Correlation requires a decoder-proven TCP stream or SCTP Association Index.
Endpoint-only evidence is published as `ENDPOINT_ONLY` and correlation is
fail-closed. A Request with a contradictory End-to-End Identifier is never
selected; non-`MATCHED` records never publish a Request/latency pair.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success |
| 2 | Malformed or missing input fields |
| 3 | Input contains no Diameter messages |
| 4 | TShark unavailable |
| 5 | TShark failure |
| 6 | Output destination failure |

## Privacy behavior

- User-Name, Subscription-Id, authentication information and authentication
  vectors publish no value.
- Grouped sensitive AVPs do not publish child values in either input path; the
  record keeps `REDACTED` grouping status and an omitted-child count.
- Session-Id publishes presence, length and opaque kind only because a real value
  may embed a subscription identifier.
- Unknown and vendor-specific AVPs publish code, Vendor-ID, flags and length
  only; raw bytes are never emitted.

## Known limitations

- Application IDs and commands outside the reviewed base set stay numeric and
  unsupported.
- Experimental-Result-Code is never translated to a base Result-Code name.
- Grouped AVP children are published only when the decoder proves nesting.
- Correlation requires decoder-proven transport association identity; SCTP
  endpoint tuple reuse without a decoder Association Index is fail-closed.
- AVP publication and JSONL input are bounded; oversized input is rejected.
- Incomplete transport reassembly does not produce a complete message.
- Protocol-local success does not imply Attach, registration, bearer, call or
  service success.