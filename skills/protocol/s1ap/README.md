# S1AP Protocol Skill

Bounded, standalone S1AP semantic extraction for the S1-MME interface.

```text
skills/protocol/s1ap/
├── SKILL.md                 Skill contract
├── README.md                This file
├── manifest.yaml            Machine-readable manifest
├── references/              Normative model, procedure map, field reference, correlation, failure cases
├── schemas/                 Event and trace-event JSON Schemas
├── scripts/                 extract-s1ap.py, s1ap_timeline.py, s1ap_model.py
├── filters/                 Reviewed Wireshark display filters
├── examples/                Fields-JSONL fixtures and expected events
└── tests/                   Standalone unit tests
```

## Quick start

```bash
# Capture input (requires tshark on PATH)
python3 scripts/extract-s1ap.py capture.pcap --output s1ap-events.jsonl

# Structured offline input, plus trace projection and UE-context correlation
python3 scripts/extract-s1ap.py examples/extracted/ue-context-flow.jsonl \
  --input-format fields-jsonl \
  --output s1ap-events.jsonl \
  --trace-output s1ap-trace.jsonl \
  --correlation-output s1ap-correlation.json

# Protocol-local timeline
python3 scripts/s1ap_timeline.py s1ap-events.jsonl --format text
```

## E-RAB tunnel evidence

Initial Context Setup messages publish item-scoped `erab_items` read from a PDML
dissection: E-RAB identity, QCI, ARP presence, transport layer address and
GTP-TEID, bound to their own item. Flat field input publishes
`unbound_erab_evidence` instead, because a repeated flat list cannot prove which
tunnel endpoint belongs to which E-RAB.

## What it extracts

| Evidence | Detail |
| --- | --- |
| PDU category | `initiatingMessage`, `successfulOutcome`, `unsuccessfulOutcome`, with the resolution basis |
| Procedure | Reviewed TS 36.413 procedure code and name |
| Message identity | S1SetupRequest/Response/Failure, InitialUEMessage, Uplink/DownlinkNASTransport, InitialContextSetupRequest/Response/Failure, UEContextReleaseRequest/Command/Complete |
| UE context | eNB-UE-S1AP-ID and MME-UE-S1AP-ID, kept strictly separate |
| Cause | Cause group (`radioNetwork`, `transport`, `nas`, `protocol`, `misc`) and value |
| NAS transport | NAS-PDU presence and length only; the payload is never read |
| E-RAB items | Operation, list role and observed E-RAB identifier for Initial Context Setup |
| Location metadata | TAC, PLMN identity presence, E-UTRAN CGI presence |

## What it does not do

No NAS decoding, no LTE Attach verdict, no boundary selection, no root cause, no
vendor or implementation mapping. See `SKILL.md` for the full non-goal list.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Events written |
| 3 | `tshark` unavailable |
| 4 | `tshark` failure or required field unavailable |
| 5 | Malformed structured input |
| 6 | No S1AP records in the input |
| 7 | Output failure, including a refused overwrite |

## Tests

```bash
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

## Version

0.2.0
