# NAS-EPS Protocol Skill

Bounded, standalone EPS NAS semantic extraction.

```text
skills/protocol/nas-eps/
├── SKILL.md                 Skill contract
├── README.md                This file
├── manifest.yaml            Machine-readable manifest
├── references/              Normative model, message map, field reference, protection rules, failure cases
├── schemas/                 Event and trace-event JSON Schemas
├── scripts/                 extract-nas-eps.py, nas_eps_timeline.py, nas_eps_model.py
├── filters/                 Reviewed Wireshark display filters
├── examples/                Fields-JSONL fixtures and expected events
└── tests/                   Standalone unit tests
```

## Quick start

```bash
# Capture input (requires tshark on PATH); no separate S1AP file needed
python3 scripts/extract-nas-eps.py capture.pcap --output nas-eps-events.jsonl

# Structured offline input plus trace projection
python3 scripts/extract-nas-eps.py examples/extracted/attach-flow.jsonl \
  --input-format fields-jsonl \
  --output nas-eps-events.jsonl \
  --trace-output nas-eps-trace.jsonl

# Protocol-local timeline
python3 scripts/nas_eps_timeline.py nas-eps-events.jsonl --format text
```

## ESM evidence

Each event carries `esm_messages`, read from a PDML dissection so that an ESM
message keeps its ESM container boundary and its enclosing NAS message. Only
reviewed, non-identifying fields are published: message identity, EBI, PTI, ESM
cause, PDN type, request type, APN presence and length, PDN address presence and
family, QoS and PCO presence, protection state and direction. The APN name, the
assigned PDN address and the container bytes are never retained. Flat field input
publishes `binding_basis: flat_fields` and never claims a container.

## What it extracts

| Evidence | Detail |
| --- | --- |
| Message identity | Attach request/accept/complete/reject, Identity request/response, Authentication request/response/failure/reject, Security mode command/complete/reject |
| Procedure family | `eps-attach`, `identity`, `authentication`, `security-mode-control` |
| Protection | Security header type and derived protection state |
| EMM cause | Value and reviewed name |
| Attach type | Value and reviewed name |
| Identity type | Numeric value only; the identity value itself is never read |
| ESM container | Presence and length only |
| Direction | `uplink` / `downlink` when the enclosing S1AP message exposes it |

## What it does not do

No ESM decoding, no bearer state, no attach verdict, no boundary selection, no root
cause, and no subscriber or authentication material of any kind. See `SKILL.md`.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Events written |
| 3 | `tshark` unavailable |
| 4 | `tshark` failure or required field unavailable |
| 5 | Malformed structured input |
| 6 | No NAS-EPS records in the input |
| 7 | Output failure, including a refused overwrite |

## Tests

```bash
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

## Version

0.1.0
