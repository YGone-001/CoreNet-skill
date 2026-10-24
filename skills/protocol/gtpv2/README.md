# GTPv2-C Protocol Skill

Bounded extraction of GTPv2-C session-control evidence from S11 and S5/S8
captures, with hierarchy-correct information-element scope and protocol-local
transaction correlation.

## Why PDML

`tshark -T fields` flattens repeated information elements. In a real Create
Session Response the message-scope F-TEIDs and the F-TEIDs inside the Bearer
Context IE arrive as one comma-separated list, and the message-scope Cause and
the bearer-scope Cause arrive as `16,16`. Flat output therefore cannot prove
which value belongs to which bearer item.

This Skill dissects captures to PDML and reads the dissector's own tree, where
each grouped IE is a node whose children are its member IEs. That is what makes
`bearer_contexts[].cause` and `bearer_contexts[].f_teids[]` provable rather than
guessed.

## Quick start

```bash
# 1. Capture (authorized lab or provided capture)
tshark -r epc.pcap -Y gtpv2 -T pdml > epc.pdml     # optional offline artifact

# 2. Extract detailed events
python3 scripts/extract-gtpv2.py epc.pcap --output events.jsonl --trace-output trace.jsonl

# 3. Correlate request/response transactions
python3 scripts/correlate-gtpv2.py events.jsonl --output transactions.json

# 4. Render the protocol-local timeline
python3 scripts/gtpv2_timeline.py events.jsonl --format text
```

The extractor accepts a capture, a PDML document or a flat fields JSONL file:

```bash
python3 scripts/extract-gtpv2.py epc.pdml --input-format pdml --output events.jsonl
python3 scripts/extract-gtpv2.py fields.jsonl --input-format fields-jsonl --output events.jsonl
```

`--input-format auto` selects by file extension (`.pcap/.pcapng`, `.pdml/.xml`,
`.jsonl/.ndjson`).

## Output shape

One JSON object per line, sorted keys, one object per GTPv2-C message. A frame
that carries more than one GTPv2-C message (piggybacking) yields one event per
message with an explicit `message_occurrence`.

```json
{
  "frame_number": 8,
  "message_type": "Create Session Response",
  "header": {"teid": 6, "teid_state": "PRESENT", "sequence_number": 23},
  "message_cause": {"cause_code": 16, "cause_name": "Request accepted", "scope": "message"},
  "f_teids": [{"scope": "message", "interface_type": 11, "teid": 969}],
  "bearer_contexts": [{
    "item_index": 0,
    "ebi": 5,
    "cause": {"cause_code": 16, "scope": "bearer"},
    "f_teids": [{"scope": "bearer", "interface_type": 1, "teid": 34351}]
  }]
}
```

Field-level reference: `references/field-reference.md`.

## Correlation

`correlate-gtpv2.py` pairs requests and responses on capture provenance, the
request/response message relationship, the reversed endpoint tuple and the
sequence number. A shared sequence number alone never links two messages.

| Status | Meaning |
| --- | --- |
| `MATCHED` | Exactly one response satisfies every key, or the decoder transaction link disambiguates the candidates. |
| `OPEN_REQUEST` | No response for this request exists in the capture. Not a proven timeout. |
| `RESPONSE_ONLY` | A response exists without its request in the capture. |
| `AMBIGUOUS` | Several responses satisfy the keys and none is uniquely identified. |

`correlation_strength` is `STRONG` when a TEID or decoder link corroborates the
pairing, `SUPPORTED` when the keys alone do, and `NONE` when there is no
pairing. Identical requests inside one capture are reported as
`retransmissions` of the earliest frame instead of separate transactions.

## Privacy

Never published: IMSI, MSISDN, MEI, TMSI values; APN network name; PAA address;
raw IE bytes; PDU payloads. Published instead: identity-IE presence booleans,
APN length, PAA address family. The bundled PDML fixture is a reduced excerpt
with those values removed.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success |
| 3 | TShark unavailable for a capture input |
| 4 | TShark dissection or parse failure |
| 5 | Malformed structured input |
| 6 | No GTPv2-C records in the input |
| 7 | Output problem (exists without `--force`, bad directory, same as input) |

## Tests

```bash
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

Fixtures under `examples/` are deterministic; the capture input path is
exercised separately against an authorized real capture.
