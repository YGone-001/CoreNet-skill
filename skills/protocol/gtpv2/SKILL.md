# GTPv2-C

## Purpose

Answer WHAT an observed GTPv2-C session-control message and its information
elements mean at the protocol layer: header semantics, message identity,
message-scope and bearer-scope Cause, message-scope and item-scoped F-TEID
evidence, EBI, APN presence and length, PDN/PAA metadata, RAT type, AMBR
presence, and protocol-local request/response correlation.

This is a Protocol-layer Skill for the S11 and S5/S8 control-plane interfaces
(GTPv2-C over UDP port 2123), bounded to the Echo, Create Session, Modify
Bearer, Delete Session and Release Access Bearers message set of 3GPP
TS 29.274, as decoded by the Wireshark/TShark GTPv2 dissector.

## Scope

- Identify the GTPv2 version, message type code and name, message length,
  TEID-present flag, header TEID, sequence number and piggybacking flag, with
  frame provenance and the transport endpoint tuple.
- Preserve the three header TEID states as distinct evidence: `ABSENT`
  (no TEID field in the header), `ZERO` (TEID field present with value 0) and
  `PRESENT`. The header TEID is never merged with an F-TEID IE.
- Separate message-scope Cause from bearer-scope Cause. A bearer-scope Cause is
  only published when the dissector exposes the Bearer Context item boundary.
- Publish message-scope F-TEID IEs and, when the dissection proves grouping,
  item-scoped F-TEID IEs inside each Bearer Context, each with its interface
  type, TEID and address family.
- Preserve EBI, APN presence and length only, PDN type, PAA address family, RAT
  type, AMBR presence and values, and Charging ID presence.
- Provide protocol-local request/response correlation with the explicit
  classifications `MATCHED`, `OPEN_REQUEST`, `RESPONSE_ONLY` and `AMBIGUOUS`,
  and never assert session, PDN-connection or bearer lifecycle state.
- Support three input paths: a live PCAP/PCAPNG capture decoded through the
  installed TShark, a stored PDML dissection, and a flat fields JSONL file for
  deterministic offline runs.

Supported messages: Echo Request, Echo Response, Create Session Request,
Create Session Response, Modify Bearer Request, Modify Bearer Response,
Delete Session Request, Delete Session Response, Release Access Bearers
Request, Release Access Bearers Response.

Known but out of the bounded analysis scope (reported as `UNSUPPORTED` with
their reviewed name): Version Not Supported Indication, Create/Update/Delete
Bearer, Delete PDN Connection Set, Identification, Context, Detach
Notification, Downlink Data Notification, PGW Restart Notification.

## Non-Goals

- No GTPv1, GTP-U payload or user-plane semantics.
- No session, PDN-connection or bearer lifecycle reconstruction.
- No cross-interface S11/S5-C association and no SGW/PGW implementation mapping.
- No first-abnormal-boundary selection, severity ranking or root-cause output.
- No Diameter, NAS, S1AP or IMS semantics; those belong to other Protocol Skills.
- No subscriber identity, APN name, PAA address or raw IE byte publication.
- No bearer-context grouping inferred from flat list order.

## Inputs

| Input | Description |
| --- | --- |
| PCAP / PCAPNG | A capture containing GTPv2-C over UDP. Requires a user-installed `tshark`; the capture is dissected to PDML so grouped IE boundaries survive. |
| PDML | A stored `tshark -T pdml` dissection. No decoder is required at run time. |
| Structured fields JSONL | One JSON object per line using the reviewed TShark field names documented in `references/field-reference.md`. No decoder is required. |

Flat fields JSONL does not preserve grouped-IE item boundaries. In that mode no
Bearer Context is published; the decoded values are published as explicitly
unbound metadata with a stated limitation.

## Outputs

| Output | Description |
| --- | --- |
| Detailed GTPv2-C events | JSON Lines, one event per observed GTPv2-C message (`schemas/gtpv2-event.schema.json`). |
| Trace-event projection | JSON Lines projection into the shared trace-event contract (`schemas/trace-event.schema.json`). |
| Transaction correlation | JSON summary of request/response transactions (`schemas/gtpv2-transaction.schema.json`). |
| Protocol-local timeline | Text or JSON rendering of the same evidence. |

## Evidence

Every event carries `evidence.level` and `evidence.source`. Message identity,
header values and IE values are `OBSERVED` from the decoded dissection.
`hierarchy_basis` records whether grouping was provable (`pdml_grouped_ie`) or
unavailable (`flat_fields`). `extraction_limitations` lists decoder-driven
gaps, and `derivations` lists interpretations that the Skill adds on top of the
observation.

A `Request accepted (16)` Cause is protocol evidence that the peer accepted that
message. It is never proof that a PDN connection, a bearer or an EPS bearer
lifecycle completed, and it is never a statement about network health.

## Failure Behavior

| Condition | Behavior |
| --- | --- |
| `tshark` missing | Exit 3, message on stderr, no output file. |
| `tshark` fails or the dissection cannot be parsed | Exit 4, message on stderr, no output file. |
| Malformed structured record | Exit 5 with the line or field that violated the contract. |
| Input contains no GTPv2-C records | Exit 6. |
| Output exists without `--force` | Exit 7; the existing file is left intact. |

## Standalone Usage

```bash
python3 scripts/extract-gtpv2.py capture.pcap \
  --output gtpv2-events.jsonl \
  --trace-output gtpv2-trace.jsonl
python3 scripts/correlate-gtpv2.py gtpv2-events.jsonl --output gtpv2-transactions.json
python3 scripts/gtpv2_timeline.py gtpv2-events.jsonl --format text
python3 scripts/gtpv2_timeline.py gtpv2-events.jsonl --format json
python3 scripts/extract-gtpv2.py fields.jsonl --input-format fields-jsonl --output events.jsonl
```

The package copies and runs outside the main repository. The only external
dependency is `tshark`, and only for the capture input path.

## Testing

```bash
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

`examples/pdml/session-control.pdml` is a reduced PDML excerpt derived from an
authorized laboratory capture; unrelated protocol layers, raw IE byte values
and subscriber identities were removed. `examples/pdml/multi-bearer-context.pdml`
is a hand-authored dissection fixture for the multi-bearer and incomplete-hierarchy
cases that the laboratory capture did not contain; it is not a capture. `examples/extracted/` holds flat fields
inputs and small hand-authored correlation inputs. Expected results are under
`examples/expected/` and are regenerated only from the accepted implementation.

## Provenance

Original CoreNet Protocol-layer package. No upstream material imported.
Normative references are 3GPP TS 29.274 (GTPv2-C) and 3GPP TS 23.401 (EPC
architecture context only). Message type codes, IE types, cause values and
F-TEID interface types were verified against the TShark 4.7.1 value tables
rather than assumed. Version 0.1.0.
