# S1AP

## Purpose

Answer WHAT an observed S1AP message and field mean at the protocol layer: PDU
category, elementary procedure, concrete message identity, eNB/MME UE S1AP
identifiers, Cause, bounded E-RAB item evidence for Initial Context Setup, and
protocol-local UE-context correlation.

This is a Protocol-layer Skill for the S1-MME interface (E-UTRAN to MME, S1AP over
SCTP), bounded to the S1 setup, UE-associated NAS transport, Initial Context Setup
and UE context release message set of 3GPP TS 36.413, as implemented by the
Wireshark/TShark 4.7.1 S1AP dissector.

## Scope

- Identify the S1AP PDU category (`initiatingMessage` / `successfulOutcome` /
  `unsuccessfulOutcome`) with its resolution basis, the procedure code and name, and
  the concrete message type for the supported subset.
- Extract eNB-UE-S1AP-ID and MME-UE-S1AP-ID as distinct UE-context identifiers;
  never fabricate, merge or rename them.
- Preserve S1AP Cause group and value exactly; never expand it into a root cause.
- Preserve NAS-PDU presence and length only. NAS semantics belong to the `nas-eps`
  Protocol Skill.
- Preserve bounded E-RAB item evidence for Initial Context Setup request and
  response: operation, list role and observed E-RAB identifier.
- Preserve TAC, PLMN identity presence and E-UTRAN CGI presence as bounded location
  metadata.
- Provide protocol-local UE-context correlation scoped by capture file and SCTP
  association, with explicit strength (`STRONG`, `SUPPORTED`, `AMBIGUOUS`,
  `UNBOUND`) and ambiguity reasons.
- Support two input paths: a live PCAP/PCAPNG capture decoded through TShark, and a
  structured fields JSONL file for deterministic offline runs.

Supported messages: S1SetupRequest, S1SetupResponse, S1SetupFailure,
InitialUEMessage, UplinkNASTransport, DownlinkNASTransport,
InitialContextSetupRequest, InitialContextSetupResponse, InitialContextSetupFailure,
UEContextReleaseRequest, UEContextReleaseCommand, UEContextReleaseComplete.

### E-RAB item evidence (bounded)

- Publish item-scoped E-RAB evidence for the Initial Context Setup request and
  response: E-RAB identity, QCI, ARP presence, transport layer address and
  GTP-TEID, each bound to its own item from a PDML dissection.
- Publish the S1-U receiving-endpoint role from the message identity only, never
  from a transport address: an Initial Context Setup Request item carries the
  SGW-U endpoint the eNodeB sends uplink traffic to (`sgw_s1u`), and an Initial
  Context Setup Response item carries the eNodeB's own endpoint
  (`enodeb_s1u`). The two roles are never interchangeable.
- Flat field input cannot prove an item boundary, so it is published as
  `unbound_erab_evidence`: the observed E-RAB identities are listed and no QoS
  value or tunnel endpoint is attributed to any of them.
- Report `nas_pdu_embedded` separately from `nas_pdu_present`, because an Initial
  Context Setup Request carries its NAS-PDU inside the E-RAB item.
- An E-RAB identity is not a UE identity, and a published GTP-TEID is
  control-plane provisioning evidence, never proof that a GTP-U tunnel forwards
  traffic.

## Non-Goals

- No NAS decoding of any kind; the NAS-PDU payload is never read or published.
- No LTE Attach procedure state machine and no end-to-end Attach verdict.
- No first-abnormal-boundary selection, no severity ranking, no root-cause output.
- No MME or eNodeB implementation mapping, vendor configuration or source-code
  analysis.
- No X2AP, S11, GTPv2-C, Diameter, RRC or user-plane semantics.
- No E-RAB identifier used as a UE identity.
- No UE merging on timestamp proximity or on a single numeric identifier.

## Inputs

| Input | Description |
| --- | --- |
| PCAP / PCAPNG | A capture containing S1AP over SCTP. Requires a user-installed `tshark`. |
| Structured fields JSONL | One JSON object per line using the reviewed TShark field names documented in `references/field-reference.md`. |

## Outputs

| Output | Description |
| --- | --- |
| Detailed S1AP events | JSON Lines, one event per observed S1AP PDU (`schemas/s1ap-event.schema.json`). |
| Trace-event projection | JSON Lines projection into the shared trace-event contract (`schemas/trace-event.schema.json`). |
| UE-context correlation | JSON summary of contexts, their strength and ambiguity reasons. |
| Protocol-local timeline | Text or JSON rendering of the same evidence. |

## Evidence

Every event carries `evidence.level` and `evidence.source`. Message identity is
`OBSERVED` from the decoded capture; the PDU category records whether it came from a
dissector presence field, the Info column, or an explicit input value. Derivations
that bound an interpretation are listed in `derivations`; decoder-driven gaps are
listed in `extraction_limitations`.

A successful `InitialContextSetupResponse` is protocol evidence that the eNodeB
accepted the request. It is never proof that the LTE Attach procedure completed.

## Failure Behavior

| Condition | Behavior |
| --- | --- |
| `tshark` missing | Exit 3, message on stderr, no output file. |
| `tshark` fails or a required field is unavailable | Exit 4, message on stderr, no output file. |
| Malformed structured record | Exit 5 with the line or field that violated the contract. |
| Input contains no S1AP records | Exit 6. |
| Output exists without `--force` | Exit 7; the existing file is left intact. |

## Standalone Usage

```bash
python3 scripts/extract-s1ap.py capture.pcap --output s1ap-events.jsonl
python3 scripts/extract-s1ap.py capture.pcap \
  --output s1ap-events.jsonl \
  --trace-output s1ap-trace.jsonl \
  --correlation-output s1ap-correlation.json
python3 scripts/s1ap_timeline.py s1ap-events.jsonl --format text
```

The package copies and runs outside the main repository; the only external
dependency is `tshark`, and only for the capture input path.

## Testing

```bash
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

Fixtures are fields JSONL inputs under `examples/extracted/`; expected detailed
events are under `examples/expected/`. Payload-bearing hex values in fixtures are
zero-filled at their original length, so fixtures carry no NAS content.

## Provenance

Original CoreNet Protocol-layer package. No upstream material imported. Normative
references are 3GPP TS 36.413 (S1AP) and 3GPP TS 23.401 (EPC architecture context
only); field names were verified against the TShark 4.7.1 dissector rather than
assumed. Version 0.2.0.
