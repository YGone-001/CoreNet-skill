# NAS-EPS

## Purpose

Answer WHAT an observed EPS NAS message means at the protocol layer: message
identity, protection state, procedure family, EMM cause, bounded attach and identity
metadata, ESM container presence, and bounded ESM session-management evidence.

This is a Protocol-layer Skill for the EPS NAS protocol (UE to MME, carried over
S1AP on N1), bounded to the EPS attach, identity, authentication and NAS security
mode control message set of 3GPP TS 24.301, as implemented by the Wireshark/TShark
4.7.1 NAS-EPS dissector.

## Scope

- Identify the EPS NAS message type for the bounded set, using the reviewed TS 24.301
  identity and the decoder value table.
- Report the security header type and the resulting protection state
  (`PLAIN`, `INTEGRITY_PROTECTED`, `INTEGRITY_AND_CIPHERED`, and the new-context and
  partially-ciphered variants).
- Keep authentication and NAS security mode control as distinct procedures; they are
  never merged into one stage because they occur consecutively.
- Preserve EMM cause value and name exactly.
- Preserve attach type, identity type value, ESM container presence and length, and
  the presence of ciphered payload and message authentication code.
- Distinguish `SUPPORTED`, `UNSUPPORTED`, `UNKNOWN` and
  `PROTECTED_INNER_MESSAGE_UNAVAILABLE`.
- Report direction when the enclosing S1AP message exposes it, with the basis
  recorded; otherwise leave it null.
- Support both a live capture input and a structured fields JSONL input.

### ESM session management (bounded)

- Decode the reviewed ESM subset: PDN connectivity request/reject, activate
  default EPS bearer context request/accept/reject, ESM information
  request/response and ESM status. Other known ESM identities are named but
  reported as `UNSUPPORTED`.
- Read ESM messages from a PDML dissection so each message keeps its ESM
  container boundary and its enclosing NAS message. Flat field input is published
  as `flat_fields` and never claims a container.
- Publish the EPS bearer identity and the procedure transaction identity as
  separate fields, and never join two NAS messages because a PTI or an EBI value
  happens to match.
- Publish APN presence and length only, PDN address presence and family only, and
  QoS/PCO presence only. The APN name, the assigned PDN address and the ESM
  container bytes are never retained.
- A ciphered NAS message whose inner ESM cannot be read keeps
  `PROTECTED_INNER_MESSAGE_UNAVAILABLE`; it is never reported as an absent ESM
  message.

Supported messages: Attach request, Attach accept, Attach complete, Attach reject,
Identity request, Identity response, Authentication request, Authentication response,
Authentication failure, Authentication reject, Security mode command, Security mode
complete, Security mode reject.

## Non-Goals

- No ESM decoding. The ESM container is reported by presence and length only.
- No EPS bearer or PDN connection state, and no default bearer analysis.
- No LTE Attach procedure state machine, no first-abnormal-boundary selection, no
  root cause.
- No subscriber identity: IMSI, IMEI, IMEISV, GUTI and TMSI values are never read.
- No authentication material: RAND, AUTN, RES, XRES and key material are never read.
- No claim that a ciphered inner message is absent; it is reported as unavailable.
- No MME implementation, vendor configuration or source-code mapping.

## Inputs

| Input | Description |
| --- | --- |
| PCAP / PCAPNG | A capture containing EPS NAS, normally encapsulated in S1AP over SCTP. Requires a user-installed `tshark`. |
| Structured fields JSONL | One JSON object per line using the reviewed TShark field names documented in `references/field-reference.md`. |

Reading NAS from a capture does not require a separately extracted S1AP event file:
the Skill filters the capture for `nas-eps` directly.

## Outputs

| Output | Description |
| --- | --- |
| Detailed NAS-EPS events | JSON Lines, one event per observed NAS message (`schemas/nas-eps-event.schema.json`). |
| Trace-event projection | JSON Lines projection into the shared trace-event contract (`schemas/trace-event.schema.json`). |
| Protocol-local timeline | Text or JSON rendering of the same evidence. |

## Evidence

Message identity and protection state are `OBSERVED`. A protected message whose inner
identity cannot be seen is reported as `PROTECTED_INNER_MESSAGE_UNAVAILABLE` with a
derivation stating that no inner identity is observable. An unavailable inner message
is never treated as a missing message on the network.

## Failure Behavior

| Condition | Behavior |
| --- | --- |
| `tshark` missing | Exit 3, message on stderr, no output file. |
| `tshark` fails or a required field is unavailable | Exit 4, message on stderr, no output file. |
| Malformed structured record | Exit 5 with the line or field that violated the contract. |
| Input contains no NAS-EPS records | Exit 6. |
| Output exists without `--force` | Exit 7; the existing file is left intact. |

## Standalone Usage

```bash
python3 scripts/extract-nas-eps.py capture.pcap --output nas-eps-events.jsonl
python3 scripts/extract-nas-eps.py capture.pcap \
  --output nas-eps-events.jsonl --trace-output nas-eps-trace.jsonl
python3 scripts/nas_eps_timeline.py nas-eps-events.jsonl --format text
```

The package copies and runs outside the main repository; the only external
dependency is `tshark`, and only for the capture input path.

## Testing

```bash
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

Fixtures are fields JSONL inputs under `examples/extracted/`; expected detailed
events are under `examples/expected/`. Ciphered payload and ESM container bytes in
fixtures are zero-filled at their original length, so fixtures carry no subscriber
material.

## Provenance

Original CoreNet Protocol-layer package. No upstream material imported. Normative
references are 3GPP TS 24.301 (EPS NAS) and 3GPP TS 23.401 (procedure context only);
field names were verified against the TShark 4.7.1 dissector rather than assumed.
Version 0.1.0.
