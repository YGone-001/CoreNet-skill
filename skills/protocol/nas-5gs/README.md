# nas-5gs

`nas-5gs` is a standalone Protocol-layer package for bounded NAS-5GS
semantic extraction on the N1 interface. Version 0.2.0 implements the
5GMM registration, identity, authentication, security mode, service, and
status subset plus the 5GSM PDU session establishment, modification, and
release subset and 5GSM status, with security-envelope classification,
bounded session-management normalization, privacy defaults, and shared
trace-event projection. It never performs NAS cryptography and never
decides procedure outcomes.

Reviewed basis: 3GPP TS 24.501 version 19.8.0 Release 19 (message types,
5GMM and 5GSM causes, registration types, identity types, request type,
PDU session type, SSC mode) and 3GPP TS 24.007 version 18.2.0 Release 18
(extended protocol discriminator: 5GMM 0x7E, 5GSM 0x2E), cross-checked
against the NAS-5GS dissector of Wireshark/TShark 4.7.1
(v4.7.1-0-g667ab240e6de). Where a specification edition and the
dissector disagree, the reviewed specification value is preserved and
the tool version is recorded.

## Package structure

- `scripts/nas5gs_model.py`: shared standalone normalization helpers and
  reviewed identity tables.
- `scripts/extract-nas5gs.py`: capture or structured JSONL input to
  detailed NAS events, with optional trace projection and the explicit
  sensitive-identity opt-in.
- `scripts/nas5gs_timeline.py`: protocol-local message timeline (text or
  JSON); never labels procedure success or failure.
- `schemas/nas5gs-event.schema.json`: detailed event contract, including
  the optional 5GSM `session_management` object.
- `schemas/trace-event.schema.json`: byte-identical copy of the shared
  trace-event schema.
- `references/`: protocol model, message map, field reference, security
  envelope, identity privacy, failure cases.
- `filters/wireshark.txt`: display filters verified on 4.7.1.
- `examples/extracted/`: synthetic structured fixtures (no payloads, no
  real identities, no authentication material, documentation address
  ranges only).
- `examples/expected/`: deterministic expected outputs.
- `tests/`: package-local test entry point.

## Usage

```bash
python scripts/extract-nas5gs.py capture.pcapng --output nas5gs-events.jsonl
python scripts/extract-nas5gs.py capture.pcapng --trace-output trace-events.jsonl
python scripts/extract-nas5gs.py fields.jsonl --input-format fields-jsonl --output nas5gs-events.jsonl
python scripts/extract-nas5gs.py fields.jsonl --output events.jsonl --include-sensitive-identifiers
python scripts/nas5gs_timeline.py nas5gs-events.jsonl --format text
```

Inputs are validated before extraction; existing outputs are refused
unless `--force` is given; outputs are deterministic (identical input,
identical bytes). Default identity behavior is presence-and-type only;
`--include-sensitive-identifiers` carries the structured-input
`identity_value` field for authorized workflows and is documented as a
risk in references/identity-privacy.md.

## Output and limits

Detailed events carry frame provenance, the security envelope, message
identity with family, support status, local result label and extended
protocol discriminator, direction with basis, bounded 5GMM IEs, and an
OBSERVED evidence record with enumerated derivations. 5GSM events
additionally carry a `session_management` object: PDU session identity,
procedure transaction identity, request type, PDU session type, SSC
mode, DNN, S-NSSAI, PDU address, always-on flags, bounded QoS presence
with QFI/5QI values, EPCO presence, and the 5GSM cause.

Boundaries: unknown codes stay UNKNOWN; known out-of-scope messages stay
UNSUPPORTED names; ciphered inner messages stay unavailable instead of
guessed; a PDU session with several QFIs keeps all of them and the
generic projection omits `qfi` rather than fabricating one; SEID/TEID are
never derived from NAS; authentication vectors are never emitted;
subscriber fields stay unpopulated. A 5GSM cause is protocol evidence of
the stated session-level reason, not an end-to-end root cause.

## Standalone validation

Copy this directory anywhere and run `python tests/test_nas5gs.py`. No
repository-root runtime files are required.
