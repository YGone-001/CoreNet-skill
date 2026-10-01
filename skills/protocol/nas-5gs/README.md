# nas-5gs

`nas-5gs` is a standalone Protocol-layer package for bounded NAS-5GS
semantic extraction on the N1 interface (UE to AMF). Version 0.1.0
implements the 5GMM registration, identity, authentication, security
mode, service, and status subset with security-envelope classification,
privacy defaults, and shared trace-event projection. It recognizes 5GSM
payloads and defers their semantics, and it never performs NAS
cryptography or decides procedure outcomes.

Reviewed basis: 3GPP TS 24.501 (Release 19 lineage) as implemented by
the NAS-5GS dissector of Wireshark/TShark 4.7.1 (v4.7.1-0-g667ab240e6de).
All identity tables (message types, 5GMM causes, registration types,
identity types, security algorithms) were verified with `tshark -G
fields` and `tshark -G values`; other Wireshark versions were not
reviewed.

## Package structure

- `scripts/nas5gs_model.py`: shared standalone normalization helpers and
  reviewed identity tables.
- `scripts/extract-nas5gs.py`: capture or structured JSONL input to
  detailed NAS events, with optional trace projection and the explicit
  sensitive-identity opt-in.
- `scripts/nas5gs_timeline.py`: protocol-local message timeline (text or
  JSON); never labels procedure success or failure.
- `schemas/nas5gs-event.schema.json`: detailed event contract.
- `schemas/trace-event.schema.json`: byte-identical copy of the shared
  trace-event schema.
- `references/`: protocol model, message map, field reference, security
  envelope, identity privacy, failure cases.
- `filters/wireshark.txt`: 46 display filters verified on 4.7.1.
- `examples/extracted/`: synthetic structured fixtures (no payloads, no
  real identities, no authentication material).
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

Detailed events carry frame provenance, the security envelope (header
type, derived protection state, sequence number, MAC presence, security
parameter index, inner-message availability with decode basis),
message identity with support status and local result label, direction
with basis, bounded IEs (registration type, follow-on request, ngKSI,
identity type, 5GMM cause, selected algorithms, service type), and an
OBSERVED evidence record with enumerated derivations.

Boundaries: 5GSM payloads are DEFERRED (no session identifiers); known
out-of-scope 5GMM messages are UNSUPPORTED names; unknown codes stay
UNKNOWN; ciphered inner messages stay unavailable instead of guessed;
authentication vectors are never emitted; subscriber fields stay
unpopulated in the shared projection. A Registration reject cause is
protocol evidence of the stated NAS-level reason, not an end-to-end
root cause.

## Standalone validation

Copy this directory anywhere and run `python tests/test_nas5gs.py`. No
repository-root runtime files are required.
