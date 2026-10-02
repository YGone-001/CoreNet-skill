# nas-5gs

## Purpose

Answer WHAT an observed NAS-5GS message means at the protocol layer:
security-envelope classification, bounded 5GMM message identity for the
registration / identity / authentication / security-mode / service /
status subset, bounded 5GSM message identity for the PDU session
establishment / modification / release and 5GSM status subset, bounded IE
normalization (registration type, follow-on request, ngKSI, identity
type, 5GMM and 5GSM cause, selected NAS algorithms, service type, and
bounded session-management fields), and shared trace-event projection
with privacy defaults. This is a Protocol-layer Skill for the N1
interface. Reviewed basis: 3GPP TS 24.501 version 19.8.0 Release 19 and
3GPP TS 24.007 version 18.2.0 Release 18 (extended protocol
discriminator), as implemented by the NAS-5GS dissector of
Wireshark/TShark 4.7.1.

## Scope

- Distinguish 5GMM from 5GSM via protocol-local evidence and the observed
  extended protocol discriminator (5GMM 0x7E, 5GSM 0x2E).
- Classify the security envelope: plain, integrity protected, ciphered,
  new security context; preserve sequence number, MAC presence, and
  security parameter index; record whether the inner message was
  available to the dissector (never guess it).
- Identify bounded 5GMM and bounded 5GSM messages (SUPPORTED), known
  out-of-scope messages (UNSUPPORTED, name only), and unknown codes
  (UNKNOWN).
- Normalize bounded 5GMM IEs: registration type, follow-on request,
  ngKSI, 5GMM cause code/name, selected NAS ciphering/integrity
  algorithms, control-plane service type, identity type.
- Normalize bounded 5GSM IEs: PDU session identity, procedure
  transaction identity, request type, PDU session type, SSC mode, DNN,
  S-NSSAI, PDU address, always-on indication, bounded QoS presence with
  QFI/5QI values, EPCO presence, and 5GSM cause code/name.
- Emit detailed NAS-5GS JSONL events and optionally shared trace-event
  projections; render a protocol-local message timeline.
- Default privacy behavior: identity presence and type only; raw
  identity values require the explicit opt-in flag. Authentication
  secret material is never emitted in any mode.

## Non-Goals

- Do not determine PDU session establishment, modification, or release
  success or failure; no PDU session lifecycle state is encoded, and
  observing a PDU session establishment accept proves only that the
  message was sent.
- Do not interpret QoS rules deeply: no packet filter grammar, no
  precedence evaluation, no reflective QoS, no GBR/MBR or ARP policy
  analysis.
- Do not decode NGAP PDU session resource semantics, PFCP, GTP-U, or
  SBI/N11 service operations.
- Do not determine 5G Registration success or failure; no mandatory
  message ordering is encoded.
- Do not implement NAS key derivation (KSEAF/KAMF/KNAS), MAC
  verification, ciphering/deciphering, or AKA cryptography.
- Do not emit raw RAND/AUTN/RES*/AUTS, KSEAF/KAMF/KNAS, or raw
  subscriber identities (SUCI/SUPI/5G-GUTI/IMEI) except the explicit
  opt-in for identity_value from structured input.
- Do not parse NGAP context identifiers (AMF/RAN-UE-NGAP-ID) or
  duplicate NGAP ownership; the cross-Protocol join is
  capture_file + frame_number provenance.
- Do not map AMF/SMF/UPF/UE implementations or infer end-to-end root
  cause. A 5GSM cause is protocol evidence, never a root cause.

## Inputs

- An authorized PCAP/PCAPNG capture containing NAS-5GS (directly or
  inside NGAP NAS transport), parsed with user-installed tshark.
- A structured NAS-5GS fields JSONL export (deterministic offline
  input; field list in references/field-reference.md). Unit tests use
  only this form.
- Optionally, classified events from core-network-pcap as transport
  context; generic events alone are insufficient for NAS semantics.

## Outputs

- scripts/extract-nas5gs.py <input> --output events.jsonl
  [--trace-output trace.jsonl] [--include-sensitive-identifiers]
- scripts/nas5gs_timeline.py events.jsonl [--format text|json]
- Detailed events conform to schemas/nas5gs-event.schema.json
  (evidence OBSERVED, derivations enumerated). The optional
  session_management object is present only for 5GSM observations, so
  5GMM events keep the original shape. Projections conform to
  schemas/trace-event.schema.json (byte-identical to the shared
  contract; subscriber fields are never populated, session fields only
  from unambiguous observed 5GSM evidence, and SEID/TEID are never
  derived from NAS).

## Dependencies

None required. Optional: core-network-pcap (capture context), ngap
(sibling Protocol Skill; not a truth source for NAS), wireshark-analysis
/ protocol-reverse-engineering / systematic-debugging (methods), tshark
(capture dissection; never installed automatically). Standalone: normal
runtime needs nothing outside this package directory.

## Workflow

1. Confirm capture authorization and note the observation point.
2. Extract detailed events from capture or structured input; keep
   evidence levels and derivation lists intact.
3. Read message-local semantics only: which message, which family and
   envelope, which bounded IEs, which stated cause.
4. Render the timeline for protocol-local ordering; never label a
   REGISTRATION SUCCESS/FAILURE or a PDU SESSION SUCCESS/FAILURE from
   local sequencing.
5. Hand procedure-state interpretation to the Domain Skills; hand 5GSM
   session procedures to the future 5gc-pdu-session Domain work; hand
   NGAP context joins to provenance-aware Domain correlation.

## Evidence Rules

- OBSERVED: header code, sequence number, MAC presence, security
  parameter index, message-type codes, registration type code,
  follow-on bit, ngKSI, identity type code, cause code, algorithm
  codes, service type code, extended protocol discriminator, PDU
  session identity, procedure transaction identity, request type, PDU
  session type, SSC mode, DNN, S-NSSAI, PDU address, QFI/5QI values.
- DERIVED: header/family/message/procedure names, protection state,
  direction by message definition, cause names, algorithm names,
  result labels, timestamps, inner-availability classification,
  session-management names.
- INFERRED: protocol-local relationships strongly suggested but not
  directly proven.
- HYPOTHESIS: explanations needing additional evidence.
- CONFIRMED: used conservatively; this Skill does not confirm
  end-to-end registration or session outcomes.

## Failure Handling

Missing or malformed input, ambiguous records (both MM and SM message
types), conflicting family/discriminator evidence, unavailable or
failing tshark, and unsafe output replacement produce readable stderr
errors and non-zero exits (tool unavailable 3, tshark failure 4,
malformed input 5, no events 6, output failure 7). Unknown codes remain
UNKNOWN; unsupported messages remain UNSUPPORTED with names; ciphered
inner messages stay unavailable. When evidence is insufficient, state
the boundary and the additional capture or log evidence needed; never
fill gaps with assumptions.

## Validation

Run python tests/test_nas5gs.py from this package (message mapping,
envelope states, discriminator handling, 5GSM session semantics,
privacy defaults, cause handling, malformed input, tshark-unavailable
behavior, deterministic output, standalone copy). Repository checkouts
also run python scripts/validate-nas-5gs.py for the package contract.

## References

references/protocol-model.md, references/message-map.md,
references/field-reference.md, references/security-envelope.md,
references/identity-privacy.md, references/failure-cases.md,
filters/wireshark.txt.
