# SDP Protocol Skill

## Purpose

Provide bounded, deterministic, privacy-safe structural evidence from explicitly
supplied SDP message bodies, using the reviewed RFC 8866 grammar and a small
media-attribute vocabulary.

## Scope

- Parse `v=`, `o=`, `s=`, `c=`, `t=`, `m=` and session/media attribute scopes.
- Recognise `a=rtpmap`, `a=fmtp`, direction attributes, `a=mid`, `a=rtcp`,
  `a=rtcp-mux` and `a=group`.
- Classify ICE, fingerprint, crypto and other security-sensitive attributes without
  publishing their values.
- Preserve unknown attributes as bounded uninterpreted evidence.
- Classify network addresses by family and scope without publishing raw addresses.
- Fail closed on malformed mandatory structure, invalid ports, invalid payload
  declarations, duplicate/contradictory declarations and truncated or oversized input.

## Non-Goals

This Skill must not implement RTP extraction, stream reconstruction, RTCP statistics,
jitter/loss/MOS, media QoS, ICE connectivity verification, SRTP decryption, SDP
Offer/Answer pairing, SIP-to-SDP dialog association, SDP-to-RTP endpoint correlation,
IMS media success, Diameter Rx, Diameter charging or unified-workflow integration.

## Inputs

JSONL, one supplied SDP body per record:

```json
{
  "source_reference": "sip-body:synthetic-sdp.pcapng:1.1",
  "capture_file": "synthetic-sdp.pcapng",
  "capture_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
  "frame_number": 1,
  "frame_reference": "frame:1",
  "message_occurrence": 1,
  "sdp_body": "v=0\r\no=- 1000 2000 IN IP4 10.0.0.1\r\n..."
}
```

All records in one input must share one capture identity and SHA-256. Duplicate source
references, missing provenance, malformed JSON and mixed-capture input are rejected.

Limits: 512 messages, 64 KiB per body, 8 KiB per line, 64 media sections, 256
attributes per scope and 64 formats per media section.

## Outputs

`schemas/sdp-events.schema.json` publishes:

- input provenance;
- per-message evidence status (`OBSERVED`, `INCOMPLETE`, `AMBIGUOUS`, `UNSUPPORTED`,
  `INVALID`) and parser version;
- session origin/name/connection/timing summaries;
- independent session and media attribute inventories;
- media type, port, protocol and payload format classifications;
- recognised RTP mappings, FMTP parameter metadata, direction, MID, RTCP, RTCP-MUX
  and BUNDLE group references;
- sensitive-attribute presence class and redacted length metadata;
- unknown attributes and malformed/unknown line metadata;
- bounded completeness counts and explicit limitations.

No raw SDP body, address, identity, ICE credential, fingerprint digest or key material
is published.

## Dependencies

- Required: Python 3 standard library.
- Optional: none.
- Capture extraction, SIP dialog association and RTP are not dependencies because they
  are not implemented here.

## Workflow

1. Validate the JSONL provenance contract.
2. Parse each body line by line with bounded sizes.
3. Preserve session-level and media-level scopes separately.
4. Redact sensitive values and network addresses.
5. Classify unknown attributes and lines as uninterpreted evidence.
6. Fail closed on malformed, contradictory or incomplete mandatory structures.
7. Validate and publish deterministic JSON plus an optional text report.

## Evidence Rules

- `OBSERVED`: structurally valid SDP fields present in the supplied body.
- `DERIVED`: deterministic classifications such as payload type class, address family
  or BUNDLE reference status.
- `INCOMPLETE`: required SDP fields or connection data are missing, or input is
  truncated.
- `AMBIGUOUS`: contradictory directions, duplicate mappings or unresolved BUNDLE
  references.
- `UNSUPPORTED`: unknown line types or media types outside the bounded vocabulary.
- `INVALID`: malformed lines, fields, ports, payload declarations or oversized input.

No Offer/Answer, RTP, media or IMS verdict is produced.

## Failure Handling

A malformed input contract exits non-zero and publishes no successful analysis. A
structurally invalid SDP body remains an explicit evidence record with reason codes;
it is never promoted to a valid media description. Additional evidence needed is the
original message context, complete body and, for media behavior, separate RTP/RTCP
observation under a future authorized capability.

## Validation

```bash
python3 -m unittest discover -s skills/protocol/sdp-rtp/tests -p 'test_*.py' -v
python3 scripts/validate-sdp-rtp.py
```

Fixtures cover valid single/multiple media, audio/video, IPv4/IPv6, static/dynamic
payloads, RTP mapping, FMTP, directions, scopes, RTCP, BUNDLE, missing mandatory
fields, invalid ports/payloads, contradictions, malformed lines, mixed line endings,
unknown attributes, truncation, oversized input, sensitive redaction, capture
provenance mismatch, reference integrity and deterministic replay.

## References

- `references/field-reference.md`
- `references/failure-cases.md`
- `references/privacy.md`