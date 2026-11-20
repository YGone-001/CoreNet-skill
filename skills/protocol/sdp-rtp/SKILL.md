# SDP Protocol Skill

## Purpose

Provide bounded, deterministic, privacy-safe evidence from explicitly supplied SDP
message bodies (RFC 8866) and from RTP version 2 / RTCP SR, RR, SDES and BYE packet
structures (RFC 3550), using reviewed dissector fields or structured offline input.

## Scope

- Parse `v=`, `o=`, `s=`, `c=`, `t=`, `m=` and session/media attribute scopes.
- Recognise `a=rtpmap`, `a=fmtp`, direction attributes, `a=mid`, `a=rtcp`,
  `a=rtcp-mux` and `a=group`.
- Classify ICE, fingerprint, crypto and other security-sensitive attributes without
  publishing their values.
- Preserve unknown attributes as bounded uninterpreted evidence.
- Classify network addresses by family and scope without publishing raw addresses.
- Optionally derive capture-scoped HMAC-SHA-256 references for SDP media transport
  endpoints and RTP UDP source/destination endpoints when an explicit local endpoint
  key is supplied. No key means no endpoint field and unchanged prior output.
- Fail closed on malformed mandatory structure, invalid ports, invalid payload
  declarations, duplicate/contradictory declarations and truncated or oversized input.
- Extract RTP version 2 fixed-header fields, CSRCs, padding, extension metadata, marker,
  payload type, sequence, timestamp, SSRC and packet provenance. Padding, extension and
  marker are mandatory one-bit observations: missing evidence never becomes false.
  Explicit false is preserved; missing is `INCOMPLETE`; invalid type/value is `INVALID`.
- Extract bounded RTCP Sender Report, Receiver Report, SDES and BYE components while
  preserving compound component order and nested report-block binding. Validate the
  type-specific RTCP count fields: receiver report count for SR/RR, source count for
  SDES/BYE; a missing count/hierarchy is `INCOMPLETE`, a contradiction is `AMBIGUOUS`.
- Validate RTP and RTCP version as the two-bit 0-3 field. Version 2 is supported;
  other representable versions are `UNSUPPORTED`; values outside 0-3 are `INVALID`.
- Keep remote-reported loss/jitter distinct from locally observed RTP fields; publish
  no local loss, jitter, MOS or media-quality calculation.

## Non-Goals

It must not implement RTP stream reconstruction, local RTCP statistics, jitter or
packet-loss calculation, MOS, media QoS, ICE connectivity verification, SRTP
decryption, SDP Offer/Answer pairing, SIP-to-SDP dialog association, SDP-to-RTP
endpoint correlation (owned by `sdp-rtp-transport`), IMS media success, Diameter Rx, Diameter charging or
unified-workflow integration. It must not claim APP, RTPFB, PSFB, XR or unknown RTCP
families as supported merely from numeric packet type.

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
`capture_file` must be a privacy-safe basename; absolute paths, path separators and
workstation path forms are rejected before output.

RTP/RTCP structured JSONL uses one record per RTP packet or RTCP compound packet with
`protocol`, `fields`, frame/capture provenance and caller-supplied references. RTCP
`fields.components` retains component order; each component carries nested
`report_blocks`, `sdes_chunks` and `bye_sources` rather than flattened arrays.

An optional `--endpoint-key-file` supplies exactly 32 owner-only random bytes. A
malformed, unreadable or permission-broad key fails before output. The key is never
auto-generated or published. Authorized PCAP/PCAPNG mode uses an installed TShark dissector with an explicit
reviewed field allowlist and optional caller-supplied `--decode-as` mappings. It never
assumes a UDP port, RTP Payload Type or SDP declaration identifies RTP/RTCP.

Limits: 512 messages, 64 KiB per body, 8 KiB per line, 64 media sections, 256
attributes per scope and 64 formats per media section.

## Outputs

`schemas/sdp-events.schema.json` (analysis `0.2.0`, event schema `1.2.0`) publishes:

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

RTP/RTCP output (`schemas/rtp-rtcp-events.schema.json`, event schema `1.2.0`)
publishes RTP packet fields and RTCP component/type/report-block/SDES/BYE evidence with
capture-scoped references, nullable mandatory flags, declared and observed source
counts, `OBSERVED`/`INCOMPLETE`/`AMBIGUOUS`/`UNSUPPORTED`/`INVALID` status, bounded
counts and explicit privacy/quality limitations. With an endpoint key it additionally
publishes optional source/destination endpoint references and endpoint evidence status
for RTP events.

No raw SDP body, address, identity, ICE credential, fingerprint digest or key material
is published.

## Dependencies

- Required: Python 3 standard library for structured SDP/RTP/RTCP input.
- Optional: an installed TShark for authorized capture extraction. TShark is never
  installed automatically.
- Capture extraction, SIP dialog association and stream reconstruction are not
  dependencies of the structured path.

## Workflow

1. Validate the JSONL or capture provenance contract.
2. Parse SDP bodies line by line and RTP/RTCP structures from reviewed structured fields
   or an allowlisted TShark JSON tree.
3. Preserve session/media scopes and RTCP compound/report-block nesting separately.
4. Redact sensitive values, payloads, addresses and identities.
5. Classify unsupported protocol families explicitly.
6. Fail closed on malformed, contradictory or incomplete structures.
7. Validate and publish deterministic JSON plus an optional text report.

## Evidence Rules

- `OBSERVED`: structurally valid SDP fields present in the supplied body.
- `DERIVED`: deterministic classifications such as payload type class, address family
  or BUNDLE reference status.
- `INCOMPLETE`: required SDP fields or connection data are missing, or input is
  truncated.
- `AMBIGUOUS`: contradictory directions, duplicate mappings or unresolved BUNDLE
  references.
- `UNSUPPORTED`: unknown line types/media types, unsupported RTP versions, or RTCP
  APP/RTPFB/PSFB/XR/unknown families outside the implemented subset.
- `INVALID`: malformed lines, fields, ports, payload declarations, RTP/RTCP ranges or
  oversized input.

No Offer/Answer, media-delivery, stream, QoS or IMS verdict is produced. RTCP report
fields are remote-reported values and are never relabeled as local measurements.

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
python3 scripts/validate-rtp-rtcp.py
```

SDP fixtures cover valid single/multiple media, audio/video, IPv4/IPv6, static/dynamic
payloads, RTP mapping, FMTP, directions, scopes, RTCP, BUNDLE, missing mandatory
fields, invalid ports/payloads, contradictions, malformed lines, mixed line endings,
unknown attributes, truncation, oversized input, sensitive redaction, capture
provenance mismatch, reference integrity and deterministic replay. RTP/RTCP fixtures
cover fixed headers, boundaries, CSRC/extension/padding, marker, invalid/missing/
truncated records, SR/RR report blocks including negative cumulative loss, SDES/BYE
redaction, compound ordering, unsupported families, malformed lengths, binding
failures, capture/reference integrity, TShark unavailability/unsupported fields,
explicit decode-as, no port inference, privacy, output collision and deterministic
JSON/report replay.

## References

- `references/field-reference.md`
- `references/failure-cases.md`
- `references/privacy.md`