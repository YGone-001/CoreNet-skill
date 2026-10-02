# GTP-U

## Purpose

Answer WHAT GTP-U traffic and fields were observed at a capture point: the
GTP-U message, the header TEID, the outer endpoints that carried the packet,
bounded PDU Session Container evidence, the extension header chain, bounded
inner packet metadata, and the observed packet/byte volume of a directed
tunnel context. This is a Protocol-layer Skill for the N3 interface, bounded
to the G-PDU, Echo, Error Indication, End Marker and Supported Extension
Headers Notification subset of 3GPP TS 29.281 version 19.2.0 Release 19,
with the PDU Session Container content reviewed against 3GPP TS 38.415
version 19.1.0 Release 19.

## Scope

- Identify the GTP-U message type from the reviewed table 6.1-1 and mark it
  SUPPORTED, UNSUPPORTED (known, semantically out of scope) or UNKNOWN.
- Preserve header fields: version, PT, E/S/PN flags, message type code and
  name, length, TEID, sequence number, N-PDU number and next extension
  header type, plus whether the reviewed message definition requires an
  all-zeroes TEID.
- Scope TEID evidence by capture, outer source endpoint, outer destination
  endpoint and direction. A TEID alone is never a global tunnel identity.
- Preserve bounded PDU Session Container evidence (PDU type, QFI, RQI, PPI)
  when it is safely attributable, and preserve ambiguous container values as
  unbound evidence.
- Represent extension headers as an array with reviewed type names; an
  unknown extension header type stays UNKNOWN with its numeric value.
- Preserve bounded inner packet metadata (IP version, addresses, protocol
  number, L4 ports, length, opacity) without reading application payload.
- Summarize observed G-PDU packet and byte counts per directed context, with
  one documented byte-count definition.

## Non-Goals

- Do not implement a byte-level GTP-U decoder, manual header offsets,
  `struct.unpack`, or manual extension-header traversal. Only tshark
  dissector output or structured offline input is used.
- Do not correlate a GTP-U TEID to a PFCP F-TEID, an NGAP transport tunnel,
  or a NAS PDU Session ID. That cross-protocol relation belongs to a future
  PDU Session Domain Skill.
- Do not interpret SBI, N11, Nsmf_PDUSession, HTTP/2, or SM Context.
- Do not infer packet loss from sequence numbers or numeric gaps.
- Do not claim that a tunnel delivered traffic, that a UE received a packet,
  that an application received data, or that user-plane forwarding works.
  Observing a G-PDU proves only that the packet was observed at this capture
  point.
- Do not call identical observations retransmissions; at most they are
  duplicate-observation candidates.
- Do not decode or persist application payloads (HTTP, DNS, SIP, RTP, TLS,
  QUIC) and do not infer an application protocol from a port number.
- Do not map behaviour to SMF, UPF, gNB, or vendor implementations.
- Do not claim end-to-end root cause.

## Inputs

- An authorized PCAP/PCAPNG capture containing GTP-U over UDP, parsed with a
  user-installed tshark (never auto-installed), or
- a structured GTP-U fields JSONL export with the documented fields in
  `references/field-reference.md` (deterministic offline input; unit tests
  use only this form). Structured input is the only form that can declare
  the extension header chain and the inner packet metadata explicitly.

## Outputs

- `scripts/extract-gtpu.py <input> --output gtpu-events.jsonl
  [--trace-output trace-events.jsonl]` — detailed GTP-U event JSONL
  (schema `schemas/gtpu-event.schema.json`) plus the optional trace-event
  projection.
- `scripts/summarize-gtpu.py gtpu-events.jsonl --output streams.json` —
  directed stream observation summary (schema
  `schemas/gtpu-stream.schema.json`).
- `scripts/gtpu_timeline.py gtpu-events.jsonl [--format text|json]` —
  protocol-local timeline; never prints a tunnel, delivery, packet-loss or
  session verdict.

## Dependencies

None required. Optional: `core-network-pcap` (capture provenance),
`wireshark-analysis`, `protocol-reverse-engineering`,
`systematic-debugging` (investigation methods), `tshark` (direct capture
parsing; user-installed). The package is standalone: normal runtime needs
nothing outside this directory, including no repository root, docs, or
shared assets.

## Workflow

1. Confirm capture authorization and observation point; record the capture
   boundary and its limits.
2. Run the extractor on the capture or structured input; treat every
   detailed event as OBSERVED capture evidence with its derivations listed.
3. Run the summarizer to obtain directed tunnel contexts and observed
   packet/byte volumes.
4. Render the timeline for protocol-local ordering.
5. Interpret only within the evidence rules: what was observed at this
   capture point, which direction was observed, and what the capture does
   not prove — then hand off to higher-layer Skills for procedure semantics
   and root cause.

## Evidence Rules

- OBSERVED: message type code, header flags, TEID, sequence number, N-PDU
  number, next extension header, message length, outer endpoints, extension
  header types, container PDU type / QFI / RQI / PPI, Error Indication
  affected TEID, Recovery value.
- DERIVED: message name, message class, Echo request/response role label,
  extension header names, container PDU type names, the directed stream key,
  sequence discontinuity candidate, duplicate-observation candidate.
- INFERRED: protocol-local relationships strongly suggested but not
  directly proven.
- HYPOTHESIS: candidate explanations needing more evidence.
- CONFIRMED: deliberately rare; this Skill never confirms end-to-end tunnel
  or user-plane behaviour.

## Failure Handling

Missing or malformed structured input, empty input, unavailable or failing
tshark, and unsafe output replacement produce a readable error on stderr
and a non-zero exit code (tool unavailable 3, tshark failure 4, malformed
input 5, no events 6, output failure 7). Unsupported messages are reported
UNSUPPORTED, unknown codes UNKNOWN. A capture that begins or ends mid-tunnel
is reported as an observation boundary: absence of an End Marker, an Error
Indication, or reverse-direction G-PDU is not automatically abnormal.

## Validation

Run `python tests/test_gtpu.py` from this package for the fixture suite
(header semantics, TEID scoping, container and QFI handling, control
messages, inner packet boundary, sequence handling, stream summary, trace
projection, schema conformance, deterministic output, malformed input,
tshark-unavailable behavior, standalone copy). Repository checkouts also
run `python scripts/validate-gtpu.py` for the package contract.

## References

Read `README.md`, `references/protocol-model.md`,
`references/message-map.md`, `references/field-reference.md`,
`references/teid-model.md`, `references/pdu-session-container.md`,
`references/stream-correlation.md`, and `references/failure-cases.md`.
Reviewed protocol basis: 3GPP TS 29.281 version 19.2.0 Release 19 and
3GPP TS 38.415 version 19.1.0 Release 19, cross-checked against the
Wireshark/TShark GTP dissector reference; verify filter and field names per
`filters/wireshark.txt` when using another Wireshark version.
