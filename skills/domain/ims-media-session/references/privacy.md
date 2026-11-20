# Privacy Policy

## Never published

- Raw IP addresses or IPv6 addresses.
- Raw UDP source or destination ports.
- Raw endpoint tuples.
- HMAC keys, key-file contents or key-file paths.
- Raw SDP bodies or SIP bodies.
- SIP Call-ID, From tag or To tag.
- SIP URIs.
- Subscriber identities such as IMSI, SUPI, MSISDN or IMPI.
- ICE credentials, candidates or selected pairs.
- DTLS fingerprints.
- RTP/RTCP payloads.
- Authentication or key material.

## Published

- Capture basename and capture SHA-256.
- Accepted artifact source names and analysis versions.
- Opaque endpoint references `endpoint-hmac-sha256:v1:<digest>`.
- Opaque correlation context `endpoint-context-hmac-sha256:v1:<digest>`.
- IMS Session attempt, branch, transaction and Dialog references.
- IMS Media Signaling exchange references and SDP references.
- SDP message references, media-section indices, MID, media type and transport
  protocol.
- Transport Correlation references, original status/strength/type, match
  directions, UDP Stream references and RTP packet event references.
- Bounded missing-evidence, conflict, completeness and limitation fields.

Opaque HMAC endpoint references are already-approved pseudonymous evidence. The
Domain does not introduce a new reversible identifier.

## Input handling

All four artifacts are read in memory and are never modified. No capture, raw
packet data or key file is read. Output JSON and report contain only accepted
references and bounded classifications.

Fixtures are synthetic and sanitized.