# Privacy

## Published

- Capture basename only, validated as a privacy-safe basename.
- Capture SHA-256.
- Capture-scoped RTP SSRC reference (`rtp-ssrc:<capture>:<hex>`).
- Aggregate UDP stream identifier.
- Optional capture-scoped HMAC endpoint references and their evidence status.
- Source event, frame, occurrence and analysis references.
- Sequence numbers, extended sequence positions, counts and classification
  labels.

## Never published

- Raw IP addresses or IPv6 addresses.
- Raw UDP ports or endpoint tuples.
- RTP payload bytes, payload hex, extension data or padding bytes.
- SDP bodies, SIP messages, call identities, tags or URIs.
- Subscriber identities (IMSI, MSISDN, SUPI, GPSI), UE identities or IMS
  identities.
- HMAC keys, endpoint keys, SRTP keys or authentication tags.
- Audio, video or codec reconstruction.
- Absolute workstation paths.

## Endpoint references

Endpoint references are HMAC-SHA-256 values produced by the accepted `sdp-rtp`
Protocol Skill with a caller-supplied local key. `rtp-stream` consumes these
opaque references and never loads the key. A unique reference is only a
capture-scoped pseudonym; it does not establish UE identity, IMS identity,
access/core side or sender/recipient role. Absence of endpoint references is
`UNAVAILABLE` and never prevents sequence reconstruction.

## Analysis boundaries that protect privacy

- Duplicate sequence observations are not labelled retransmissions.
- Out-of-order observations are not labelled malicious or attack traffic.
- A restart pattern is not attributed to a UE reboot, application restart,
  network interruption, SSRC collision or sender replacement.
- A sequence gap is unobserved sequence numbers, never confirmed loss.
- RTCP components are counted only and never associated with an RTP stream.
- No jitter, MOS, QoS, delivery, two-way-audio or call verdict is produced.

## Fixtures

Every committed fixture is synthetic and sanitized. No binary capture, raw
address, port, payload, subscriber identity or key material is committed. Real
or private captures are never read by this Skill's tests.