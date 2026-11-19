# SDP privacy policy

## Never published

- Raw SDP message body or raw line content.
- SIP Call-ID, SIP URI, subscriber identity, username, session ID or session name.
- Raw IP address, IPv6 address, domain name or media endpoint.
- Raw ICE username fragment, password, candidate address or candidate type details.
- Fingerprint digest value.
- SRTP/SDP crypto key material.
- Arbitrary FMTP or unknown attribute values.
- Authentication, key-exchange or identity material.

## Published

- Caller-supplied source reference, capture file name, capture SHA-256, frame number,
  frame reference, message occurrence and parser version.
- Session/media structural field presence, counts, enums and numeric safe metadata.
- Address family and bounded address class (`PRIVATE`, `MULTICAST`, `GLOBAL_UNICAST`,
  `DOMAIN_NAME`, `INVALID`, etc.) without the address itself.
- RTP payload type, encoding name, clock rate and channels.
- Safe reviewed FMTP parameter metadata for a small whitelist.
- Sensitive attribute presence, redacted length and safe reviewed metadata such as
  fingerprint hash function or crypto suite name.
- Unknown attribute name and length only.
- BUNDLE semantics and safe MID tokens.

## Endpoint correlation boundary

This Skill does not implement endpoint correlation. Any future SDP-to-RTP correlation
must define a capture-scoped provenance contract and must not infer correlation from
addresses, ports, frame proximity, timestamps or filenames alone.

## Input handling

All SDP bodies are consumed in memory for parsing. They are never written to the output
JSON or report and are never sent to external services. Fixtures are synthetic and
contain no real subscriber information.

## RTP/RTCP additions

Never published:

- RTP media payload bytes or decoded media.
- Raw UDP payload or raw RTP extension data.
- SRTP encrypted payload, authentication tag or master-key identifier.
- Raw SDES text for CNAME, NAME, EMAIL, PHONE, LOC, TOOL, NOTE or PRIV.
- RTCP APP application data or feedback-control payload.
- Raw endpoint IP addresses or MAC addresses.

Permitted evidence:

- RTP version, padding/extension presence and bounded metadata, CSRC count/numeric
  identifiers, marker, payload type, sequence, timestamp, SSRC and packet length.
- Capture-scoped SSRC references; numeric SSRC is not a subscriber identity.
- SR/RR report values with explicit `RECEIVER_REPORTED`/sender-reported classes.
- SDES item type/name, presence and redacted length.
- BYE source identifiers and redacted reason length.
- Capture/frame provenance and UDP stream metadata as transport conversation context.

SSRC references are capture-scoped. UDP stream indexes are never renamed as RTP
sessions. RTCP report values are not local measurements. No payload-bearing TShark
intermediate JSON is persisted, logged or reported.
