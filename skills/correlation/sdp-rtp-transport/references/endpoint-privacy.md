# Endpoint Privacy Model

## Purpose

SDP and RTP evidence normally contains raw IP addresses and UDP ports. Those
values stay private. The Protocol Skill publishes only a keyed, opaque,
capture-scoped endpoint reference that the Correlation Skill can compare.

## HMAC construction

The helper is shared by the SDP and RTP/RTCP Protocol extractors:

```text
endpoint = HMAC-SHA-256(
  key,
  "corenet-sdp-rtp-endpoint:v1" || 0x00 ||
  transport_code || address_family ||
  capture_sha256_raw || packed_address || port_big_endian
)
```

- `transport_code`: one byte; `1` means UDP.
- `address_family`: one byte; `4` or `6`.
- `capture_sha256_raw`: the 32 raw bytes decoded from the lowercase hexadecimal
  capture SHA-256.
- `packed_address`: the canonical 4-byte IPv4 or 16-byte IPv6 address.
- `port_big_endian`: the 2-byte unsigned UDP port.

All variable-length ambiguity is removed by the fixed layout and by the
versioned, NUL-separated domain separator. The published form is:

```text
endpoint-hmac-sha256:v1:<64 lowercase hexadecimal characters>
```

The capture-scoped correlation context uses a separate domain:

```text
context = HMAC-SHA-256(
  key,
  "corenet-sdp-rtp-context:v1" || 0x00 || context_version(1) ||
  capture_sha256_raw
)
```

Published as:

```text
endpoint-context-hmac-sha256:v1:<64 lowercase hexadecimal characters>
```

Both artifacts publish the same context only when they used the same key and the
same capture SHA-256. The context contains no reusable key identifier and cannot
be used to track an endpoint across captures.

## Key management

- Exactly 32 random bytes, generated with Python `secrets`.
- Supplied only through an explicit local key file (`--endpoint-key-file`).
- Never printed, logged, published, placed in an exception message or committed.
- Never generated automatically by the Protocol extractors, tests or CI.
- POSIX key files must be owner-only; a broader mode is rejected.
- An absent key disables endpoint references and preserves the previous
  privacy-safe Protocol output.

The user-invoked `scripts/create-endpoint-key.py` helper creates the file
exclusively, refuses an existing path, sets `0600`, rejects paths inside the
repository and prints no key material.

## Security properties

Tests demonstrate:

1. Same key, capture and endpoint produce the same reference.
2. A different key produces a different reference.
3. A different capture SHA-256 produces a different reference.
4. A different port produces a different reference.
5. A different address family produces a different reference.
6. A different IP address produces a different reference.
7. The reference cannot be reversed from the published artifact.
8. Raw IP addresses, raw endpoint tuples and raw ports never enter public output.
9. An unkeyed hash is not accepted as a substitute.

## What is not protected

The HMAC protects against publishing raw endpoints and against accidental
cross-capture joins. It does not provide anonymity against an adversary who
already knows the key and can enumerate candidate endpoints. The key is a local
correlation secret, not a production credential or a substitute for capture
access control.