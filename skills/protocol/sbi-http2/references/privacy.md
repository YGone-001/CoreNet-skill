# Privacy and Security Policy

## Privacy-First Investigation

Signaling on 5G Service Based Interfaces may expose sensitive subscriber and security
information. In accordance with repository governance, this Skill implements strict
privacy defaults.

## Subscriber Identity Redaction

### JSON Request/Response Bodies

SBI payloads (such as `SmContextCreateData`) frequently contain subscriber identifiers:
- `supi`: Subscription Permanent Identifier (e.g., `imsi-001010000000001`)
- `gpsi`: Generic Public Subscription Identifier (e.g., `msisdn-10000000001`)
- `pei`: Permanent Equipment Identifier (e.g., `imeisv-1234567890123456`)

**Default Policy:**
1. Detection: The parser detects the presence of any subscriber identity member.
2. Metadata: `subscriber_identity_present = true`, and `subscriber_identity_type` records
   which identity type was detected (`"SUPI"`, `"GPSI"`, or `"PEI"`).
3. Redaction: The actual identifier string value is **redacted and never persisted**
   in detailed event outputs, correlation files, timelines, or trace projections.

### Generic Trace Projection

- The shared `trace-event.schema.json` defines optional `subscriber` fields (`imsi`, `msisdn`, `supi`, `guti`).
- In this Skill, subscriber fields in the projected trace event **remain unset (empty)**.
- No heuristic conversion (such as stripping `imsi-` prefix from a SUPI to fill `imsi`) is permitted.

## Authorization and Security Headers

### Bearer Tokens and Secrets

Under 3GPP TS 29.500 and TS 29.510, SBI interactions across NF boundaries may use OAuth 2.0
Bearer tokens carried in HTTP `Authorization` headers.
- **`Authorization` header values MUST NEVER be persisted.**
- Any `Authorization` or `Proxy-Authorization` header encountered in input is unconditionally
  stripped and excluded from `selected_headers`.
- OAuth bearer tokens, JWT claims, private keys, passwords, client secrets, and session tickets
  are never accepted into committed artifacts.

## TLS and Secret Material

- This Skill does not implement TLS decryption.
- TLS key log files (`SSLKEYLOGFILE`), RSA private keys, and pre-master secrets are never
  requested, stored, or processed by this Skill.
- If traffic is TLS-encrypted and no cleartext HTTP/2 fields are available, the Skill records
  that application payload evidence is unavailable due to encryption.
