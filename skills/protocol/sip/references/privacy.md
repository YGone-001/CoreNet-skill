# SIP privacy contract

Privacy is a publication boundary, not a presentation preference. The Skill
publishes protocol facts that are necessary to identify a message and its source
frame, and suppresses values that can identify a subscriber, a dialog, a peer or
a credential.

## Never published

- IMS private identity, IMS public identity, IMPI, IMPU.
- SIP user part, display name, SIP URI or tel URI.
- IMSI, MSISDN, SUPI, SUCI or any subscriber number.
- Call-ID value.
- From tag, To tag or any dialog tag value.
- Via branch value.
- Contact URI, Route URI, Record-Route URI or P-Asserted/Preferred identity URI.
- Authorization, Proxy-Authorization, WWW-Authenticate or Proxy-Authenticate
  header values.
- Digest username, realm, nonce, response, opaque value, algorithm parameters or
  any security-negotiation material.
- Raw SIP header dump (`sip.msg_hdr`).
- Raw SIP message body (`sip.msg_body`) and any SDP body.

## Published instead

| Sensitive input | Published evidence |
| --- | --- |
| identity or URI | presence and bounded length |
| Call-ID | presence, occurrence count and bounded length |
| dialog tag | presence and bounded length |
| Via branch | presence and bounded length |
| authorization/authentication header | occurrence count only |
| message body | presence and byte length only |

A reviewed standard reason phrase and a safe base media type may be published
because they are protocol vocabulary, not subscriber data. An arbitrary reason
phrase, a non-standard media type, or a media type with parameters is withheld.

## Error and log boundary

Input errors name the offending field or line number, never the value. Decoder
stderr is reduced to its first line and bounded length. Output publication is
atomic, and an existing output is never reused without `--force`.

## Tests

Negative tests assert that private synthetic tokens do not appear in JSONL event
output, trace projection, CLI stdout, CLI stderr or test diagnostics. The test data
is synthetic and labelled as illustrative; no real subscriber capture or
credential is committed.