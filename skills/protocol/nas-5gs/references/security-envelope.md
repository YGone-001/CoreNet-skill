# NAS Security Envelope

The 5GS NAS security header classifies the protection state of a message
independently of its inner semantics. This Skill preserves that state
and nothing more.

## Classification

Observed security header type (reviewed TShark 4.7.1 table
`nas-5gs.security_header_type`):

| Code | Reviewed name | Derived integrity | Derived ciphering | Derived new context |
| --- | --- | --- | --- | --- |
| 0 | plain NAS message, not security protected | no | no | no |
| 1 | integrity protected | yes | no | no |
| 2 | integrity protected and ciphered | yes | yes | no |
| 3 | integrity protected with new 5GS security context | yes | no | yes |
| 4 | integrity protected and ciphered with new 5GS security context | yes | yes | yes |

Plain messages (code 0) expose their inner message directly, recorded as
`inner_message_available: true` with basis `plain-message`.

## Protected envelopes and inner visibility

A protected envelope may carry an inner NAS message that cannot be
decoded without the security context. Therefore:

    security-protected outer message observed
    does not imply
    inner message successfully decoded

- If the dissector exposed an inner message type (for example, a
  structured export carrying `nas-5gs.mm.message_type` inside a
  protected envelope), the event records
  `inner_message_available: true` with basis `dissector-decoded`.
- Otherwise the event records `inner_message_available: false` with
  `decode_basis: null`. The inner message is never guessed from the
  sequence number, direction, or timing.

## Sequence numbers and MAC

- `security.sequence_number` preserves the exported NAS sequence value
  (low COUNT octet as exposed by the dissector). It is observation
  metadata for ordering within a security context, not a correlation
  identifier across contexts.
- `security.message_authentication_code_present` records MAC presence
  only. The MAC value is never exported by this package, and MAC
  validity is never assessed.

## Explicit cryptographic non-goals

This Skill does not:

- derive KSEAF, KAMF, KNASint, or KNASenc;
- verify or compute message authentication codes;
- cipher or decipher NAS contents;
- implement AKA challenge/response logic;
- store or export authentication vector material (RAND, AUTN, RES*,
  AUTS) in any mode.

Cryptographic correctness cannot be concluded from this Skill's output.
Observing Security mode complete proves only that the observed NAS
message was sent; it does not prove the security context was correct.

## Evidence handling

Header code, sequence number, MAC presence, and security parameter
index are OBSERVED. Header name, integrity/ciphering/new-context state,
and inner-availability classification are DERIVED. Envelope state and
inner-message semantics are always recorded as separate concerns so a
protected-but-undecoded frame cannot masquerade as a decoded one.
