# NAS-EPS Protection and Privacy Rules

## Classification rules

1. If the security header type is absent and the message type is absent, the event is
   `UNKNOWN`.
2. If the security header type is not `PLAIN` and no message identity is observable,
   the event is `PROTECTED_INNER_MESSAGE_UNAVAILABLE` with
   `protected_inner_message_unavailable: true`.
3. If a message identity is observable, the event is `SUPPORTED` when the identity is
   in the bounded set and `UNSUPPORTED` when it is a known message outside the set.
4. A protected message whose outer identity is visible (for example Security mode
   complete) keeps its identity and records that ciphered inner content is present.

## What the Skill must never do

- Claim that a ciphered inner message does not exist.
- Guess an inner message identity from the surrounding sequence.
- Publish ciphered bytes, message authentication codes, ESM container bytes, identity
  values or authentication parameters.
- Treat an unavailable inner message as a missing network message.

## Verification in tests

- `protected-inner.jsonl` produces two `PROTECTED_INNER_MESSAGE_UNAVAILABLE` events
  and one visible Security mode complete.
- `esm-container.jsonl` reports container presence and length only.
- No expected output contains an identity value, a key, or a payload byte string.
