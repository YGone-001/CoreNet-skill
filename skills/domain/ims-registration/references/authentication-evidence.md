# Authentication challenge and retry evidence

## Challenge observations

A 401 Unauthorized or 407 Proxy Authentication Required response is an authentication
challenge. It is not an automatic registration failure. A normal initial IMS
registration may contain a challenge followed by an authorized retry.

The analyzer retains:

- the challenge response event reference;
- the observed `WWW-Authenticate` or `Proxy-Authenticate` presence count;
- the transaction reference;
- the numeric status code.

The raw challenge, realm, nonce, algorithm and opaque parameters are never published.

## Retry observations

A positive Challenge→Retry association requires all of:

- an observed challenged REGISTER transaction and its 401/407 response;
- a distinct later REGISTER transaction with the same capture-local registration
  identity and an increasing CSeq;
- `Authorization` presence for a 401, or `Proxy-Authorization` presence for a 407;
- no competing eligible retry candidate;
- exact challenge/retry transaction and event references.

A request carrying Authorization before receiving the observed Challenge is not a
retry of that Challenge. Challenge-before-retry ordering is evaluated from transaction
order and CSeq progression, never from timestamps, addresses or frame proximity.

The authoritative decision returns an association record with the challenge
transaction, challenge response, retry transaction, retry request, basis, missing
evidence and conflict findings. The public authentication status is derived from that
record, not from independent challenge and authorization booleans.

A retry is not assumed to have succeeded because credentials were present. The SIP
outcome is derived from the observed final response. Multiple eligible retries with
different CSeq values remain ambiguous and are not associated.

## Evidence states

| State | Meaning |
| --- | --- |
| `NOT_OBSERVED` | No challenge and no authorization presence |
| `CHALLENGE_OBSERVED` | A 401/407 was observed (reserved for single-transaction evidence) |
| `RETRY_OBSERVED` | Authorization presence was observed (reserved for single-transaction evidence) |
| `CHALLENGE_RETRY_ASSOCIATED` | A challenged transaction and a later authorized retry are supported by the same attempt evidence |
| `CHALLENGE_WITHOUT_OBSERVED_RETRY` | A challenge is observed without an associated retry |
| `RETRY_WITHOUT_OBSERVED_CHALLENGE` | Authorization is present without an observed preceding challenge |
| `RETRY_NOT_ESTABLISHED` | A challenge and authorization are present but the retry relationship is not supported |
| `AUTHENTICATION_OUTCOME_UNPROVED` | Authentication cannot be independently verified from the capture |

The attempt also publishes
`authentication_cryptographically_verified: false`. This is a fixed protocol
boundary, not a computed guess.

## Restrictions

A 200 OK after an authorized REGISTER does not prove that the analyzer verified the
digest response or any IMS AKA vector. The supported conclusion is a protocol-observed
registration response.

Never publish:

- Digest nonce or response;
- Authorization username;
- authentication vector, RES/XRES, RAND, AUTN, CK or IK;
- raw `Authorization`, `Proxy-Authorization`, `WWW-Authenticate` or
  `Proxy-Authenticate` values.

Only presence counts and bounded evidence states are published.