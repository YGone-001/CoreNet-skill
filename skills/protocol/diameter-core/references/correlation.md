# Request/Answer correlation

## Statuses

| Status | Meaning |
| --- | --- |
| `MATCHED` | one Request and one Answer share a unique protocol-local key |
| `OPEN_REQUEST` | a Request has no assigned Answer within the capture |
| `RESPONSE_ONLY` | an Answer has no eligible Request within the capture |
| `AMBIGUOUS` | more than one Request competes for the same Answer |

## Matching gates

A candidate pair must satisfy all of the following:

1. same capture;
2. same transport association;
3. Request before Answer;
4. opposite endpoint direction;
5. equal Command Code;
6. equal Application-ID;
7. equal Hop-by-Hop Identifier;
8. equal End-to-End Identifier for `STRONG` correlation.

An Answer occurrence is assigned to at most one Request. Requests and Answers
are never paired by frame proximity.

## Reused identifiers

The same Hop-by-Hop Identifier on different transport associations remains
independent. A duplicate Request on the same association is published as a
separate `OPEN_REQUEST`; if several such Requests compete for one Answer, the
Answer is `AMBIGUOUS` and every candidate is published.

## Matching eligibility

Only Requests whose End-to-End Identifier equals the Answer's identifier are
eligible. A Request with the same Hop-by-Hop Identifier but a contradictory
End-to-End Identifier is not a candidate; it does not create false ambiguity and
it is never attached to the Answer.

A Request becomes selected only after every mandatory condition succeeds:
capture, proven transport association, opposite direction, ordering, Command
Code, Application-ID, Hop-by-Hop Identifier and End-to-End Identifier.

## Status invariants

```text
MATCHED        request != null, answer != null, latency published
OPEN_REQUEST   request != null, answer == null, latency null
RESPONSE_ONLY  request == null, answer != null, latency null
AMBIGUOUS      request == null, candidates retained, latency null
```

An Answer occurrence is assigned at most once. A previously consumed Request is
not reused for a duplicate Answer; the duplicate remains `RESPONSE_ONLY`.

## Transport association identity

Correlation requires decoder-proven association identity:

- TCP uses the decoder stream identifier.
- SCTP uses the decoder Association Index.
- When the decoder exposes no stream or Association Index, the event publishes
  `ENDPOINT_ONLY`; the pair is fail-closed and no `MATCHED` transaction is
  produced. An endpoint tuple alone is never treated as proof of Association
  continuity.
- The SCTP Verification Tag is direction-specific evidence. It is published but
  is not used as an association key.

## Latency

Latency is calculated from the frame timestamps only for `MATCHED` pairs. An
open, response-only or ambiguous record publishes no latency.

## What correlation does not prove

- An open Request does not prove a timeout, retransmission or peer failure.
- A matched Answer does not prove application, subscriber, bearer or procedure
  success.
- Correlation is protocol-local; it does not join EPC, IMS or charging
  application namespaces.