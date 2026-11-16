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

## Latency

Latency is calculated from the frame timestamps only for `MATCHED` pairs. An
open or response-only record publishes no latency.

## What correlation does not prove

- An open Request does not prove a timeout, retransmission or peer failure.
- A matched Answer does not prove application, subscriber, bearer or procedure
  success.
- Correlation is protocol-local; it does not join EPC, IMS or charging
  application namespaces.