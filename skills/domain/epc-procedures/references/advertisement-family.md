# Advertisement families

An advertisement family is a deterministic group of GTPv2-C messages that
advertise **one S1-U receiving endpoint**. It is not an EPS bearer, not a
generation and not a new allocation.

## Classification vocabulary

| Classification | Meaning |
| --- | --- |
| `SINGLE_ADVERTISEMENT` | one observed message advertises the endpoint |
| `SAME_TRANSACTION_ADVERTISEMENTS` | the request and response of one accepted transaction advertise the same endpoint |
| `SAME_GENERATION_UPDATE_SUPPORTED` | later matched advertisements update an endpoint whose allocation was already observed; no new generation |
| `SEPARATE_GENERATIONS_ESTABLISHED` | an accepted release that names the endpoint separates the advertisements |
| `COMPETING_ALLOCATION_EVIDENCE` | the advertisements disagree on the endpoint or on the item-scoped bearer identity |
| `INSUFFICIENT_GENERATION_EVIDENCE` | the advertisements cannot be ordered into one allocation plus updates |

These are not interchangeable, and a higher classification is never inferred from
a lower one.

## Consolidation gates

Two advertisements are consolidated into one `SAME_TRANSACTION_ADVERTISEMENTS`
family only when **all** of the following hold:

1. both source frames are members of the same accepted GTPv2-C transaction;
2. that transaction is `MATCHED`, with a request and a response present;
3. the correlation strength is `STRONG` or `SUPPORTED` — `NONE`, a missing value
   and an unreviewed value are never sufficient;
4. the procedure family is the same;
5. the item-scoped bearer identities do not conflict;
6. the receiving interface type is identical;
7. the endpoint address and TEID are identical;
8. no negative Cause is observed on the advertisement;
9. every source reference is present.

A family keeps **every** advertisement frame in its evidence. Neither the request
nor the response is erased, and the response is not treated as a new allocation.

## Retransmissions

A retransmission is another observed message of the same transaction. It joins
the same family and keeps its own frame; it never creates a second allocation.
Retransmission equivalence is taken from the accepted correlator, never inferred
from equal payload values.

## Conflicting evidence

* Request and response advertising **different** endpoint values stay visible as
  `COMPETING_ALLOCATION_EVIDENCE`; the request endpoint is never overwritten.
* A negative Cause is not successful provisioning and cannot establish a family.
* A Cause is only read from the bearer context with the **same EBI** as the
  advertisement; a Cause belonging to another bearer item is never substituted.
  When no matching item-scope Cause is observed, `ALLOCATION_ACCEPTED_OBSERVED` is
  not published.
* Different item-scoped bearer identities block consolidation.
* An `OPEN_REQUEST`, `RESPONSE_ONLY` or `AMBIGUOUS` transaction never establishes a
  proved request/response family.
* Multiple uncorrelated advertisements are never merged merely because their
  endpoint values match.
* A transaction whose capture cannot be resolved is never a proved family: the
  same frame number in two captures, or the same message occurring twice in one
  frame, leaves it unbound. The default-bearer and lifecycle models apply the same
  policy, so a transaction unbound in one is never a family in the other.
* The accepted event contract publishes the message outcome as `message_cause`
  with an explicit scope; no other field is read for it.
