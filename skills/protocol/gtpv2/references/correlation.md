# Correlation model

Correlation answers one narrow question: which observed response belongs to
which observed request, inside one capture. It does not reconstruct sessions,
PDN connections or bearer lifecycles.

## Keys

A request/response pair must satisfy all of:

1. Same capture provenance (`capture_file`).
2. Complementary message identity: the response code is the response of the
   request code (`1↔2`, `32↔33`, `34↔35`, `36↔37`, `170↔171`).
3. Reversed endpoint tuple: `source`/`destination` of the response equals
   `destination`/`source` of the request, including ports.
4. Equal sequence number.

A shared sequence number on its own never links two messages. Two transactions
with the same sequence number on different endpoint pairs stay separate.

## Corroboration

`corroboration` records evidence that is checked but never used as a key:

| Field | Meaning |
| --- | --- |
| `decoder_link_frame` | The dissector's own transaction link (`gtpv2.response_to`), i.e. the request frame the response answers. |
| `teid_echo` | The response header TEID matches a message-scope F-TEID the request advertised. `null` when the request advertised no message-scope F-TEID or the input cannot prove scope. |
| `teid_relation` | `initial_zero_teid_request`, `established_context_request`, `teid_absent_request` or `unavailable`. |

`teid_echo` only uses message-scope F-TEIDs. A bearer-scope or unbound F-TEID
cannot establish which TEID the peer would address.

## Statuses

| Status | Condition |
| --- | --- |
| `MATCHED` | Exactly one response satisfies the keys, or several do and the decoder link selects exactly one. |
| `OPEN_REQUEST` | No response satisfies the keys. The request is open inside this capture; this is not a proven timeout. |
| `RESPONSE_ONLY` | A response satisfies no request in the capture. |
| `AMBIGUOUS` | Several responses satisfy the keys and the decoder link does not select one. All candidates stay in `response_candidates`; none is published as the answer. |

`correlation_strength` is `STRONG` when a TEID echo or a decoder link
corroborates the pairing, `SUPPORTED` when only the keys do, and `NONE` when
there is no pairing.

## Retransmissions

Requests with identical identity inside one capture — same message type, same
sequence number, same endpoint tuple — cannot be separated by protocol
evidence. The earliest frame becomes the transaction request; later copies are
listed in `retransmissions` and counted in `retransmission_count`, and the
transaction strength is capped at `SUPPORTED`.

This is a stated derivation, not a proof of retransmission: the same identity
could in principle be sequence-number reuse. The limitation is attached to the
transaction.

## Ordering and windows

Transactions are ordered by their earliest frame. `observation_window` spans the
request, its retransmissions and the matched response. `evidence_refs` carries
at most ten references.

## Explicit non-claims

- An open request is not a timeout, a failure or a lost message.
- A matched pair is not proof that the procedure succeeded; the Cause is the
  only statement about acceptance, and it is scoped to the message.
- No correlation result asserts that a PDN connection or a bearer exists,
  survived, or was released.
