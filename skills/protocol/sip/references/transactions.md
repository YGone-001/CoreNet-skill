# SIP transaction correlation

This reference defines the protocol-local transaction model used by `sip_transactions.py`.
It follows RFC 3261 transaction identity and matching rules, and RFC 6026 for INVITE
2xx transaction behavior. It does not define SIP dialogs, IMS registration,
authentication, calls, SDP or RTP.

## Matching modes

RFC 3261 section 17.2.3 distinguishes a modern Via branch from a legacy RFC 2543
branch. The two are never conflated.

| Top Via branch | Mode | Request identity |
| --- | --- | --- |
| starts with `z9hG4bK` | `MODERN` | capture, top Via branch, top Via sent-by, request method |
| present but no magic cookie | `LEGACY` | capture, Request-URI, To value, From value, Call-ID, CSeq number, CSeq method, top Via |
| absent | `UNAVAILABLE` | no transaction identity |

A response uses a marker shared with its request transaction:

- `MODERN`: capture, top Via branch, top Via sent-by, CSeq method.
- `LEGACY`: capture, From value, Call-ID, CSeq number, CSeq method, top Via.

Legacy matching does not apply the modern branch-only algorithm. If a required
legacy value is missing, the observation is preserved with
`matching_status: NOT_ESTABLISHED`; Call-ID alone is never used as a fallback.
Raw Request-URI, To/From URI and tags, Via values and Call-ID are retained only in
the in-memory message record and are never published.

## Request and CSeq method consistency

Every request must have a CSeq method equal to its request-line method. A
contradiction such as `INVITE` with `CSeq: 1 REGISTER` is retained as an incomplete
observation with `METHOD_MISMATCH` and cannot form a valid transaction identity or
receive a response association. The correlator never silently rewrites CSeq.

## Response matching

A matching response contributes CSeq number, Call-ID and From-tag consistency
evidence. A conflict does not attach the response; it produces a separate
response-only transaction with `NOT_ESTABLISHED` and a conflict finding. A response
without a request is `RESPONSE_ONLY`. A request without a response is
`REQUEST_OBSERVED` for non-INVITE and `OPEN_IN_CAPTURE` for INVITE; absence is
capture incompleteness, never a timeout.

Multiple provisional responses produce `PROVISIONAL_RESPONSE_OBSERVED`. Final
responses produce `FINAL_RESPONSE_OBSERVED`. Multiple distinct final responses or
To tags remain separate branches and yield `SINGLE_FINAL_RESPONSE_NOT_ESTABLISHED`.

## CANCEL consistency

CANCEL is its own transaction. Association with the original INVITE is a separate
step that verifies:

- same capture;
- matching Via relationship for the applicable matching mode;
- same Request-URI;
- same Call-ID;
- same From value including tag;
- same To value including tag;
- same numeric CSeq;
- CANCEL request-line method and CSeq method equal `CANCEL`;
- original INVITE request-line method and CSeq method equal `INVITE`.

A matching branch alone is not proof that these construction requirements were
satisfied. Association is fail-closed and distinguishes three outcomes:

| Outcome | Condition | Published result |
| --- | --- | --- |
| `MATCH` | every required value is observed and consistent | `ASSOCIATED` |
| `CONFLICT` | required values are observed but contradict | `NOT_ESTABLISHED` plus a conflict finding |
| `INSUFFICIENT_EVIDENCE` | one or more required values are unavailable | `NOT_ESTABLISHED` plus precise missing evidence |

A missing Request-URI, Call-ID, From URI, To URI or CSeq number is insufficient
evidence, never a successful comparison. An absent initial To tag on both the INVITE
and the CANCEL is legitimate; a To tag present on only one side is a
`TO_TAG_MISMATCH` conflict. A conflict is never downgraded to missing evidence, and
missing evidence is never reported as a contradiction.

The CANCEL transaction outcome, the INVITE final response and the INVITE transaction
state are published as separate evidence:

- `cancel_response_sequence_observed`;
- `cancel_final_response_status`;
- `invite_final_response_status`;
- `cancel_invite_association_status`.

A 200 OK acknowledges the CANCEL transaction. A 487 is an observed final response to
the INVITE. When both are present and the association is valid the INVITE reports
`CANCEL_RESPONSE_SEQUENCE_OBSERVED`. It does not report `TERMINATED`: RFC timer I,
timer D, timer H, timer J and timer M expiration cannot be inferred from capture
silence, so `invite_transaction_termination_established` remains false and
`TRANSACTION_TERMINATION_NOT_ESTABLISHED` is published.

## ACK consistency

An ACK for a non-2xx INVITE final response is attached only when the applicable
matching mode and all of the following are consistent:

- same original INVITE Request-URI;
- same Call-ID;
- same From URI and From tag;
- same CSeq number;
- ACK request-line method and CSeq method equal `ACK`;
- original INVITE request-line method and CSeq method equal `INVITE`;
- correct top Via relationship;
- ACK To-tag equals the observed non-2xx final-response To-tag;
- same To URI.

The same required-field policy applies: an unavailable Request-URI, Call-ID, From
URI, To URI, From tag, CSeq number, ACK To-tag or Via identity yields
`INSUFFICIENT_EVIDENCE` and no association. A diagnostic conflict helper never
substitutes for the eligibility check: one shared eligibility result decides
association, and it reports missing and conflicting fields separately. A missing
required field cannot produce server `CONFIRMED` or client `TERMINATED`.

Any contradiction leaves the ACK as an independent unresolved observation with a
conflict finding and never changes the INVITE transaction state. An ACK for a 2xx
response remains an independent `ACK_2XX` request transaction; dialog association is
`DIALOG_ASSOCIATION_UNAVAILABLE`. Multiple competing INVITE candidates yield
`ACK_AMBIGUOUS`.

## Transaction role and state

A passive capture does not establish which stack side owns a transaction. The model
therefore separates:

- `transaction_role`: `CLIENT`, `SERVER` or `UNKNOWN`;
- `observed_evidence_status`: what the capture actually shows;
- `rfc_transaction_state`: an RFC 3261/RFC 6026 projection, present only when the
  role is explicitly known;
- `state_semantics`: `RFC_STATE` or `EVIDENCE_ONLY`.

Observed evidence statuses are `REQUEST_OBSERVED`, `PROVISIONAL_RESPONSE_OBSERVED`,
`FINAL_RESPONSE_OBSERVED`, `NON_2XX_ACK_OBSERVED`,
`CANCEL_RESPONSE_SEQUENCE_OBSERVED`, `OPEN_IN_CAPTURE`, `RESPONSE_ONLY`,
`REQUEST_ONLY`, `AMBIGUOUS` and `INCOMPLETE_EVIDENCE`.

When the role is known, the applicable state machine is used:

- INVITE 2xx → `ACCEPTED` (RFC 6026), preserving multiple 2xx responses.
- INVITE non-2xx without ACK → `COMPLETED`.
- INVITE non-2xx with ACK → `CONFIRMED` on the server side and `COMPLETED` on the
  client side. The client-generated ACK is not termination evidence; the transition
  from `COMPLETED` to `TERMINATED` requires the applicable RFC timer or equivalent
  independently observed transition, which a passive capture does not provide.
- non-INVITE final response → `COMPLETED`; provisional-only → `PROCEEDING`;
  request-only → `TRYING`.

`CONFIRMED` is a server INVITE transaction state after a valid non-2xx ACK. It is
never published for an unknown role. `transaction_state` remains a compatibility
field: it carries the RFC state when one is established and the evidence status
otherwise.

## Retransmission fingerprint confidence

The fingerprint has an explicit completeness class:

| Class | Meaning |
| --- | --- |
| `FULL_MESSAGE` | decoder-delivered header and body are available |
| `HEADER_ONLY` | header is available but the body is unavailable |
| `FIELDS_ONLY` | sanitized reviewed fields only, including Request-URI |
| `UNAVAILABLE` | insufficient identity fields |

Only `FULL_MESSAGE` equality may produce `EXACT_RETRANSMISSION` or
`RESPONSE_RETRANSMISSION`. `HEADER_ONLY` and `FIELDS_ONLY` equality produces
`RETRANSMISSION_CANDIDATE` and publishes `RETRANSMISSION_FINGERPRINT_INCOMPLETE`. An
unavailable fingerprint produces `FINGERPRINT_UNAVAILABLE`. A TCP repeat is a
`REPEATED_TCP_OBSERVATION`, never a SIP retransmission. Bodies are never
reconstructed and raw contents are never published.

## Privacy

The correlator consumes raw matching values only in memory. Transaction references
are derived from source event references (`sip-event:<capture>:<frame>.<occurrence>`)
and never contain a Call-ID, branch, tag, URI or credential. The transaction
document has no raw matching fields. Error messages identify the field or line,
never its value.

## Unsupported behavior

SIP dialog identity, 2xx ACK dialog association, forked-dialog selection,
registration state, authentication state, SDP/RTP, RFC timer state, timeout
inference, cross-protocol Diameter/SIP association and IMS procedure verdicts are
outside this phase.