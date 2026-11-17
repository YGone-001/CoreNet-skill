# SIP transaction correlation

This reference defines the protocol-local transaction model used by `sip_transactions.py`.
It follows RFC 3261 transaction-layer identity and matching rules. It does not define
SIP dialogs, IMS registration, authentication, calls, SDP or RTP.

## Transaction identity

A request or response transaction identity is built from the top Via branch, the top
Via sent-by value and the request method. CSeq number, CSeq method, Call-ID and From tag
are consistency evidence. Call-ID alone, CSeq alone, addresses, ports, frame adjacency,
timestamps and endpoint tuples are never transaction identities.

The top Via sent-by is normalized as host (case-folded) plus optional port. The branch
value is compared exactly. The raw branch, sent-by, Call-ID, tags and URIs are kept only
inside the in-memory message records and are never written to the transaction document.

| Evidence | Role |
| --- | --- |
| top Via branch | transaction key |
| top Via sent-by | transaction key |
| request method | transaction key |
| CSeq method | response-to-request method consistency |
| CSeq number | request/response consistency |
| Call-ID | consistency only |
| From tag | consistency only |
| To tag | response branch distinction, not transaction identity |

## Request/response matching

A response is matched only to a request transaction with the same capture, top Via
branch, top Via sent-by and CSeq method. CSeq number must agree. Call-ID and From tag must
agree when both sides expose them; a missing value is published as missing evidence and
can yield `PARTIALLY_MATCHED`. A conflict does not attach the response; it produces a
separate response-only transaction with `NOT_ESTABLISHED` and conflict findings.

A response without a request is `RESPONSE_ONLY`. A request without a response is
`REQUEST_ONLY` with state `TRYING` for non-INVITE and `OPEN_IN_CAPTURE` for INVITE.
The absence of a response is capture incompleteness, never proof of a timeout.

Multiple responses are preserved in source order. Provisional responses drive
`PROCEEDING`. Final responses drive `COMPLETED`. Multiple distinct final responses or
To tags are preserved as separate response branches; no final response is selected and
`SINGLE_FINAL_RESPONSE_NOT_ESTABLISHED` is published. A retransmitted response is
classified only when its protocol fields and in-memory content fingerprint agree.

Out-of-order messages are matched by identity, not by frame adjacency. A response may be
observed before its request. The transaction reports both frame anchors without
fabricating order.

## INVITE behavior

- 100, 180, 183 and other provisional responses → `PROCEEDING`.
- Final non-2xx response → `COMPLETED`; missing ACK is `ACK_NOT_OBSERVED`.
- Final 2xx response → `COMPLETED`; dialog and 2xx ACK association remain unavailable.
- Multiple final branches → `COMPLETED` with no selected final response.
- Missing final response → `OPEN_IN_CAPTURE`, not a timeout.

## CANCEL behavior

CANCEL has its own transaction identity because its method is CANCEL. It is associated
with an INVITE transaction only when the capture, top Via branch, top Via sent-by, CSeq
number, Call-ID and From tag are consistent. The 200 OK to CANCEL is matched to the
CANCEL transaction, not to the INVITE transaction.

A 200 OK to CANCEL acknowledges the CANCEL request only. The INVITE transaction is
`TERMINATED` only when the matching INVITE also has a 487 final response. Otherwise the
INVITE state remains based on its own response evidence and the limitation is published.

## ACK behavior

An ACK for a non-2xx INVITE response uses the INVITE transaction key and CSeq number. It
is attached to the INVITE transaction as associated control evidence and sets
`CONFIRMED`. It does not create a second INVITE transaction.

An ACK for a 2xx INVITE response is an independent request transaction (`ACK_2XX`).
Even when it happens to reuse the INVITE branch, it is never merged. Dialog association
is `DIALOG_ASSOCIATION_UNAVAILABLE`. An ACK without an established INVITE outcome is
`ACK_ORPHAN`; multiple competing INVITE candidates yield `ACK_AMBIGUOUS`.

## Retransmission classification

| Observation | UDP | TCP |
| --- | --- | --- |
| first request/response | `ORIGINAL` / `ORIGINAL_RESPONSE` | same |
| identical repeat in a later frame | `EXACT_RETRANSMISSION` / `RESPONSE_RETRANSMISSION` | `REPEATED_TCP_OBSERVATION` |
| repeat with different content | `CONFLICTING_REQUEST` or distinct response branch | same |
| repeated control ACK | exact retransmission on UDP | repeated TCP observation |

TCP segmentation and decoder reassembly are not SIP retransmissions. A repeated TCP
SIP message is classified as a repeated observation unless independent SIP retransmission
evidence exists. The model never publishes raw SIP content to prove retransmission.

## Transaction state model

| State | Meaning |
| --- | --- |
| `TRYING` | non-INVITE request observed without a response |
| `OPEN_IN_CAPTURE` | INVITE request observed without a final response |
| `PROCEEDING` | provisional response(s) observed, no final response |
| `COMPLETED` | final response observed; no ACK requirement is pending for the observed family |
| `CONFIRMED` | INVITE final non-2xx response plus matching non-2xx ACK |
| `TERMINATED` | INVITE 487 plus matching CANCEL transaction with 200 OK |
| `RESPONSE_ONLY` | response observed with no request association |
| `REQUEST_ONLY` | independent ACK/request transaction without a response |
| `AMBIGUOUS` | more than one candidate transaction remains |
| `INCOMPLETE_EVIDENCE` | required transaction identity or consistency evidence is missing |

`matching_status`, `capture_completeness`, `missing_evidence` and `conflict_findings` are
separate axes. `MATCHED` describes evidence association, not IMS procedure success.
`COMPLETE` describes capture evidence completeness, not a network verdict.

## Privacy

The correlator consumes raw matching values only in memory. Transaction references are
derived from source event references (`sip-event:<capture>:<frame>.<occurrence>`) and
never contain a Call-ID, branch, tag, URI or credential. The transaction document has no
raw matching fields. Error messages identify the field or line, never its value.

## Unsupported behavior

SIP dialog identity, 2xx ACK dialog association, forked-dialog selection, registration
state, authentication state, SDP/RTP, timers, timeout inference, cross-protocol
Diameter/SIP association and IMS procedure verdicts are outside this phase.