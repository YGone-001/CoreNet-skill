# Offer/Answer Procedures and Normative Review

## Bounded procedure model

This Domain implements the signaling-position subset that the accepted SIP and
SDP artifacts can prove. It does not implement the complete RFC 3264
negotiation model.

### Initial offer

RFC 3264 defines the offerer as the agent that generates a session
description to create or modify a session, and the answerer as the agent that
responds with its own description. In an initial INVITE exchange the caller is
the offerer when the INVITE carries an offer. The Domain therefore requires:

- the accepted initial INVITE event is a `REQUEST` with `method = INVITE`;
- `headers.cseq.method = INVITE`;
- the SIP Event message completeness and extraction status are accepted;
- an SDP message exists at the exact same capture-scoped source reference with
  matching frame and message occurrence;
- the SIP Event declares `body_present = true` and
  `headers.content_type = application/sdp`;
- the SDP message evidence status is `OBSERVED`.

When those conditions hold the Domain publishes `INITIAL_INVITE_SDP_OFFER`.

### Answer in an accepted final 2xx response

For each independently accepted IMS Session branch the Domain reads
`dialog_reference`, `response_event_references` and `ack_event_references`. A
branch-scoped answer is published only when:

- the branch outcome is `ACCEPTED_2XX`;
- exactly one accepted 2xx response event carries an eligible SDP message;
- the same initial INVITE offer was observed.

The result is `INITIAL_INVITE_OFFER_ANSWER` with
`negotiation_compatibility = NOT_EVALUATED`. Observing an offer and an answer at
the expected signaling positions does not prove codec overlap, direction
agreement, hold state or successful negotiation.

### Late offer

RFC 3261 permits an INVITE without an offer, with the offer carried in a 2xx
response and the answer carried in the ACK. The Domain implements this bounded
case only when:

- the initial INVITE has no SDP body;
- exactly one accepted 2xx response on an accepted branch carries an eligible
  SDP message;
- exactly one SDP-bearing ACK is present in that branch's accepted
  `ack_event_references`;
- the ACK is a request with `method = ACK` and `cseq.method = ACK`.

The result is `LATE_OFFER_ANSWER`. A missing or competing ACK remains missing
evidence or `AMBIGUOUS`; it never erases the observed 2xx response or the
Confirmed Dialog.

### Forking

One initial INVITE may create several independent dialog branches. Each branch
is processed separately. The Domain never picks the first branch, never moves an
answer across branches and never merges two accepted 2xx branches into one
exchange.

### Dialog termination

An accepted BYE transaction with an accepted 2xx response can move a Dialog from
`CONFIRMED` to `TERMINATED`. The later release does not erase the earlier
INVITE 2xx response, the confirmed Dialog identity or the SDP Offer/Answer
association derived from them. The Domain preserves that historical association
only when the branch still owns the accepted 2xx INVITE response, the response
role and CSeq checks pass, the SDP provenance is intact, and both the branch
release record and the attempt `release_evidence` identify this exact Dialog as
termination-supported. The `TERMINATED` label alone is never evidence of earlier
confirmation; `EARLY` and `UNKNOWN` Dialogs remain ineligible. This historical
association is signaling evidence only and never proves media delivery, RTP
teardown or call success.

### Provisional responses

The accepted SIP Event contract does not expose `Require: 100rel`, `RSeq`,
`RAck` or complete PRACK binding. RFC 3262 and RFC 6337 reliable provisional
response semantics therefore cannot be proven from the accepted artifacts. SDP
in 18x responses is preserved as `PROVISIONAL_SDP_UNINTERPRETED` with its exact
SIP Event reference and is never promoted to a completed early-media
Offer/Answer exchange.

When provisional SDP and final 2xx SDP are observed in the same accepted branch,
both observations are retained. The final response is not treated as a
uniquely established answer: the exchange remains unestablished and carries
`PROVISIONAL_FINAL_SDP_ROLE_UNRESOLVED`. Provisional SDP in a different branch
does not affect the branch under evaluation.

### Final response role

A final-answer or late-offer candidate must be a SIP `RESPONSE` with a valid
2xx `status_code`, `status_code_valid = true`, `headers.cseq.method = INVITE`,
complete message extraction and ownership by the accepted IMS Session branch.
A 2xx response with a BYE, REGISTER, UPDATE or other CSeq method is not an
INVITE answer. The Domain does not rebuild SIP transactions; when the accepted
branch does not prove ownership, the result fails closed.

### Session modification

RFC 3264 defines session modification through a new offer at any time during the
session. The accepted artifacts retain re-INVITE and UPDATE as
`NOT_INTERPRETED`. This Domain preserves their SDP as `OUT_OF_SCOPE`; PRACK,
INFO, MESSAGE, REFER and arbitrary multipart bodies are also out of scope.

## Normative review record

| Document | Retrieval status | Reviewed scope |
|---|---|---|
| RFC 3264 — An Offer/Answer Model with SDP | RETRIEVED (full text via rfc-editor.org) | Abstract, definitions, protocol operation, initial offer, answer generation, offerer processing and session-modification sections |
| RFC 3261 — SIP | NOT_RETRIEVED_IN_THIS_PHASE (semantics consumed from the accepted `sip` Protocol contract) | INVITE, response, ACK, dialog branch and CSeq behavior were not re-derived from the RFC text in this phase |
| RFC 3262 — Reliability of Provisional Responses | NOT_RETRIEVED_IN_THIS_PHASE | Reliable provisional semantics are explicitly not implemented |
| RFC 3311 — SIP UPDATE | NOT_RETRIEVED_IN_THIS_PHASE | UPDATE SDP is explicitly out of scope |
| RFC 6337 — SIP 100rel and early media | NOT_RETRIEVED_IN_THIS_PHASE | Reliable provisional state and role resolution are explicitly not implemented |
| RFC 8866 — SDP | NOT_RETRIEVED_IN_THIS_PHASE (structure consumed from the accepted `sdp-rtp` contract) | SDP structure is owned by the Protocol Skill |
| RFC 3550 — RTP/RTCP | NOT_RETRIEVED_IN_THIS_PHASE (dependency boundary only) | No RTP or RTCP evidence is produced |
| 3GPP TS 24.229 — IMS session control | NOT_RETRIEVED | No IMS-specific 3GPP conformance is claimed and no clause reference is invented |

Absence of retrieval is recorded rather than replaced with invented clause
numbers. IMS-specific behavior in this Skill is limited to the standardized SIP
and SDP signaling positions above.