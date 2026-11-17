# SIP dialog evidence

This reference defines the protocol-local SIP dialog model produced by
`sip_dialogs.py`. It consumes the accepted SIP message records and the accepted
transaction document. It does not define IMS registration, IMS session control, SDP,
RTP, media delivery or call-success semantics.

## Scope

Supported dialog creators:

- initial INVITE requests that establish an RFC 3261 INVITE dialog;
- provisional responses with a valid To tag, producing Early Dialog evidence;
- 2xx responses with a valid To tag, producing Confirmed Dialog evidence.

Recognized but not modelled as full dialog usages:

- SUBSCRIBE and NOTIFY event subscriptions;
- non-INVITE dialog usages such as PUBLISH or subscription refresh.

REGISTER, OPTIONS and PUBLISH are never treated as INVITE dialog creators.

## Dialog identity

A capture-scoped dialog identity requires:

- the capture;
- Call-ID;
- the initial INVITE From tag, which identifies the initiating side;
- the response To tag, which identifies the selected branch;
- the initiating INVITE transaction reference;
- exact source-event references.

Call-ID alone, Via branch, CSeq, addresses, ports, TCP stream, timestamp proximity,
request method and media addresses are never used as dialog identity.

The initial INVITE may legitimately omit the To tag. That absence is not a malformed
message and does not prevent an Early or Confirmed Dialog from being established by
a later response carrying a To tag.

Different To tags under one Call-ID are different forked dialog branches. A repeated
response with the same tag is not a new dialog.

In-dialog requests may reverse the From/To tag placement. Matching compares the tag
pair, not the fixed From/To positions. A reverse-direction BYE is associated with the
same dialog as the original-direction BYE.

## Published references

Raw Call-ID, From/To tags, SIP URIs, Request-URI, Contact, Via branch, sent-by,
subscriber identities, authentication values and message bodies remain in memory
only. Published references are derived from source-event references:

- `sip-dialog:<capture>:<frame>.<occurrence>`
- `sip-fork:<capture>:<frame>.<occurrence>`
- `sip-observation:<capture>:<frame>.<occurrence>`

A dialog reference is an internal capture-scoped analysis identifier. It is
deterministic, replay-stable and is not a portable subscriber identity.

## Early Dialog evidence

An eligible provisional response establishes Early Dialog evidence when it carries a
valid To tag and the initial INVITE identity is sufficient.

- 100 Trying never creates an Early Dialog.
- 180 Ringing and 183 Session Progress are eligible provisional responses.
- A provisional response without a To tag remains an unresolved observation.
- Repeated 180/183 responses with the same tag do not duplicate the dialog.
- Different To tags create independent branches.
- A provisional response does not prove that a remote user equipment is ringing.
- 183 does not prove successful early-media delivery.

## Confirmed Dialog evidence

A 2xx response associated with the accepted INVITE transaction confirms the branch
identified by its To tag.

- A 2xx may confirm an existing Early Dialog.
- A 2xx may establish a Confirmed Dialog without an observed provisional response.
- A missing 180/183 does not invalidate the confirmed dialog.
- A 2xx without a To tag cannot establish a confirmed dialog and remains unresolved.
- A non-2xx final response does not confirm a dialog.
- A confirmed dialog is signaling evidence only and does not prove RTP delivery,
  two-way audio, IMS registration, authentication or end-to-end call completion.

## Forking

One initial INVITE transaction may produce multiple independent dialogs.

- A distinct valid To tag identifies a separate branch.
- A repeated response on the same branch is not a new dialog.
- A 2xx on one branch does not confirm another branch.
- A failure on one branch does not invalidate another confirmed dialog.
- Multiple 2xx responses are never collapsed into one selected dialog.
- Missing or contradictory tags remain unresolved.
- No branch is marked as the preferred or answered call without independent evidence.

`forked_initiating_transaction_count` counts initiating transaction references shared
by more than one dialog.

## ACK association for 2xx

The ACK for an INVITE 2xx remains an independent SIP request transaction. Dialog
analysis may attach it to a uniquely matching Confirmed Dialog using:

- capture identity;
- Call-ID;
- original INITIATOR From tag;
- the dialog branch To tag;
- the original INVITE CSeq number;
- the ACK CSeq method.

The original INVITE Via branch is not required, and the ACK may use a different
branch. An ACK To tag that does not match a confirmed branch remains unresolved. An
ACK is never assigned to all forked dialogs. Non-2xx ACK remains under the accepted
transaction ownership and does not create a dialog.

## In-dialog requests

Bounded in-dialog methods are BYE, re-INVITE, UPDATE, INFO, PRACK, REFER and MESSAGE.
Matching requires:

- capture identity;
- Call-ID equality;
- a complete From/To tag pair matching the dialog tags;
- a direction consistent with the initiating or responding tag;
- a unique matching dialog;
- exact transaction and event references.

A re-INVITE does not create a new dialog. UPDATE does not establish a session
modification or media change by itself. Application semantics of INFO, REFER and
MESSAGE are not interpreted.

One dialog may contain multiple transactions. One transaction is not assigned to
multiple dialogs; the shared initial INVITE transaction is the only event shared by
forked branches.

## CSeq observations

CSeq values from in-dialog requests are tracked per direction. The model does not
enforce one global monotonic sequence across both directions. A numeric gap is
published as `sequence_gap_observed` with the assessment
`DIRECTION_AWARE_OBSERVATION_ONLY`; it never implies packet loss. Missing messages
remain capture incompleteness.

## BYE and lifecycle evidence

A BYE is dialog-associated signaling. The model distinguishes:

1. BYE request observed;
2. BYE final response observed;
3. BYE transaction pairing established;
4. dialog termination signaling observed;
5. dialog termination established.

A BYE with a 2xx final response on a confirmed dialog sets `dialog_state` to
`TERMINATED` and `observed_lifecycle_status` to `TERMINATION_SIGNALING_OBSERVED`.
A BYE without a final response keeps the dialog `CONFIRMED` and publishes
`BYE_RESPONSE_NOT_OBSERVED`. A non-2xx BYE response does not establish termination.

A 200 OK to BYE proves the SIP response was observed, not that RTP stopped or that
the network delivered an end-to-end release event. A missing BYE is not classified as
an abnormal teardown, and no dialog is terminated merely because the capture ended.

## Lifecycle axes

Dialog identity, observed lifecycle evidence and dialog state are separate:

| Axis | Values |
| --- | --- |
| identity status | `ESTABLISHED`, `AMBIGUOUS`, `INSUFFICIENT_EVIDENCE`, `NOT_ESTABLISHED` |
| observed lifecycle | `EARLY_OBSERVED`, `CONFIRMATION_OBSERVED`, `TERMINATION_SIGNALING_OBSERVED`, `INCOMPLETE_CAPTURE`, `UNRESOLVED` |
| dialog state | `EARLY`, `CONFIRMED`, `TERMINATED`, `UNKNOWN` |

A dialog may be confirmed while its 2xx ACK is absent from the capture. A
termination-signaling observation does not necessarily mean the dialog state is
`TERMINATED`. No state is inferred from elapsed capture time.

## Mid-capture and incomplete evidence

Captures that begin after session establishment are supported without fabricating an
earlier INVITE:

- BYE, UPDATE or re-INVITE without an observed initial INVITE is an unbound
  observation with `DIALOG_CREATOR_NOT_OBSERVED`.
- An ACK without a confirmed branch is an unbound observation.
- Missing Call-ID, From tag or To tag is `INSUFFICIENT_EVIDENCE`.
- Truncated or partially reassembled messages remain bounded by the accepted event
  completeness rules.
- A complete tag pair without a dialog creator is an observed dialog-shaped context,
  not an established INVITE-created dialog.
- Contradictory or multiple possible dialogs remain ambiguous or unbound.

## Privacy

The dialog document publishes no Call-ID, tag, SIP URI, Request-URI, Contact,
subscriber identity, authentication value, message body or SDP content. Raw matching
values are consumed only in memory and are discarded after the document is built.
No persistent subscriber hash is derived from raw identifiers.

## Unsupported behavior

SIP dialog analysis does not provide:

- IMS registration or authentication outcomes;
- call-success or call-failure verdicts;
- RTP media, two-way audio or early-media delivery proof;
- SDP interpretation;
- dialog timer expiration;
- full SUBSCRIBE/NOTIFY subscription state machines;
- cross-protocol Diameter or IMS correlation.