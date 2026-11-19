# IMS session procedures

## Normative review record

| Specification | Clauses reviewed | Use in this Skill | Retrieval status |
| --- | --- | --- | --- |
| RFC 3261 | Section 9 (CANCEL), Section 12 (Dialogs), Section 13 (Initiating a Session), Section 15 (Terminating a Session), Section 17 (Transactions) | SIP transaction, dialog, CANCEL, INVITE response and BYE semantics | Directly retrieved and reviewed from the RFC Editor text |
| 3GPP TS 24.229 | Applicable IMS session establishment and release procedures | IMS-specific procedure mapping and claims | `NOT_RETRIEVED`: the available specification document exceeded the retrieval size limit in this environment |

Because TS 24.229 was not directly retrieved, this phase does not claim IMS-specific
clause conformance or a complete IMS session procedure implementation. The Skill
models a bounded session-signaling evidence layer whose observable objects are defined
by accepted SIP evidence. TS 24.229 mapping is restricted to terminology already
documented in the repository and remains a documented limitation.

## RFC 3261 evidence directly represented

- An initial INVITE creates a client transaction and may receive zero, one or many
  provisional responses before one or more final responses (Section 13.2.2.1).
- A provisional response with a To tag may create an Early Dialog; 100 Trying has no
  dialog identity (Sections 12.1 and 13.2.2.1).
- Multiple 2xx responses may arrive for one INVITE due to forking; each To tag is a
  distinct dialog branch (Section 13.2.2.4).
- A 2xx INVITE response is an observed acceptance response and requires an ACK. The
  presence or absence of that ACK is separate from the observed 2xx and Confirmed
  Dialog (Sections 13.2.2.4 and 17.1.1.1).
- A non-2xx final response terminates any early dialogs created for that request
  (Sections 12.3 and 13.2.2.3). It is not successful session establishment.
- CANCEL asks a UAS to cease processing a request; a 200 OK to CANCEL acknowledges the
  CANCEL transaction only, while a 487 INVITE is a separate INVITE final response
  (Section 9).
- BYE terminates a specific dialog/session; a 2xx BYE response supports termination
  signaling, not media teardown proof (Sections 12.3 and 15).
- A missing final response is a capture observation, not proof of a SIP timeout.

## Session attempt anchor

An attempt is anchored to one accepted initial INVITE transaction reference. Separate
initial INVITE transactions never merge because they share a Call-ID. No timestamp,
address, port, frame proximity or transport stream substitutes for transaction
identity.

A transaction is treated as in-dialog rather than initial when the accepted Dialog
document identifies it as an in-dialog transaction. Re-INVITE and UPDATE never create
new session attempts.

## Stages and outcomes

| Stage | Evidence source | Semantics |
| --- | --- | --- |
| Initial INVITE | Transaction request event | Observed attempt anchor |
| 100 Trying | Provisional response event, status 100 | Provisional only; no dialog |
| 180 Ringing | Provisional response with To tag | Early Dialog eligible |
| 183 Session Progress | Provisional response with To tag | Early Dialog eligible; no media proof |
| Final response | Transaction final response references | 2xx or non-2xx observed |
| Accepted 2xx | 2xx final response event | Acceptance response observed |
| Confirmed Dialog | Accepted SIP Dialog output | Signaling dialog confirmed |
| 2xx ACK | Dialog ACK references | Observed or missing per branch |
| Non-2xx ACK | Transaction control references | Separate from 2xx ACK |
| CANCEL | CANCEL transaction and association | Separate request, response and INVITE final response |
| BYE | Dialog BYE transaction references | Release signaling observation |

## Forked branches

Each accepted SIP Dialog reference remains an independent branch. A branch may be
Early only, Accepted 2xx, Negative final or unresolved. Multiple 2xx branches are never
collapsed. A negative branch does not invalidate another accepted branch. Missing To
tags remain insufficient evidence and never create a preferred branch.

## CANCEL boundary

A CANCEL 200 OK is not an INVITE success. A 487 INVITE response is not proof of RFC
transaction termination from a passive capture. Even when a CANCEL 200 and INVITE 487
are both observed, `invite_transaction_termination_established` remains false. A CANCEL
observed after an INVITE final response is published as an explicit conflict.

## BYE boundary

A BYE with a 2xx final response on a Confirmed Dialog may support SIP termination
signaling. A BYE without a final response remains incomplete. A negative BYE response
does not establish termination. A 200 OK to BYE does not prove that RTP stopped or that
media resources were released.

## Session modification boundary

re-INVITE and UPDATE are published as in-dialog observations with
`conclusion: NOT_INTERPRETED`. SDP offer/answer, media modification and QoS semantics
are outside this phase.

## 5GC / EPC boundary

This Skill does not modify or consume 5GC/EPC execution paths and does not implement
end-to-end IMS failure-boundary orchestration.