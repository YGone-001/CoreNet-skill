# NAS-5GS Failure Cases

Protocol-local abnormal and inconclusive patterns this Skill reports,
with the hard boundary between protocol evidence and causal claims.

## Protocol-local abnormal patterns

- Registration reject observed — message identity, local REJECT result,
  5GMM cause code and reviewed name preserved. The cause explains the
  NAS-level rejection as stated on the wire; it does not automatically
  become the end-to-end infrastructure root cause. For example, cause
  22 (Congestion) states congestion evidence, not which element or
  operator decision congested.
- Service reject observed — 5GMM cause preserved. Paging failure, RRC
  failure, or AMF defects are not inferable from Service reject alone.
- Security mode reject observed — 5GMM cause preserved (for example,
  UE security capabilities mismatch). The stated mismatch reason is
  protocol evidence, not a diagnosis of either implementation.
- Authentication failure observed — 5GMM cause and AUTS presence
  recorded. Bad USIM, failed HPLMN authentication backend, clock skew,
  or SQN issues are hypotheses requiring Domain/Implementation-layer
  evidence, never conclusions from this Skill.
- Authentication reject observed — recorded with envelope context. No
  authentication backend logic exists here.
- 5GMM status observed — treated as protocol-level error/status
  evidence with its 5GMM cause; never promoted to an implementation
  root cause.
- Known unsupported message — recognized name (deregistration,
  configuration update, notification, NAS transport, relay messages),
  UNSUPPORTED status, no semantics.
- Unknown message type — numeric code preserved, UNKNOWN status, no
  invented identity.
- 5GSM payload — recognized as DEFERRED family evidence; no session
  semantics.
- Protected envelope without decodable inner message — recorded as
  `inner_message_available: false`. Ciphered contents are never guessed
  from sequence numbers or timing.
- Malformed structured metadata — missing or invalid required fields
  fail loudly per record; nothing is guessed into validity.
- Sensitive identity present — default output redacts values; an
  opt-in export must be deliberate.

## Cause is evidence, not root cause

A 5GMM cause code is what the message stated. The chain from a stated
cause to an end-to-end fault requires procedure context (Domain), core
and radio evidence, and implementation knowledge:

    observed 5GMM cause
        -> protocol-local meaning (this Skill)
        -> procedure interpretation (future Domain Skill)
        -> implementation mapping (future Implementation Skill)
        -> candidate defect, then validation

This Skill's output stops after the first arrow. Reports built from it
must keep cause labels as protocol evidence.

## Capture-window uncertainty

    outcome not observed in this capture
    !=
    outcome not sent on the network

- An expected counterpart (accept, complete, response) missing from the
  capture may be absent because the capture window ended, filters
  dropped it, or the capture point never saw it.
- A protected inner message may be undecodable in the capture yet
  perfectly decodable in the live network with security context.
- Absence of a security-protected response is not proof of absence on
  the air interface, especially at capture points that terminate the
  protected segment.

Reports must name the capture boundary and phrase missing outcomes as
unobserved-in-capture.
