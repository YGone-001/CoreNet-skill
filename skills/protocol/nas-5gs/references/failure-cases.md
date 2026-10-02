# NAS-5GS Failure Cases

Protocol-local abnormal and inconclusive patterns this Skill reports,
with the hard boundary between protocol evidence and causal claims.

## Protocol-local abnormal patterns (5GMM)

- Registration reject observed — message identity, local REJECT result,
  5GMM cause code and reviewed name preserved. The cause explains the
  NAS-level rejection as stated on the wire; it does not automatically
  become the end-to-end infrastructure root cause.
- Service reject observed — 5GMM cause preserved. Paging failure, RRC
  failure, or AMF defects are not inferable from Service reject alone.
- Security mode reject observed — 5GMM cause preserved.
- Authentication failure observed — 5GMM cause and AUTS presence
  recorded; backend, USIM, or clock-skew explanations are hypotheses
  needing other evidence.
- Authentication reject observed — recorded with envelope context.
- 5GMM status observed — treated as protocol-level status evidence with
  its 5GMM cause; never promoted to an implementation root cause.

## Protocol-local abnormal patterns (5GSM)

- PDU session establishment reject observed — message identity, local
  REJECT result, and 5GSM cause code and reviewed name preserved. For
  example cause 27 (Missing or unknown DNN) states a session-level
  reason; it does not prove SMF, UPF, or AMF failure.
- PDU session modification reject observed — 5GSM cause preserved.
- PDU session modification command reject observed — 5GSM cause
  preserved; the UE-side rejection is protocol evidence, not a
  diagnosis of either implementation.
- PDU session release reject observed — 5GSM cause preserved.
- PDU session release command observed — an observed protocol action.
  It is not proof of root cause; the command may reflect policy,
  mobility, or error handling this Skill cannot see.
- 5GSM status observed — treated as protocol-level status evidence with
  its 5GSM cause; never promoted to an implementation root cause.
- Reserved or unknown PDU session type / SSC mode / 5GSM cause — the
  numeric value is preserved with a null name; no semantics are invented.
- Known unsupported 5GSM message (for example PDU session authentication
  command, remote UE report) — recognized name, UNSUPPORTED status, no
  session semantics.
- Unknown 5GSM message type — numeric code preserved, UNKNOWN status, no
  invented identity.
- QoS rules present but no stable QFI exposed — the presence flag is
  preserved and the QFI list stays empty; no QFI is fabricated.
- Protected envelope without decodable inner message — recorded as
  `inner_message_available: false`. Ciphered contents are never guessed.
- Malformed structured session metadata (PDU session identity or
  procedure transaction identity outside 0..255) — fails loudly per
  record; nothing is guessed into validity.

## Shared inconclusive patterns

- Unknown message type — numeric code preserved, UNKNOWN status, no
  invented identity.
- Sensitive identity present — default output redacts values; an opt-in
  export must be deliberate.

## Cause is evidence, not root cause

A 5GMM or 5GSM cause code is what the message stated. The chain from a
stated cause to an end-to-end fault requires procedure context (Domain),
core and radio evidence, and implementation knowledge:

    observed cause
        -> protocol-local meaning (this Skill)
        -> procedure interpretation (Domain Skill)
        -> implementation mapping (external, when evidence is provided)
        -> candidate defect, then validation

This Skill's output stops after the first arrow.

## Capture-window uncertainty

    outcome not observed in this capture
    !=
    outcome not sent on the network

- An expected counterpart (accept, complete, response) missing from the
  capture may be absent because the capture window ended, filters
  dropped it, or the capture point never saw it.
- A protected inner message may be undecodable in the capture yet
  perfectly decodable in the live network with security context.

Reports must name the capture boundary and phrase missing outcomes as
unobserved-in-capture.
