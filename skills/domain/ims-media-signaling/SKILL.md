# IMS SDP Offer/Answer Signaling

## Purpose

Provide bounded, privacy-safe, deterministic IMS SDP Offer/Answer signaling
evidence by associating accepted SIP session attempts and independent dialog
branches with independently parsed SDP messages.

## Scope

- Anchor an initial INVITE attempt through the accepted IMS Session
  `initial_invite_event_reference`.
- Associate an SDP message with a SIP Event only through exact, capture-scoped
  source-reference equality, plus frame and message-occurrence equality.
- Publish `INITIAL_INVITE_SDP_OFFER` when an accepted initial INVITE carries an
  accepted SDP offer.
- Publish `INITIAL_INVITE_OFFER_ANSWER` when an accepted final 2xx response on
  the same branch carries an accepted SDP message.
- Keep each accepted forked branch separate and never assign one branch's
  answer to another.
- Publish `LATE_OFFER_ANSWER` for an accepted 2xx SDP offer answered by the
  same branch's accepted SDP-bearing 2xx ACK.
- Preserve 18x SDP as `PROVISIONAL_SDP_UNINTERPRETED`.
- Preserve PRACK, re-INVITE, UPDATE, INFO and other SDP-bearing in-dialog
  messages as `OUT_OF_SCOPE`.
- Fail closed on mismatched capture, frame or occurrence metadata, missing
  source events, duplicate references and competing candidates.

## Non-Goals

This Skill must not determine:

- SDP negotiation compatibility, codec agreement, hold state or media
  direction correctness;
- media delivery, RTP flow, two-way audio, early media or QoS;
- call success, call failure, VoLTE service success or subscriber reachability;
- SIP transaction matching, dialog identity construction or fork resolution;
- session modification through re-INVITE, UPDATE or PRACK;
- subscriber identity bridging or cross-protocol association;
- root cause, implementation blame or end-to-end IMS diagnosis.

## Inputs

Required, same capture, accepted artifacts:

1. SIP Event JSONL (`sip` event schema version `1.0.0`).
2. IMS Session Analysis JSON (`ims-session` analysis version `0.1.0`).
3. SDP Analysis JSON (`sdp-rtp` analysis version `0.1.0`, event schema `1.0.0`).

The Domain rejects unsupported versions, duplicate references, cross-capture
joins, missing source events, IMS Session event SHA-256 mismatch and any SDP
provenance disagreement: root capture identity, root capture SHA-256 syntax,
per-message `capture_file`, per-message `capture_sha256`, frame number, message
occurrence, source-reference components, frame references of the form
`frame-<n>`, root/message counts and parser version. Contradictory provenance is
rejected before any output is written.

The SIP Event contract does not publish an independent capture SHA-256, so this
Domain never asserts a cross-artifact capture-hash equality. The SIP Event file
SHA-256 and the capture SHA-256 are different identities and are never equated.
It uses exact SIP Event references, frame metadata, message occurrence and
capture identity.

## Outputs

`schemas/ims-media-signaling-analysis.schema.json` (analysis version `0.2.0`):

- `exchanges`: attempt, transaction and dialog branch references, branch
  identity status, exchange type, `initial_sdp_state`, association status,
  offer/answer event and SDP references, roles, `negotiation_compatibility =
  NOT_EVALUATED`, missing evidence, conflict findings and `evidence_class =
  DERIVED`;
- `unbound_observations`: provisional, out-of-scope, unbound and unmatched
  observations with bounded reason codes;
- `completeness`: conservation-checked counts;
- `input_provenance`, `limitations` and `not_confirmed`.

No raw SDP body, raw SIP body, Call-ID, URI, tag, subscriber identity, IP
address, ICE credential, fingerprint or key material is published.

## Dependencies

- Required: `sip >= 0.4.0`, `sdp-rtp >= 0.3.0`, `ims-session >= 0.1.0`.
- Optional: none.
- The Skill is independently downloadable. It never modifies the accepted SIP,
  SDP, IMS Session or unified workflow contracts.

## Workflow

1. Load the three accepted artifacts.
2. Verify schema versions, capture identity, SDP internal provenance, IMS
   Session event SHA-256 and full SIP Event reference resolution.
3. Classify the initial SDP evidence as `ABSENT`, `OBSERVED_VALID`,
   `OBSERVED_INCOMPLETE`, `OBSERVED_INVALID`, `UNRESOLVED` or `OUT_OF_SCOPE`.
4. Index SDP messages by their exact source references.
5. Build initial INVITE offer evidence and branch-scoped answer evidence only
   through accepted Dialog and branch identity.
6. Build late-offer and 2xx ACK answer evidence only after proven initial SDP
   absence.
7. Preserve provisional and out-of-scope SDP observations without promotion.
8. Validate conservation and privacy, then write deterministic JSON and an
   optional text report.

## Evidence Rules

- `OBSERVED`: accepted SIP Event and SDP message evidence owned by lower layers.
- `DERIVED`: the association itself.
- An established branch-scoped pair requires an accepted attempt, an accepted
  branch of that attempt, a non-null branch reference, a non-null Confirmed
  Dialog reference, `identity_status = ESTABLISHED`, branch-owned response
  evidence, exact SIP-to-SDP reference identity and no competing branch owner.
- Missing Dialog or branch identity is `INSUFFICIENT_EVIDENCE`; conflicting
  ownership is `AMBIGUOUS`. Neither is promoted to a confirmed branch.
- Initial SDP absence is only `ABSENT` when the INVITE has no body, zero content
  length, complete extraction and no contradictory SDP message.
- Unusable initial SDP evidence publishes
  `INITIAL_INVITE_SDP_EVIDENCE_UNUSABLE`; it never becomes
  `INITIAL_INVITE_WITHOUT_SDP` and never enables a late offer.
- Provisional SDP in the same branch keeps the final-response answer role
  unresolved (`PROVISIONAL_FINAL_SDP_ROLE_UNRESOLVED`) and the pair unestablished.
- A final-answer candidate must be a `RESPONSE` with valid 2xx status,
  `headers.cseq.method = INVITE`, complete extraction and the accepted branch
  that owns it.
- An offer/answer pair never means negotiation compatibility.
- A missing ACK or missing answer is missing evidence, not a SIP timeout or a
  call failure.
- Competing candidates are `AMBIGUOUS`; no candidate is selected arbitrarily.

## Failure Handling

Missing, malformed, duplicate or contradictory inputs return a non-zero exit
and never an empty successful analysis. A valid capture with no SDP offer
publishes `INITIAL_INVITE_WITHOUT_SDP` only when the absence is proven;
otherwise it publishes `INITIAL_INVITE_SDP_EVIDENCE_UNUSABLE`.

## Validation

```bash
python3 -m unittest discover -s skills/domain/ims-media-signaling/tests -p 'test_*.py' -v
python3 scripts/validate-ims-media-signaling.py
```

The tests cover the required 70-case matrix, privacy, capture provenance,
branch identity, initial SDP absence versus unusable evidence, provisional
role ambiguity, bounded output, deterministic replay and committed expected
outputs.

## References

- `references/offer-answer-procedures.md`
- `references/evidence-model.md`
- `references/failure-cases.md`
- `references/privacy.md`