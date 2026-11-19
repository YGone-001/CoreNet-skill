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
joins, missing source events, IMS Session event SHA-256 mismatch and SDP
provenance that disagrees with the SIP Event capture identity.

The SIP Event contract does not publish an independent capture SHA-256, so this
Domain never asserts a cross-artifact capture-hash equality. It uses exact SIP
Event references, frame metadata, message occurrence and capture identity.

## Outputs

`schemas/ims-media-signaling-analysis.schema.json`:

- `exchanges`: attempt, transaction and dialog branch references, exchange
  type, association status, offer/answer event and SDP references, roles,
  `negotiation_compatibility = NOT_EVALUATED`, missing evidence, conflict
  findings and `evidence_class = DERIVED`;
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
2. Verify schema versions, capture identity, IMS Session event SHA-256 and full
   SIP Event reference resolution.
3. Index SDP messages by their exact source references.
4. Build initial INVITE offer evidence and branch-scoped answer evidence.
5. Build late-offer and 2xx ACK answer evidence on accepted branches.
6. Preserve provisional and out-of-scope SDP observations without promotion.
7. Validate conservation and privacy, then write deterministic JSON and an
   optional text report.

## Evidence Rules

- `OBSERVED`: accepted SIP Event and SDP message evidence owned by lower layers.
- `DERIVED`: the association itself.
- An offer/answer pair means the expected signaling positions and exact source
  references were observed. It never means negotiation compatibility.
- Provisional SDP is preserved, never promoted to a completed reliable
  provisional exchange.
- A missing ACK or missing answer is missing evidence, not a SIP timeout or a
  call failure.
- Competing candidates are `AMBIGUOUS`; no candidate is selected arbitrarily.

## Failure Handling

Missing, malformed, duplicate or contradictory inputs return a non-zero exit
and never an empty successful analysis. Valid captures with no SDP offer remain
valid analyses that publish an explicit `INITIAL_INVITE_WITHOUT_SDP` or
`NOT_ESTABLISHED` exchange.

## Validation

```bash
python3 -m unittest discover -s skills/domain/ims-media-signaling/tests -p 'test_*.py' -v
python3 scripts/validate-ims-media-signaling.py
```

The tests cover the required 54-case matrix, privacy, capture provenance,
bounded output, deterministic replay and committed expected outputs.

## References

- `references/offer-answer-procedures.md`
- `references/evidence-model.md`
- `references/failure-cases.md`
- `references/privacy.md`