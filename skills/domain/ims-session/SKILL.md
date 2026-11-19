# IMS Session

## Purpose

Provide bounded, privacy-safe, deterministic IMS session establishment and release
signaling evidence from already-extracted SIP Event, Transaction and Dialog artifacts.

## Scope

- Anchor one IMS session attempt to one accepted initial INVITE transaction.
- Preserve 100 Trying, tagged 180 Ringing, tagged 183 Session Progress, final response
  and accepted 2xx observations.
- Keep Early and Confirmed Dialog branches independent, including forked 2xx branches.
- Separate 2xx ACK evidence from non-2xx ACK evidence.
- Preserve CANCEL request, CANCEL final response, CANCEL-to-INVITE association and the
  original INVITE final response as separate observations.
- Preserve BYE request, BYE final response, BYE transaction association and dialog
  termination signaling evidence.
- Retain re-INVITE and UPDATE as in-dialog observations without session-modification
  conclusions.
- Fail closed on missing evidence, ambiguous references, inconsistent captures and
  invalid input contracts.

## Non-Goals

This Skill must not determine:

- call success, call failure, VoLTE service success or subscriber reachability;
- media delivery, RTP flow, two-way audio or early-media delivery;
- SDP offer/answer semantics, QoS or session modification;
- IMS registration, authentication or a registration-to-session association;
- SIP transaction matching, dialog identity construction, CANCEL matching or ACK
  matching;
- root cause, implementation blame, network-function role or end-to-end diagnosis.

## Inputs

Required, same capture, accepted artifacts:

1. SIP Event JSONL (`sip` event contract version `1.0.0`).
2. SIP Transaction JSON (`sip-transactions` version `1.1.0`).
3. SIP Dialog JSON (`sip-dialogs` version `1.1.0`).

The Domain rejects unsupported versions, duplicate or missing references,
cross-capture joins, missing source events, malformed transaction or dialog contracts,
and more than one capture identity.

## Outputs

`schemas/ims-session-analysis.schema.json`:

- `session_attempts`: attempt reference, initial INVITE transaction and event
  references, stage evidence, invite outcome, independent branches, ACK evidence,
  CANCEL evidence and release evidence;
- `unbound_observations`: dialog or CANCEL observations without an established
  attempt owner;
- `in_dialog_observations`: re-INVITE/UPDATE with `NOT_INTERPRETED`;
- `completeness`: bounded counts with conservation;
- `input_provenance`, `limitations` and `not_confirmed`.

References are capture-scoped and deterministic. No raw subscriber or SIP identity is
published.

## Dependencies

- Required: `sip >= 0.4.0` Event, Transaction and Dialog artifacts.
- Optional: none.
- The Skill is independently downloadable; no other Domain package is required.

## Workflow

1. Load all three accepted artifacts and verify capture identity.
2. Verify schema versions and reference integrity in both directions.
3. Select initial INVITE transactions without collapsing separate transactions that
   share a Call-ID.
4. Build attempts, independent dialog branches, ACK, CANCEL and BYE observations.
5. Fail closed on unresolved or contradictory evidence.
6. Validate the result and write deterministic JSON and an optional text report.

## Evidence Rules

- `OBSERVED`: accepted source event, transaction or dialog evidence.
- `DERIVED`: deterministic attempt, branch, ACK, CANCEL or release observation.
- Missing evidence is capture incompleteness, never a timeout, failure or negative
  service verdict.
- A Confirmed Dialog is not media delivery.
- A 200 OK to BYE is termination signaling only, not proof that RTP stopped.
- A 200 OK to CANCEL acknowledges the CANCEL transaction only.
- A 2xx INVITE ACK does not prove media delivery.

## Failure Handling

Missing, malformed or contradictory inputs return a non-zero exit and never an empty
successful analysis. The report identifies the missing artifact or reference. A capture
with no INVITE remains a valid zero-attempt session analysis with explicit limitations.

## Validation

```bash
python3 -m unittest discover -s skills/domain/ims-session/tests -p 'test_*.py' -v
python3 scripts/validate-ims-session.py
```

The tests cover the required 36-case matrix, privacy, capture provenance, bounded
output, deterministic replay and committed expected outputs.

## References

- `references/session-procedures.md`
- `references/evidence-model.md`
- `references/failure-cases.md`
- `references/privacy.md`