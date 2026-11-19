# IMS Session Domain Skill

Bounded, privacy-safe evidence analysis of IMS session establishment and release
signaling from already-extracted SIP Event, Transaction and Dialog artifacts.

The analyzer anchors each session attempt to an initial INVITE transaction, preserves
provisional and final response stages, keeps forked Early and Confirmed Dialog branches
independent, separates 2xx and non-2xx ACK evidence, separates CANCEL request/response/
association from the INVITE final response, and records BYE release signaling. It does
not claim call success, media delivery, two-way audio, RTP, QoS or session modification.

## Inputs

All three artifacts must belong to one capture:

- SIP Event JSONL (`sip` event schema `1.0.0`)
- SIP Transaction JSON (`sip-transactions` `1.1.0`)
- SIP Dialog JSON (`sip-dialogs` `1.1.0`)

## Usage

```bash
python3 skills/domain/ims-session/scripts/analyze-ims-session.py \
  --sip-events skills/domain/ims-session/examples/inputs/session-cases-events.jsonl \
  --sip-transactions skills/domain/ims-session/examples/inputs/session-cases-transactions.json \
  --sip-dialogs skills/domain/ims-session/examples/inputs/session-cases-dialogs.json \
  --output /tmp/ims-session.json \
  --report /tmp/ims-session.txt \
  --force
```

## Output interpretation

Keep these dimensions separate:

- INVITE outcome: accepted 2xx, negative final, provisional-only, no response or
  incomplete evidence.
- Dialog identity and state: Early, Confirmed, Terminated or unresolved.
- ACK evidence: observed for all accepted branches, missing for an accepted branch or
  not applicable.
- CANCEL evidence: request, response, association and INVITE final response remain
  separate.
- Release evidence: BYE request, response, missing response or negative response.
- Capture completeness: complete or partial; missing evidence is never timeout proof.

## Limitations

The Skill consumes only accepted SIP protocol evidence. It does not decode packets,
reconstruct transactions or dialogs, interpret SDP, inspect RTP, correlate Diameter Rx/
Sh/charging, or link registration and session identities. Real-capture operational
acceptance remains a separate authorized activity.

See `SKILL.md`, `references/session-procedures.md`,
`references/evidence-model.md`, `references/failure-cases.md` and
`references/privacy.md`.