# IMS Registration Domain Skill

Bounded, privacy-safe evidence analysis of IMS registration signaling from
already-extracted SIP and optional Diameter IMS Cx/Dx protocol evidence.

The analyzer inventories SIP REGISTER transactions, groups evidence-supported
registration attempts, preserves 401/407 challenges and authorized retries,
distinguishes initial registration, re-registration, refresh and de-registration
observations, classifies negative SIP responses, retains independent Cx/Dx
observations, and fails closed on cross-protocol subscriber identity association.
All-bindings removal requires exactly one sole RFC 3261 wildcard `Contact: *` with
`Expires: 0`; mixed or duplicate wildcard values and unresolved raw Contact boundaries
fail closed. A supplied Contact targeted by `expires=0` remains Contact-scoped, a
Contact-specific expiration overrides the default `Expires` header, and `Expires: 0`
without a Contact does not establish de-registration. Each removal observation is bound to its own
REGISTER transaction and final response. A Challenge→Retry association requires a
later authorized REGISTER after the observed challenge response in capture-local
evidence order. Bounded publications conserve total/published/omitted counts, cross-source
SIP/Diameter rows remain source-local unless common capture provenance is verified,
and CLI output destinations cannot alias inputs or each other. The Skill does not
analyze IMS sessions, media, SDP, RTP, Rx, Sh or call outcomes.

```bash
python3 skills/domain/ims-registration/scripts/analyze-ims-registration.py \
  skills/domain/ims-registration/examples/input/registration-cases.jsonl \
  --output /tmp/ims-registration.json \
  --report /tmp/ims-registration.txt \
  --force
```

Optional Diameter evidence:

```bash
python3 skills/domain/ims-registration/scripts/analyze-ims-registration.py \
  skills/domain/ims-registration/examples/input/registration-cases.jsonl \
  --diameter-ims skills/domain/ims-registration/examples/input/diameter-ims-cases.json \
  --output /tmp/ims-registration.json \
  --force
```

See `SKILL.md`, `references/registration-procedures.md`,
`references/authentication-evidence.md`, `references/diameter-context.md`,
`references/evidence-model.md`, `references/privacy.md`,
`references/failure-cases.md` and `references/real-pcap-acceptance.md`.