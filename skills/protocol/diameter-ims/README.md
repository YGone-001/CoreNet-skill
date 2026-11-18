# Diameter IMS Protocol Skill

Bounded, privacy-safe Diameter IMS Cx/Dx application-message evidence over
accepted `diameter-core` events and transactions.

The Skill recognizes the Cx/Dx Application-ID 16777216 command families
UAR/UAA, SAR/SAA, LIR/LIA, MAR/MAA, RTR/RTA and PPR/PPA. It publishes reviewed
AVP presence, occurrence counts and decoder-proven grouped structure, keeps base
`Result-Code` and 3GPP `Experimental-Result` namespaces separate, and always
publishes `interface_identity = UNPROVED` because Cx and Dx share the same
application semantics.

It does not prove IMS registration, subscriber authentication, HSS
authorization, S-CSCF assignment, media delivery or call success. It does not
implement Sh, Rx or charging procedures, and it never publishes subscriber
identities, public identities, user data, authentication vectors or keying
material.

```bash
python3 skills/protocol/diameter-ims/scripts/analyze-diameter-ims.py \
  --events skills/protocol/diameter-ims/examples/core/events.jsonl \
  --transactions skills/protocol/diameter-ims/examples/core/transactions.json \
  --output /tmp/diameter-ims-analysis.json \
  --timeline-output /tmp/diameter-ims-timeline.txt \
  --force
```

See `SKILL.md`, `references/standards.md`, `references/commands.md`,
`references/avp-reference.md`, `references/evidence-model.md`,
`references/privacy.md` and `references/failure-cases.md`.