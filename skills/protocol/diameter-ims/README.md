# Diameter IMS Protocol Skill

Bounded, privacy-safe Diameter IMS Cx/Dx application-message evidence over
accepted `diameter-core` events and transactions.

The Skill recognizes the Cx/Dx Application-ID 16777216 command families
UAR/UAA, SAR/SAA, LIR/LIA, MAR/MAA, RTR/RTA and PPR/PPA. It publishes reviewed
AVP presence with both the normative TS 29.229 name and the decoder alias,
occurrence counts and decoder-proven grouped structure, keeps base `Result-Code`
and 3GPP `Experimental-Result` namespaces separate, and always publishes
`interface_identity = UNPROVED` because Cx and Dx share the same application
semantics.

The Release 19-aligned result handling recognizes Cx Experimental-Result success
codes 2001–2004 (`DIAMETER_FIRST_REGISTRATION`,
`DIAMETER_SUBSEQUENT_REGISTRATION`, `DIAMETER_UNREGISTERED_SERVICE`,
`DIAMETER_SUCCESS_SERVER_NAME_NOT_STORED`) and permanent failures 5001–5009,
5011 and 5012. Code 2005 is Void and Deprecated, and code 5010 is Void and
unassigned; both remain numeric and `UNRESOLVED`. The separate TS 29.230
reserved success range 2006–2020 and reserved permanent-failure range 5013–5020
retain numeric identity and receive no invented names. Codes 5021–5040 are
reserved for TS 32.299 and are not Cx/Dx result codes.

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