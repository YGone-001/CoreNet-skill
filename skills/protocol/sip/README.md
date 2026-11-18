# SIP Protocol Skill

Bounded, privacy-safe SIP message extraction over UDP and TCP from captures,
stored PDML dissections or sanitized dissector records.

The extractor publishes SIP requests and responses with source-frame provenance,
transport metadata, reviewed header facts and explicit completeness
classifications. It correlates requests and responses at the RFC 3261 transaction
layer, distinguishes magic-cookie and legacy Via matching, validates CANCEL and ACK
header consistency with fail-closed required-field eligibility, separates observed
evidence status from RFC 3261/RFC 6026 state, and reports retransmission confidence.
It also derives bounded, privacy-safe INVITE dialog evidence: capture-scoped Early
and Confirmed branches, forked dialog isolation, 2xx ACK association, in-dialog
request association, direction-specific CSeq observations and BYE lifecycle
signaling. Every bounded reference collection publishes conservation accounting with
observed unique, published and omitted counts. It does not assign IMS registration,
authentication or call semantics.

```bash
python3 skills/protocol/sip/scripts/extract-sip.py \
  skills/protocol/sip/examples/pdml/base-udp.pdml \
  --output /tmp/sip-events.jsonl \
  --transaction-output /tmp/sip-transactions.json \
  --dialog-output /tmp/sip-dialogs.json \
  --trace-output /tmp/sip-trace.jsonl \
  --force
```

See `SKILL.md`, `references/field-reference.md`, `references/transactions.md`,
`references/dialogs.md`, `references/privacy.md` and
`references/failure-cases.md`.