# SIP Protocol Skill

Bounded, privacy-safe SIP message extraction over UDP and TCP from captures,
stored PDML dissections or sanitized dissector records.

The extractor publishes SIP requests and responses with source-frame provenance,
transport metadata, reviewed header facts and explicit completeness
classifications. It correlates requests and responses at the RFC 3261 transaction
layer, distinguishes magic-cookie and legacy Via matching, validates CANCEL and ACK
header consistency, separates observed evidence status from RFC 3261/RFC 6026 state,
and reports retransmission confidence. It does not correlate SIP dialogs and does not
assign IMS registration, authentication or call semantics.

```bash
python3 skills/protocol/sip/scripts/extract-sip.py \
  skills/protocol/sip/examples/pdml/base-udp.pdml \
  --output /tmp/sip-events.jsonl \
  --transaction-output /tmp/sip-transactions.json \
  --trace-output /tmp/sip-trace.jsonl \
  --force
```

See `SKILL.md`, `references/field-reference.md`, `references/transactions.md`,
`references/privacy.md` and `references/failure-cases.md`.