# SIP Protocol Skill

Bounded, privacy-safe SIP message extraction over UDP and TCP from captures,
stored PDML dissections or sanitized dissector records.

The extractor publishes SIP requests and responses with source-frame provenance,
transport metadata, reviewed header facts and explicit completeness
classifications. It does not correlate transactions or dialogs and does not assign
IMS registration or call semantics.

```bash
python3 skills/protocol/sip/scripts/extract-sip.py \
  skills/protocol/sip/examples/pdml/base-udp.pdml \
  --output /tmp/sip-events.jsonl \
  --trace-output /tmp/sip-trace.jsonl \
  --force
```

See `SKILL.md`, `references/field-reference.md`, `references/privacy.md` and
`references/failure-cases.md`.