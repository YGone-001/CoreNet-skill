# Real SIP/IMS capture acceptance workflow

This workflow is read-only and privacy-preserving. It never retrieves subscriber
credentials or authentication vectors and never publishes raw capture content.

## Authorization gate

Before any replay, the owner of the capture must provide:

- the exact absolute PCAP/PCAPNG path;
- explicit authorization to read that file for this analysis;
- confirmation that the capture may be analyzed.

The mere existence of a capture directory is not authorization. Do not scan arbitrary
directories, capture live traffic automatically or request Cx/Dx credentials and
subscriber data. A SIP-only capture cannot validate Diameter Cx/Dx analysis; a
separate authorized capture is required for Diameter.

When no capture is authorized, record `REAL_PCAP_BLOCKED_INPUT_AUTHORIZATION`. Source
corrections and synthetic gates may still be accepted, but the result is
`IMPLEMENTATION_ACCEPTED / LIVE_ACCEPTANCE_PENDING`, not production-ready.

## Reproducible read-only replay

Run all commands from the repository root. Keep generated artifacts in a temporary
directory outside the working tree.

```bash
sha256sum /authorized/path/capture.pcapng
tshark --version

rm -rf /tmp/ims-acceptance && mkdir -p /tmp/ims-acceptance

python3 skills/protocol/sip/scripts/extract-sip.py \
  /authorized/path/capture.pcapng \
  --output /tmp/ims-acceptance/sip-events.jsonl \
  --transaction-output /tmp/ims-acceptance/sip-transactions.json

python3 skills/domain/ims-registration/scripts/analyze-ims-registration.py \
  --sip-input /tmp/ims-acceptance/sip-events.jsonl \
  --output /tmp/ims-acceptance/registration.json \
  --report /tmp/ims-acceptance/registration.txt
```

Repeat the two producers into a second directory and compare bytes to prove
deterministic replay:

```bash
cmp /tmp/ims-acceptance/sip-events.jsonl /tmp/ims-acceptance-2/sip-events.jsonl
cmp /tmp/ims-acceptance/registration.json /tmp/ims-acceptance-2/registration.json
```

Validate the produced JSON with the frozen Domain schema and the producer's semantic
validator (the repository validator shows the exact call). Never validate only the
text report.

## Recorded facts

The acceptance record includes:

- capture SHA-256, TShark version and transport types;
- IPv4/IPv6 observations and SIP message count;
- REGISTER request, transaction and registration-attempt counts;
- 401/407 counts and Challenge→Retry associations;
- 2xx and negative registration responses;
- de-registration requests and transaction-bound outcomes;
- Contact expiration aggregate metadata and boundary status;
- source event, transaction and timeline references;
- missing, ambiguous or truncated evidence;
- schema, semantic and privacy validation results;
- deterministic replay result.

Raw Call-ID, SIP URIs, Contact URIs, tags, identities and credentials are never
published. Real captures and generated reports stay outside Git.

## Scenario classification

Each operational scenario observed with matching evidence is classified as:

- `OBSERVED_AND_VERIFIED`
- `OBSERVED_BUT_UNRESOLVED`
- `NOT_OBSERVED_IN_CAPTURE`
- `NOT_TESTED`
- `UNSUPPORTED`

A scenario absent from the capture stays a coverage limitation and is never fabricated.
One capture is not required to contain initial registration, 401 and 407 challenges,
refresh, Contact-specific de-registration, wildcard de-registration, rejection,
incomplete sequences and multi-hop REGISTER observations together.

## Remaining unsupported cases

- No registrar binding-state database, so a SIP 2xx to a removal request is not proof
  of persistent binding deletion.
- Encrypted SIP is not decrypted; absence of plaintext evidence is not absence of
  traffic.
- No SIP-to-Diameter subscriber identity bridge; Cx/Dx results stay independent.
- A capture boundary cannot prove that an unobserved final response timed out.