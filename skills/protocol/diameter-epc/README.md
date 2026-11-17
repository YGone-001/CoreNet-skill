# Diameter EPC — Operational Guide

## Purpose

Turn accepted Diameter Core events and transactions into bounded S6a/S6d
application evidence for Authentication-Information (AIR/AIA) and
Update-Location (ULR/ULA). The Skill never emits an EPS Attach or UE
authentication verdict.

## Requirements

- Accepted `diameter-core` output.
- Python 3.10 or later.
- `jsonschema` only for the optional local schema tests; CI installs it.

## Produce Core output

```bash
python3 skills/protocol/diameter-core/scripts/extract-diameter-core.py \
  /path/to/capture.pcapng \
  --output /tmp/corenet-diameter-epc/events.jsonl \
  --trace-output /tmp/corenet-diameter-epc/trace.jsonl

python3 skills/protocol/diameter-core/scripts/correlate-diameter-core.py \
  /tmp/corenet-diameter-epc/events.jsonl \
  --output /tmp/corenet-diameter-epc/transactions.json \
  --timeline-output /tmp/corenet-diameter-epc/core-timeline.txt
```

## Analyze application evidence

```bash
python3 skills/protocol/diameter-epc/scripts/analyze-diameter-epc.py \
  --events /tmp/corenet-diameter-epc/events.jsonl \
  --transactions /tmp/corenet-diameter-epc/transactions.json \
  --output /tmp/corenet-diameter-epc/epc-analysis.json \
  --timeline-output /tmp/corenet-diameter-epc/epc-timeline.txt
```

`--force` is required to replace existing outputs. Outputs may not overwrite an
input artifact.

## Supported commands

| Command | Request/Answer | Scope |
| --- | --- | --- |
| 318 | AIR/AIA | bounded authentication-information evidence |
| 316 | ULR/ULA | bounded message/result/presence evidence |
| 317 | CLR/CLA | recognized, detailed semantics unsupported |
| 319 | IDR/IDA | recognized, detailed semantics unsupported |
| 320 | DSR/DSA | recognized, detailed semantics unsupported |
| 321 | NOR/NOA | recognized, detailed semantics unsupported |
| 322 | PUR/PUA | recognized, detailed semantics unsupported |
| 323 | RSR/RSA | recognized, detailed semantics unsupported |

Application-ID 16777251 is the S6a/S6d common application. Commands on other
Application-IDs are never classified as S6a/S6d. The Skill never infers S6a
versus S6d interface identity.

## Output interpretation

The analysis keeps four independent dimensions:

- `message_status`: OBSERVED, UNSUPPORTED, INSUFFICIENT.
- `transaction_status`: MATCHED, OPEN_REQUEST, RESPONSE_ONLY, AMBIGUOUS.
- `application_result`: SUCCESS_REPORTED, FAILURE_REPORTED, UNRESOLVED,
  NOT_APPLICABLE.
- `authentication_information`: PRESENT_REDACTED, NOT_OBSERVED,
  NOT_OBSERVED_IN_PUBLISHED_SUBSET, UNAVAILABLE, INCOMPLETE, NOT_APPLICABLE.

`MATCHED + SUCCESS_REPORTED + PRESENT_REDACTED` does not prove that
authentication vectors are usable, that the UE authenticated, or that EPS Attach
succeeded.

## Result namespaces

- Base Result-Code 5001 is `DIAMETER_AVP_UNSUPPORTED` (RFC 6733).
- 3GPP Vendor-ID 10415 Experimental-Result-Code 5001 is
  `DIAMETER_ERROR_USER_UNKNOWN`.
- The same numeric value in different namespaces never shares a name.
- An unknown vendor or missing Vendor-ID receives no 3GPP meaning.
- Simultaneous base and experimental results are `CONFLICTING` and unresolved.
- Core result arrays retain AVP provenance; duplicate results are not collapsed
  into an arbitrary success.

Presence is matched by exact reviewed namespace: base User-Name/Session-Id cannot
be satisfied by an unknown vendor Code 1/263, and 3GPP AVPs require Vendor-ID
10415.

## Privacy

Subscriber identity, authentication vectors, RAND, AUTN, XRES, KASME,
Subscription-Data contents and Session-Id values are never published. AVPs are
reported as presence, structural status, value kind and redaction only.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Analysis written |
| 2 | Invalid, inconsistent or unresolved Core input |
| 3 | No supported or recognized S6a/S6d evidence |
| 6 | Output destination failure |

## Limitations

- Authentication-information children and vector counts are not inferred from a
  redacted parent.
- ULA Subscription-Data is presence-only.
- ULR/ULA does not reconstruct mobility, registration or subscription state.
- AIR without AIA remains open at the capture boundary; it is not a timeout.
- Cross-protocol joins are not implemented.
- Clause-level TS 29.272 content is not embedded; see
  `references/standards.md` for the exact release and decoder verification
  boundary.