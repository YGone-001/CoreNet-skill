# Failure and insufficient-evidence cases

## Input rejection

- Invalid JSONL or JSON returns exit code 2.
- Missing required event or transaction fields returns exit code 2.
- Events from more than one capture are rejected.
- Transaction `capture_files` that disagree with the event capture are rejected.
- Duplicate event frame/occurrence identity is rejected.
- A transaction reference that does not resolve to a Core event is rejected.
- A reference whose direction, command, application, hop or end-to-end identifier
  disagrees with the event is rejected.
- A MATCHED transaction without both references is rejected.
- An S6a/S6d event without any Core transaction representation is rejected as
  incomplete supplied evidence. No local `diameter-epc-unresolved:` transaction
  is created.
- A non-MATCHED transaction with a selected pair or latency is rejected.
- An AMBIGUOUS transaction without candidate references is rejected.

## No S6a/S6d evidence

If the capture has no supported or recognized S6a/S6d application evidence, the
CLI returns exit code 3. It does not create an empty success.

## Unsupported commands

Command codes 317, 319, 320, 321, 322 and 323 remain `UNSUPPORTED` with exact
frame/occurrence provenance. They are not malformed and are not converted into
S6a failure evidence.

## Missing or truncated evidence

- Missing Result-Code is `MISSING` and `UNRESOLVED`.
- Conflicting base and experimental results are `CONFLICTING` and `UNRESOLVED`.
- A redacted authentication group is `PRESENT_REDACTED`, not a vector success.
- An absent authentication group with omitted AVPs is
  `NOT_OBSERVED_IN_PUBLISHED_SUBSET`, not proven absence.
- Subscription-Data remains presence-only.
- An unanswered AIR is not a timeout.

## Output failure

Existing outputs require `--force`. An output may not overwrite an input artifact.
A missing destination directory returns exit code 6.