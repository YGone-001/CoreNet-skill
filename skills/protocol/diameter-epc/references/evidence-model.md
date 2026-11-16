# Evidence model and invariants

## Independent dimensions

```text
message_status              OBSERVED | UNSUPPORTED | INSUFFICIENT
transaction_status          MATCHED | OPEN_REQUEST | RESPONSE_ONLY | AMBIGUOUS
application_result          SUCCESS_REPORTED | FAILURE_REPORTED | UNRESOLVED | NOT_APPLICABLE
authentication_information  PRESENT_REDACTED | NOT_OBSERVED |
                            NOT_OBSERVED_IN_PUBLISHED_SUBSET | UNAVAILABLE |
                            INCOMPLETE | NOT_APPLICABLE
```

The dimensions are never collapsed into one success flag.

## Provenance

Every observation carries:

- `observation_reference` derived from the anchor frame and message occurrence;
- request and/or answer `event_reference`;
- exact frame number and message occurrence;
- the accepted Core `transaction_reference`;
- the Core `transaction_status` and established latency only for `MATCHED`.

## Core pairing

The Skill never creates a Request/Answer pair. `OPEN_REQUEST`,
`RESPONSE_ONLY`, `AMBIGUOUS` and `INSUFFICIENT` remain explicit. A Core
`MATCHED` transaction is protocol-local pairing evidence only.

## Application evidence rules

- AIR with a valid AIA pair reports request presence and answer result separately.
- An answer-only AIA remains `RESPONSE_ONLY`.
- An open AIR remains `OPEN_REQUEST`; it is not a timeout.
- An ambiguous Core transaction retains all candidate references.
- A recognized unsupported command remains `UNSUPPORTED`, not malformed.
- A command on a different Application-ID is not S6a/S6d.

## No unauthorized joins

The Skill emits safe source references for future Domain consumers. It does not
join AIR/AIA to NAS-EPS, EPS Attach, GTPv2-C, SIP/IMS or charging evidence.
Timestamps, subscriber-like values, addresses and network-function assumptions
are never used as procedure identity.