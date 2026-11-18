# Application evidence model

## Separation of dimensions

The document keeps three independent axes:

| Axis | Values | Meaning |
| --- | --- | --- |
| `message_status` | `OBSERVED`, `KNOWN_UNSUPPORTED`, `CONFLICTING` | whether the reviewed Cx/Dx command and Application-ID were interpreted |
| `transaction_status` | `MATCHED`, `OPEN_REQUEST`, `RESPONSE_ONLY`, `AMBIGUOUS` | the accepted Diameter Core correlation result |
| `application_result` | `SUCCESS_REPORTED`, `FAILURE_REPORTED`, `UNRESOLVED`, `NOT_APPLICABLE` | what the observed Diameter result namespace reports |

No axis overrides another. `OBSERVED + MATCHED + SUCCESS_REPORTED` is the
strongest protocol-local combination and still proves no IMS procedure outcome.

## Message identity

Each observation publishes:

- the reviewed command code and command name;
- the observed request/answer name when the command is interpreted;
- the Diameter Core transaction reference;
- request and answer projections with exact frame, occurrence, direction,
  Application-ID, Hop-by-Hop and End-to-End identifiers, and endpoints;
- candidate references for an `AMBIGUOUS` transaction.

The observation reference is derived from the anchor frame and occurrence
(request when present, otherwise answer). It is deterministic and replay-stable.

## Provenance rules

- The analysis consumes exactly one capture.
- Every referenced event must resolve to a supplied Diameter Core event and
  agree on direction, command code, Application-ID, Hop-by-Hop identifier and
  End-to-End identifier.
- Every Cx/Dx event must be represented by a supplied transaction. Missing
  coverage is rejected; no synthetic transaction is created.
- A non-`MATCHED` transaction publishes only the request or answer the Core
  accepted, never an invented counterpart.
- Latency is published only for `MATCHED` transactions, exactly as accepted from
  Diameter Core.

## AVP presence

Each reviewed AVP publishes:

- code, reviewed name and expected Vendor-ID;
- occurrence count across the published Core AVP subset;
- one of `PRESENT`, `PRESENT_REDACTED`, `PRESENT_STRUCTURE_ONLY`,
  `NOT_OBSERVED` or `NOT_OBSERVED_IN_PUBLISHED_SUBSET`;
- sensitivity and grouped classification;
- decoder-reported grouping status;
- whether grouped child structure is proven;
- reviewed enumerated values only where the vocabulary permits them;
- direct child summaries when the parent structure is proven.

`NOT_OBSERVED_IN_PUBLISHED_SUBSET` is used when Diameter Core reported omitted
AVPs. It is not proof that the AVP was absent from the message.

Repeated occurrences increment the occurrence count. A repeated grouped parent
publishes children from the first proven occurrence and preserves the Core child
omission count.

## Result evidence

The result object preserves every Core base and experimental result entry,
including AVP references where the Core supplied them. It publishes:

- `core_result_status` (`MISSING`, `SINGLE_BASE`, `SINGLE_EXPERIMENTAL`,
  `CONFLICTING`, `DUPLICATE`);
- `namespace_status` (`BASE_RFC6733`, `3GPP_TS_29_229_EXPERIMENTAL`,
  `UNKNOWN_VENDOR_EXPERIMENTAL`, `MISSING`, `CONFLICTING`);
- the selected reviewed base or experimental code and name, or null when the
  evidence is conflicting, duplicated or unreviewed;
- separate arrays for base and experimental result evidence.

Conflicting or duplicated result evidence is never collapsed into one value.

## Interface identity

`interface_identity` is always `UNPROVED` with an empty basis. No input field in
this Skill supplies trusted Cx-versus-Dx metadata. Application-ID, command code,
port, hostname, Origin-Host, IP address and ordering are not used as interface
identity evidence.

## Completeness

The `completeness` object publishes observation counts, omitted observations,
Cx/Dx event and transaction counts, events with AVP omissions, truncated
observations, unsupported observations, conflicting observations and
observations with unproven grouped structure. These are counts, not verdicts.