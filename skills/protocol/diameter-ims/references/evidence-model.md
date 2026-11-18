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

Each reviewed AVP publishes two names:

- `canonical_name`: the normative 3GPP name from TS 29.229 clause 6.3;
- `name`: the reviewed decoder alias used by the installed Diameter decoder.

For most AVPs the two names are identical. For 606–610 and 612–613 they differ;
the code and Vendor-ID are the stable identity. See `avp-reference.md`.

Each reviewed AVP also publishes:

- code, expected Vendor-ID and sensitivity;
- occurrence count across the published Core AVP subset;
- one of `PRESENT`, `PRESENT_REDACTED`, `PRESENT_STRUCTURE_ONLY`,
  `NOT_OBSERVED` or `NOT_OBSERVED_IN_PUBLISHED_SUBSET`;
- grouped classification and decoder-reported grouping status;
- whether grouped child structure is proven;
- reviewed enumerated values only where the vocabulary permits them;
- direct child summaries, each with both names, when the parent structure is
  proven.

`NOT_OBSERVED_IN_PUBLISHED_SUBSET` is used when Diameter Core reported omitted
AVPs. It is not proof that the AVP was absent from the message.

Repeated occurrences increment the occurrence count. A repeated grouped parent
publishes children from the first proven occurrence and preserves the Core child
omission count.

## Result evidence

Cx/Dx result values are carried inside Experimental-Result with Vendor-ID 10415;
Result-Code is absent when such a value is present (TS 29.229 clause 6.2). The
producer does not require the input to omit Result-Code, but it refuses to merge
the two namespaces when both are supplied.

The result object preserves every Core base and experimental result entry,
including AVP references where the Core supplied them. It publishes:

- `core_result_status` (`MISSING`, `SINGLE_BASE`, `SINGLE_EXPERIMENTAL`,
  `CONFLICTING`, `DUPLICATE`);
- `namespace_status` (`BASE_RFC6733`, `3GPP_TS_29_229_EXPERIMENTAL`,
  `UNKNOWN_VENDOR_EXPERIMENTAL`, `MISSING`, `CONFLICTING`);
- the selected reviewed base or experimental code and name, or null when the
  evidence is conflicting, duplicated or unreviewed;
- separate arrays for base and experimental result evidence.

### Cx success results

Experimental-Result codes 2001–2004 with Vendor-ID 10415 are reviewed Cx success
results. They publish `SUCCESS_REPORTED` and the exact TS 29.229 names
`DIAMETER_FIRST_REGISTRATION`, `DIAMETER_SUBSEQUENT_REGISTRATION`,
`DIAMETER_UNREGISTERED_SERVICE` and `DIAMETER_SUCCESS_SERVER_NAME_NOT_STORED`.
The numeric code and Vendor-ID are preserved.

These values are not RFC 6733 base Result-Code semantics. Base Result-Code
2001/2002 retain their own base-protocol success classification.

### Cx permanent failures

Experimental-Result codes 5001–5009, 5011 and 5012 with Vendor-ID 10415 publish
`FAILURE_REPORTED` and their exact TS 29.229 names.

### Void, reserved and unassigned values

- 2005 is Void in TS 29.229 clause 6.2.1.5 and a Deprecated value in TS 29.230
  table 8.1.2; numeric only, `UNRESOLVED`, no name, never a valid success.
- 2006–2020 is the TS 29.230 table 8.1.2 reserved success range; numeric only,
  `UNRESOLVED`, no name.
- 5010 is Void in TS 29.229 clause 6.2.2.10 and unassigned in TS 29.230 table
  8.1.4; numeric only, `UNRESOLVED`, no name, with an explicit limitation.
- 5013–5020 is the TS 29.230 table 8.1.4 reserved permanent-failure range for
  TS 29.229; numeric only, no name.
- 5021–5040 is reserved for TS 32.299 and is not a Cx/Dx result code; numeric
  only, no Cx/Dx semantics.
- Other unreviewed 3GPP codes and other vendor namespaces remain numeric with no
  semantic name.

Success and permanent-failure reserved ranges are independent and are never
merged. The producer never assigns Cx/Dx semantics to a code inside the
TS 32.299-owned range.

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