# Privacy contract

## Never published

The following values are never published, even when Diameter Core exposes them:

- IMSI, IMPI, IMPU, MSISDN or any Public-Identity value.
- User-Name.
- SIP authentication credentials, RAND, AUTN, XRES, KASME or any
  authentication vector.
- SIP-Authenticate, SIP-Authorization or SIP-Authentication-Context contents.
- Cx-User-Data contents.
- Confidentiality-Key or Integrity-Key contents.
- Reason-Info free text.
- Raw SIP identity or registration state.

## Protected AVP set

The producer treats the following as protected regardless of the Diameter Core
sensitivity flag:

| Code | AVP |
| --- | --- |
| 601 | Public-Identity |
| 606 | Cx-User-Data |
| 609 | 3GPP-SIP-Authenticate |
| 610 | 3GPP-SIP-Authorization |
| 611 | SIP-Authentication-Context |
| 617 | Reason-Info |
| 625 | Confidentiality-Key |
| 626 | Integrity-Key |

A protected AVP is published as `PRESENT_REDACTED` with no value and no reviewed
value, even if the Core input contains a value.

## Permitted publication

For reviewed AVPs the producer may publish only:

- code and reviewed name;
- expected Vendor-ID;
- presence state;
- occurrence count;
- grouped classification and decoder-reported grouping status;
- decoder-proven child code, reviewed child name, child occurrence count and
  child sensitivity;
- reviewed symbolic names for Server-Assignment-Type, Reason-Code,
  User-Authorization-Type and User-Data-Already-Available when the numeric value
  is in the reviewed enumeration and the AVP is not protected or marked
  sensitive.

No other AVP value is published. Server-Name, Visited-Network-Identifier,
Session-Id and other non-protected AVPs publish presence only.

## Derived identifiers

- Observation references derive only from capture file name, frame number and
  message occurrence.
- No subscriber hash, persistent pseudonym or reversible identifier is derived.
- No raw value appears in exceptions, stdout or stderr.

## Truncation

When Diameter Core reports omitted AVPs, an unobserved reviewed AVP is published
as `NOT_OBSERVED_IN_PUBLISHED_SUBSET`, not as proven absence. Grouped structure
that the decoder did not prove is published with `structure_proven: false` and an
empty child array.

## Verification

The validator scans the produced analysis and timeline for reviewed sensitive
markers and raw identity values. Tests assert that protected AVPs never publish a
value and that no forbidden IMS verdict token appears in the output.