# Diameter EPC

## Purpose

Provide bounded S6a/S6d application-message evidence on top of accepted
`diameter-core` events and transactions. The Skill answers what S6a/S6d message
and result the capture actually shows. It does not answer whether the UE
authenticated, whether EPS Attach succeeded, or whether the subscriber is
authorized.

## Scope

- Authentication-Information request/answer (Command Code 318) under
  Application-ID 16777251: bounded AIR/AIA message identity, presence-only
  authentication-information evidence, base and 3GPP experimental result
  classification, provenance and limitations.
- Update-Location request/answer (Command Code 316) under Application-ID
  16777251: message identity, base and 3GPP experimental result classification,
  and presence-only location/subscription AVP evidence.
- Recognition of S6a/S6d command codes 317, 319, 320, 321, 322 and 323 as
  `KNOWN_UNSUPPORTED`; they are not malformed and receive no detailed semantics.
- Numeric preservation of every Application-ID and Command Code.
- Independent dimensions for message status, Core transaction status,
  application result and authentication-information availability.
- Exact frame/occurrence provenance and source references back to Diameter Core.

## Non-Goals

- No Diameter base-header parsing, AVP structural extraction, TCP/SCTP
  association reconstruction, Hop-by-Hop pairing or base result-name decoding.
- No raw PCAP requirement; input is accepted Diameter Core output.
- No EPS Attach, EMM registration, UE authentication, HSS authorization,
  context installation or network-access verdict.
- No subscriber identity, IMSI, RAND, AUTN, XRES, KASME or authentication-vector
  publication.
- No Gx, Rx, Cx, credit-control, Diameter IMS, charging or SIP semantics.
- No S6a-versus-S6d interface inference from Application-ID, port or hostname.
- No cross-protocol join to NAS-EPS, GTPv2-C, SIP/IMS or charging evidence.

## Inputs

- Diameter Core event JSONL (`diameter-event.schema.json` records).
- Diameter Core transaction JSON (`diameter-transaction.schema.json` document).

The analysis rejects inconsistent inputs: multiple captures, capture mismatch,
duplicate event identity, unresolved references, reference/event disagreement,
and invalid status/latency invariants.

## Outputs

- Application analysis JSON validated by
  `schemas/diameter-epc-analysis.schema.json`.
- Human-readable application timeline.

## Independent evidence dimensions

```text
message_status:
  OBSERVED | UNSUPPORTED | INSUFFICIENT

transaction_status:
  MATCHED | OPEN_REQUEST | RESPONSE_ONLY | AMBIGUOUS

application_result:
  SUCCESS_REPORTED | FAILURE_REPORTED | UNRESOLVED | NOT_APPLICABLE

authentication_information:
  PRESENT_REDACTED | NOT_OBSERVED | NOT_OBSERVED_IN_PUBLISHED_SUBSET |
  UNAVAILABLE | INCOMPLETE | NOT_APPLICABLE
```

A combination such as `MATCHED + SUCCESS_REPORTED + PRESENT_REDACTED` means only
that a paired AIA reported protocol success and that authentication-information
presence was observed under redaction. It does not prove usable vectors, UE
authentication, EPS Attach or network service.

## Result namespaces

Base `Result-Code` uses RFC 6733 semantics. A 3GPP `Experimental-Result` requires
Vendor-ID 10415 and a reviewed TS 29.272 code. Identical numeric values in the two
namespaces never share a name. Conflicting simultaneous base and experimental
results remain `CONFLICTING` and unresolved.

## Privacy

All subscriber, subscription and authentication values remain redacted or
presence-only. The Skill never weakens Diameter Core privacy. If AVP publication
was truncated, absence is reported as `NOT_OBSERVED_IN_PUBLISHED_SUBSET`, not as
proven absence.

## Interface identity

Application-ID 16777251 is the common S6a/S6d application. The Skill publishes
`interface_identity = UNPROVED`; it never infers MME versus SGSN from identifiers,
ports or hostnames.

## Limitations

- Clause-level TS 29.272 PDF content was not downloaded; the exact ETSI release
  document is identified in `references/standards.md`, while AVP names and result
  codes were verified against the TShark 4.2.2 decoder tables.
- Authentication-information grouped AVPs are usually redacted by Diameter Core;
  child count and vector contents are not inferred.
- Subscription-Data is presence-only; profile contents are unavailable.
- An unanswered AIR is not a timeout.
- S6a/S6d interface identity remains unproved.
- Detailed semantics for command codes 317, 319, 320, 321, 322 and 323 are not
  implemented.

## Provenance

Original CoreNet Protocol-layer package. No upstream implementation imported.
Normative basis: 3GPP TS 29.272, 3GPP TS 29.230, RFC 6733, IANA registries and the
reviewed Wireshark/TShark 4.2.2 decoder definitions.