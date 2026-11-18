# Diameter IMS

## Purpose

Provide bounded Cx/Dx application-message evidence on top of accepted
`diameter-core` events and transactions. The Skill answers what Cx/Dx message,
reviewed AVP structure and result the capture actually shows. It does not answer
whether the subscriber is registered, authenticated or authorized, whether an
S-CSCF is assigned, or whether IMS service is available.

## Scope

- Application-ID 16777216 (3GPP Cx/Dx) command identity for
  User-Authorization (300), Server-Assignment (301), Location-Info (302),
  Multimedia-Auth (303), Registration-Termination (304) and Push-Profile (305),
  with request/answer names UAR/UAA, SAR/SAA, LIR/LIA, MAR/MAA, RTR/RTA and
  PPR/PPA.
- Reviewed, bounded Cx/Dx AVP presence for the command family actually observed:
  Public-Identity, Server-Name, Server-Capabilities, Mandatory-Capability,
  Optional-Capability, Cx-User-Data, 3GPP-SIP-Number-Auth-Items,
  3GPP-SIP-Authentication-Scheme, 3GPP-SIP-Authenticate,
  3GPP-SIP-Authorization, SIP-Authentication-Context, 3GPP-SIP-Auth-Data-Item,
  3GPP-SIP-Item-Number, Server-Assignment-Type, Deregistration-Reason,
  Reason-Code, Reason-Info, User-Authorization-Type,
  User-Data-Already-Available, Confidentiality-Key, Integrity-Key,
  Supported-Features, Feature-List-ID and Feature-List.
- Decoder-proven grouped AVP child structure for Server-Capabilities,
  3GPP-SIP-Auth-Data-Item, Deregistration-Reason and Supported-Features. Child
  relationships are never inferred from AVP list order.
- Independent dimensions for message status, Diameter Core transaction status
  and application result.
- Separate base `Result-Code` and 3GPP `Experimental-Result` namespaces with
  reviewed TS 29.229 result names.
- Numeric preservation of every Application-ID and Command Code outside the
  reviewed command set.
- Exact frame/occurrence provenance and source references back to Diameter Core.

## Non-Goals

- No Diameter base-header parsing, AVP structural extraction, transport
  association reconstruction, Hop-by-Hop pairing or base result-name decoding.
- No raw PCAP requirement; input is accepted Diameter Core output.
- No IMS registration, authentication, session, media, SDP, RTP, QoS or
  call-success verdict.
- No SIP REGISTER correlation or IMS subscriber identity establishment.
- No Sh, Rx or Ro/Gy application procedures.
- No raw Public-Identity, IMPI, IMPU, MSISDN, Cx-User-Data, authentication
  vector, SIP-Authenticate, SIP-Authorization or keying-material publication.
- No Cx-versus-Dx interface inference from Application-ID, command code, TCP
  port, hostname, IP address, Origin-Host, message ordering or endpoint role.
- No HSS, I-CSCF or S-CSCF role inference from an unverified endpoint.
- No cross-protocol correlation with SIP, SDP, RTP or charging evidence.

## Inputs

- Diameter Core event JSONL (`diameter-event.schema.json` records).
- Diameter Core transaction JSON (`diameter-transaction.schema.json` document).

The analysis rejects inconsistent inputs: multiple captures, capture mismatch,
duplicate event identity, duplicate transaction references, invalid transaction
reference syntax, unresolved references, reference/event disagreement, invalid
status/latency invariants, and missing transaction coverage of a Cx/Dx event.

## Outputs

- Application analysis JSON validated by
  `schemas/diameter-ims-analysis.schema.json`.
- Human-readable application timeline.

## Independent evidence dimensions

```text
message_status:
  OBSERVED | KNOWN_UNSUPPORTED | CONFLICTING

transaction_status:
  MATCHED | OPEN_REQUEST | RESPONSE_ONLY | AMBIGUOUS

application_result:
  SUCCESS_REPORTED | FAILURE_REPORTED | UNRESOLVED | NOT_APPLICABLE
```

A combination such as `OBSERVED + MATCHED + SUCCESS_REPORTED` means only that a
paired Cx/Dx answer reported protocol success. It does not prove IMS
registration, subscriber authentication, HSS authorization or IMS service.

## Result namespaces

Base `Result-Code` follows RFC 6733 value classes. A 3GPP `Experimental-Result`
requires Vendor-ID 10415 and a reviewed TS 29.229 Cx/Dx code. Identical numeric
values in the two namespaces never share a name. Simultaneous base and
experimental results remain `CONFLICTING` and unresolved. The producer consumes
Core result arrays and preserves their AVP provenance; a vendor-specific code is
never treated as a base Result-Code.

## AVP semantics

Only reviewed AVPs are classified. A reviewed AVP requires its expected
namespace: 3GPP AVPs require Vendor-ID 10415 and base AVPs require no vendor.
Repeated occurrences are counted, not collapsed into one. A present grouped AVP
publishes child structure only when Diameter Core reports `DECODED`; otherwise
`structure_proven` is false and children are not inferred. A missing reviewed AVP
is `NOT_OBSERVED_IN_PUBLISHED_SUBSET` when Diameter Core truncated the AVP list,
never proven absent.

Reviewed enumerated values (Server-Assignment-Type, Reason-Code,
User-Authorization-Type, User-Data-Already-Available) may publish their reviewed
symbolic name. No other AVP value is published.

## Privacy

All subscriber, public-identity, user-data, authentication and keying values
remain redacted or presence-only. The Skill never weakens Diameter Core privacy.
No persistent hash or reversible pseudonym is derived.

## Interface identity

Application-ID 16777216 is shared by the Cx and Dx interfaces. The Skill always
publishes `interface_identity = UNPROVED` with an empty basis; it never infers Cx
versus Dx from identifiers, ports, hostnames or ordering. Peer roles (HSS,
I-CSCF, S-CSCF) are never inferred.

## Failure behavior

Invalid input fails closed with exit code 2 and no analysis output. An input with
no reviewed Cx/Dx or conflicting Cx/Dx command evidence fails with exit code 3
and no analysis output. Output write failures use exit code 6. Unreviewed command
codes remain `KNOWN_UNSUPPORTED` with numeric identity rather than being treated
as malformed.

## Limits

- The reviewed command and AVP set follows the Cx/Dx block of the installed
  TShark/Wireshark 4.2.2 Diameter dictionary, which cites 3GPP TS 29.229
  version 6.7.0 Release 6. The specification PDF was not downloaded; later
  releases were not compared clause by clause.
- Grouped structure is limited to decoder-proven direct children.
- An unanswered request is not a timeout.
- Cx/Dx interface identity and network-function roles remain unproved.
- Sh and Rx procedures are not implemented.

## Provenance

Original CoreNet Protocol-layer package. No upstream material imported.
Standards basis: 3GPP TS 29.229 for Cx/Dx commands, AVPs and experimental
results; 3GPP TS 29.228 for stage-2 procedure context; RFC 6733 for the Diameter
base protocol. Command and AVP codes were checked against the reviewed TShark
4.2.2 decoder dictionary.