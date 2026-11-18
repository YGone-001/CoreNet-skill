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
  Optional-Capability, User-Data (decoder alias Cx-User-Data),
  SIP-Number-Auth-Items (3GPP-SIP-Number-Auth-Items),
  SIP-Authentication-Scheme (3GPP-SIP-Authentication-Scheme),
  SIP-Authenticate (3GPP-SIP-Authenticate), SIP-Authorization
  (3GPP-SIP-Authorization), SIP-Authentication-Context, SIP-Auth-Data-Item
  (3GPP-SIP-Auth-Data-Item), SIP-Item-Number (3GPP-SIP-Item-Number),
  Server-Assignment-Type, Deregistration-Reason, Reason-Code, Reason-Info,
  User-Authorization-Type, User-Data-Already-Available, Confidentiality-Key,
  Integrity-Key, Supported-Features, Feature-List-ID and Feature-List.
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
- No raw Public-Identity, IMPI, IMPU, MSISDN, User-Data (decoder alias
  Cx-User-Data), authentication
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
requires Vendor-ID 10415 and a reviewed TS 29.229 Cx/Dx code. TS 29.229 clause
6.2 requires Cx/Dx values to be carried in Experimental-Result with Result-Code
absent. Identical numeric values in the two namespaces never share a name:
Experimental-Result 2001 is `DIAMETER_FIRST_REGISTRATION`, while base 2001 is
`DIAMETER_SUCCESS`.

Reviewed Cx success results (Experimental-Result, Vendor-ID 10415) are 2001
`DIAMETER_FIRST_REGISTRATION`, 2002 `DIAMETER_SUBSEQUENT_REGISTRATION`, 2003
`DIAMETER_UNREGISTERED_SERVICE` and 2004
`DIAMETER_SUCCESS_SERVER_NAME_NOT_STORED`; each publishes `SUCCESS_REPORTED`.
Reviewed permanent failures are 5001–5009, 5011 and 5012 and publish
`FAILURE_REPORTED`.

Code 2005 is Void (clause 6.2.1.5). Code 5010 is Void (clause 6.2.2.10). Codes
5013–5020 are reserved in the reviewed baseline. Void, reserved and unreviewed
codes keep their numeric identity, publish no name and remain `UNRESOLVED`.

Simultaneous base and experimental results remain `CONFLICTING` and unresolved.
The producer consumes Core result arrays and preserves their AVP provenance; a
vendor-specific code is never treated as a base Result-Code.

## AVP semantics

Only reviewed AVPs are classified. A reviewed AVP requires its expected
namespace: 3GPP AVPs require Vendor-ID 10415 and base AVPs require no vendor.
Each AVP publishes `canonical_name` (the normative TS 29.229 name) and `name`
(the reviewed decoder alias); the code and Vendor-ID remain the stable identity.
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

- The reviewed command, AVP and result set follows 3GPP TS 29.229 V19.1.0
  Release 19, clauses 6.1, 6.2, 6.3.0 and 6.3.7–6.3.14. The official ETSI PDF
  was downloaded and reviewed for those clauses. TS 29.228 V19.2.0 and
  TS 29.230 V19.3.0 were not retrievable in this environment and were not
  clause-audited. Later releases were not compared clause by clause, and this
  Skill does not claim full Release 19 conformance.
- The installed TShark/Wireshark 4.2.2 dictionary is used only as the reviewed
  decoder-alias and grouping reference.
- Grouped structure is limited to decoder-proven direct children.
- An unanswered request is not a timeout.
- Cx/Dx interface identity and network-function roles remain unproved.
- Sh and Rx procedures are not implemented.

## Provenance

Original CoreNet Protocol-layer package. No upstream material imported.
Standards basis: 3GPP TS 29.229 V19.1.0 for Cx/Dx commands, AVPs and result
codes; 3GPP TS 29.228 V19.2.0 for stage-2 procedure context (not clause-audited);
3GPP TS 29.230 V19.3.0 for registry ownership (not clause-audited); RFC 6733 for
the Diameter base protocol. The reviewed TShark 4.2.2 dictionary supplies only
decoder display aliases and grouped-AVP decoding.