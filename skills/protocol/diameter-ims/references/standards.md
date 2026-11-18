# Standards basis

## Normative references and review status

| Specification | Version | Role | Review status |
| --- | --- | --- | --- |
| 3GPP TS 29.229 | V19.1.0 (2026-02), ETSI TS 129 229 V19.1.0 | Cx/Dx protocol details: commands, AVPs, result codes | Downloaded from ETSI and clause-reviewed for this correction |
| 3GPP TS 29.228 | V19.2.0 Release 19 | Cx/Dx signalling flows and stage-2 context | Not downloaded in this environment; no clause-level review is claimed |
| 3GPP TS 29.230 | V19.3.0 Release 19 | 3GPP Diameter application identifiers, command codes, AVP codes and experimental result codes | Not downloaded in this environment; registry ownership recorded, no clause-level review is claimed |
| IETF RFC 6733 | RFC 6733 | Diameter Base Protocol value classes and base Result-Code semantics | Base semantics retained; no new clause-level review is claimed |

Reviewed TS 29.229 PDF source:

```text
https://www.etsi.org/deliver/etsi_ts/129200_129299/129229/19.01.00_60/ts_129229v190100p.pdf
SHA-256 346a451830b3073ba4a03bf037fe0eb08f353eee445dc9776d6bc8fe8c607221
```

## TS 29.229 V19.1.0 clauses reviewed

| Clause/Table | Reviewed content |
| --- | --- |
| Clause 6 | Cx/Dx application: 3GPP Vendor-ID 10415, Application-ID 16777216 |
| Table 6.1.1 | Command Codes 300–305: UAR/UAA, SAR/SAA, LIR/LIA, MAR/MAA, RTR/RTA, PPR/PPA |
| Clause 6.2 | The Cx/Dx result values below are carried in Experimental-Result; Result-Code shall be absent |
| Clauses 6.2.1.1–6.2.1.4 | Success results 2001–2004 with names `DIAMETER_FIRST_REGISTRATION`, `DIAMETER_SUBSEQUENT_REGISTRATION`, `DIAMETER_UNREGISTERED_SERVICE`, `DIAMETER_SUCCESS_SERVER_NAME_NOT_STORED` |
| Clause 6.2.1.5 | Code 2005 is Void |
| Clauses 6.2.2.1–6.2.2.9 | Permanent failures 5001–5009 with reviewed names |
| Clause 6.2.2.10 | Code 5010 is Void |
| Clauses 6.2.2.11–6.2.2.12 | Permanent failures 5011 and 5012 with reviewed names |
| Clause 6.3.0 | Cx/Dx AVP code table and Vendor-ID 10415 |
| Clauses 6.3.7–6.3.14 | Normative names `User-Data` (606), `SIP-Number-Auth-Items` (607), `SIP-Authentication-Scheme` (608), `SIP-Authenticate` (609), `SIP-Authorization` (610), `SIP-Authentication-Context` (611), `SIP-Auth-Data-Item` (612), `SIP-Item-Number` (613) |
| Clause 6.4.2 | Experimental-Result-Code namespace assignment summary |
| Clause 6.4.3 | Command Code values 300–305 |

## Reviewed Cx success results

| Code | Reviewed name | Application classification |
| --- | --- | --- |
| 2001 | `DIAMETER_FIRST_REGISTRATION` | `SUCCESS_REPORTED` |
| 2002 | `DIAMETER_SUBSEQUENT_REGISTRATION` | `SUCCESS_REPORTED` |
| 2003 | `DIAMETER_UNREGISTERED_SERVICE` | `SUCCESS_REPORTED` |
| 2004 | `DIAMETER_SUCCESS_SERVER_NAME_NOT_STORED` | `SUCCESS_REPORTED` |

Code 2005 is Void in clause 6.2.1.5 and receives no semantic name.

## Reviewed Cx permanent failures

| Code | Reviewed name |
| --- | --- |
| 5001 | `DIAMETER_ERROR_USER_UNKNOWN` |
| 5002 | `DIAMETER_ERROR_IDENTITIES_DONT_MATCH` |
| 5003 | `DIAMETER_ERROR_IDENTITY_NOT_REGISTERED` |
| 5004 | `DIAMETER_ERROR_ROAMING_NOT_ALLOWED` |
| 5005 | `DIAMETER_ERROR_IDENTITY_ALREADY_REGISTERED` |
| 5006 | `DIAMETER_ERROR_AUTH_SCHEME_NOT_SUPPORTED` |
| 5007 | `DIAMETER_ERROR_IN_ASSIGNMENT_TYPE` |
| 5008 | `DIAMETER_ERROR_TOO_MUCH_DATA` |
| 5009 | `DIAMETER_ERROR_NOT_SUPPORTED_USER_DATA` |
| 5011 | `DIAMETER_ERROR_FEATURE_UNSUPPORTED` |
| 5012 | `DIAMETER_ERROR_SERVING_NODE_FEATURE_UNSUPPORTED` |

Code 5010 is Void in clause 6.2.2.10. It receives no semantic name, remains
numeric, and stays `UNRESOLVED`. Codes 5013–5020 are reserved in the reviewed
baseline and receive no invented names.

## Specification text inconsistency

Clause 6.4.2 summarizes the assigned range as "2001-2005 and 5001-5011", while
clauses 6.2.1.5 and 6.2.2.10 define 2005 and 5010 as Void and clause 6.2.2.12
defines 5012. This implementation follows the clause-level definitions, which
are more specific and explicitly marked Void where applicable. The summary
sentence is recorded as a specification inconsistency, not used to invent
semantics.

## Registry ownership

TS 29.230 is the 3GPP Diameter registry owner for application identifiers,
Command Codes, AVP codes and experimental result codes. TS 29.229 defines the
Cx/Dx values used here. The TS 29.230 document was not downloaded in this
environment; its registry ownership is recorded as a standards reference, not as
a clause-level audit.

## Decoder reference

The installed TShark/Wireshark 4.2.2 Diameter dictionary remains a decoder alias
reference for the reviewed AVP display names and grouped-AVP decoding. It is not
the normative source for names, codes or result semantics.

## Coverage limitation

This Skill implements a bounded Cx/Dx subset. It does not claim full Release 19
conformance. TS 29.228 stage-2 flows and TS 29.230 registry contents were not
clause-audited. Unreviewed AVPs and result codes remain explicitly unreviewed.