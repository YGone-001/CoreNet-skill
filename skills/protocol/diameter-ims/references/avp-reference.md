# Reviewed Cx/Dx AVP reference

Only the AVPs listed here are classified. Names are the reviewed decoder names.
The prompt-level shorthand `User-Data` corresponds to `Cx-User-Data` (606), and
the Cx authentication AVPs are the vendor-specific 3GPP AVPs 607–613, not the
same-named base SIP application AVPs from RFC 4740.

## Reviewed AVP vocabulary

| Code | Reviewed name | Vendor-ID | Grouped | Publication class |
| --- | --- | --- | --- | --- |
| 263 | Session-Id | base | no | presence, length is not published |
| 266 | Vendor-Id | base | no | structure only |
| 268 | Result-Code | base | no | reviewed result namespace |
| 297 | Experimental-Result | base | yes | structure only, children preserved when proven |
| 600 | Visited-Network-Identifier | 10415 | no | presence only |
| 601 | Public-Identity | 10415 | no | protected, presence only |
| 602 | Server-Name | 10415 | no | presence only |
| 603 | Server-Capabilities | 10415 | yes | structure only |
| 604 | Mandatory-Capability | 10415 | no | presence and occurrence count |
| 605 | Optional-Capability | 10415 | no | presence and occurrence count |
| 606 | Cx-User-Data | 10415 | no | protected, presence only |
| 607 | 3GPP-SIP-Number-Auth-Items | 10415 | no | presence and occurrence count |
| 608 | 3GPP-SIP-Authentication-Scheme | 10415 | no | presence only |
| 609 | 3GPP-SIP-Authenticate | 10415 | no | protected, presence only |
| 610 | 3GPP-SIP-Authorization | 10415 | no | protected, presence only |
| 611 | SIP-Authentication-Context | 10415 | no | protected, presence only |
| 612 | 3GPP-SIP-Auth-Data-Item | 10415 | yes | structure only |
| 613 | 3GPP-SIP-Item-Number | 10415 | no | presence and occurrence count |
| 614 | Server-Assignment-Type | 10415 | no | reviewed enumeration |
| 615 | Deregistration-Reason | 10415 | yes | structure only |
| 616 | Reason-Code | 10415 | no | reviewed enumeration |
| 617 | Reason-Info | 10415 | no | protected free text |
| 623 | User-Authorization-Type | 10415 | no | reviewed enumeration |
| 624 | User-Data-Already-Available | 10415 | no | reviewed enumeration |
| 625 | Confidentiality-Key | 10415 | no | protected, presence only |
| 626 | Integrity-Key | 10415 | no | protected, presence only |
| 628 | Supported-Features | 10415 | yes | structure only |
| 629 | Feature-List-ID | 10415 | no | presence and occurrence count |
| 630 | Feature-List | 10415 | no | presence and occurrence count |

## Grouped AVP children

Child structure is published only when Diameter Core reports `DECODED` for the
parent. The reviewed child sets are:

- Server-Capabilities (603): Mandatory-Capability (604), Optional-Capability
  (605), Server-Name (602).
- 3GPP-SIP-Auth-Data-Item (612): 3GPP-SIP-Item-Number (613),
  3GPP-SIP-Authentication-Scheme (608), 3GPP-SIP-Authenticate (609),
  3GPP-SIP-Authorization (610), SIP-Authentication-Context (611),
  Confidentiality-Key (625), Integrity-Key (626).
- Deregistration-Reason (615): Reason-Code (616), Reason-Info (617).
- Supported-Features (628): Vendor-Id (266), Feature-List-ID (629),
  Feature-List (630).

Child AVPs that are not in the reviewed vocabulary may be listed by numeric code
with a null reviewed name and no value. Children beyond the direct level are not
expanded. If Diameter Core does not prove the parent-child relationship, the
producer publishes `structure_proven: false` and an empty child array; it never
infers children from AVP order.

## Reviewed enumerations

Only these reviewed values may be published:

| AVP | Value | Name |
| --- | --- | --- |
| Server-Assignment-Type | 0 | `NO_ASSIGNMENT` |
| Server-Assignment-Type | 1 | `REGISTRATION` |
| Server-Assignment-Type | 2 | `RE_REGISTRATION` |
| Server-Assignment-Type | 3 | `UNREGISTERED_USER` |
| Server-Assignment-Type | 4 | `TIMEOUT_DEREGISTRATION` |
| Server-Assignment-Type | 5 | `USER_DEREGISTRATION` |
| Server-Assignment-Type | 6 | `TIMEOUT_DEREGISTRATION_STORE_SERVER_NAME` |
| Server-Assignment-Type | 7 | `USER_DEREGISTRATION_STORE_SERVER_NAME` |
| Server-Assignment-Type | 8 | `ADMINISTRATIVE_DEREGISTRATION` |
| Server-Assignment-Type | 9 | `AUTHENTICATION_FAILURE` |
| Server-Assignment-Type | 10 | `AUTHENTICATION_TIMEOUT` |
| Server-Assignment-Type | 11 | `DEREGISTRATION_TOO_MUCH_DATA` |
| Server-Assignment-Type | 12 | `AAA_USER_DATA_REQUEST` |
| Server-Assignment-Type | 13 | `PGW_UPDATE` |
| Server-Assignment-Type | 14 | `RESTORATION` |
| Reason-Code | 0 | `PERMANENT_TERMINATION` |
| Reason-Code | 1 | `NEW_SERVER_ASSIGNED` |
| Reason-Code | 2 | `SERVER_CHANGE` |
| Reason-Code | 3 | `REMOVE_S-CSCF` |
| User-Authorization-Type | 0 | `REGISTRATION` |
| User-Authorization-Type | 1 | `DE_REGISTRATION` |
| User-Authorization-Type | 2 | `REGISTRATION_AND_CAPABILITIES` |
| User-Data-Already-Available | 0 | `USER_DATA_NOT_AVAILABLE` |
| User-Data-Already-Available | 1 | `USER_DATA_ALREADY_AVAILABLE` |

If Diameter Core marks one of these AVPs sensitive, no reviewed value is
published.

## Results

Base `Result-Code` values 2001 and 2002 report success. Base protocol-error and
failure value classes report failure. 3GPP Experimental-Result codes with
Vendor-ID 10415 use the reviewed TS 29.229 names:

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
| 5010 | `DIAMETER_MISSING_USER_ID` |
| 5011 | `DIAMETER_ERROR_FEATURE_UNSUPPORTED` |
| 5012 | `DIAMETER_ERROR_SERVING_NODE_FEATURE_UNSUPPORTED` |

A 3GPP vendor code outside this reviewed set remains numeric with no semantic
name. A non-3GPP or missing Vendor-ID never receives a 3GPP name.