# Reviewed Cx/Dx AVP reference

Only the AVPs listed here are classified. Each entry distinguishes the normative
3GPP name from the reviewed decoder alias. The producer publishes both as
`canonical_name` and `name` respectively. AVP codes and Vendor-ID 10415 follow
TS 29.229 V19.1.0 clauses 6.3.0 and 6.3.7–6.3.14.

## Reviewed AVP vocabulary

| Code | Normative TS 29.229 name | Decoder alias (`name`) | Vendor-ID | Grouped | Publication class |
| --- | --- | --- | --- | --- | --- |
| 1 | User-Name | User-Name | base | no | protected, presence only |
| 263 | Session-Id | Session-Id | base | no | presence only |
| 264 | Origin-Host | Origin-Host | base | no | presence only |
| 266 | Vendor-Id | Vendor-Id | base | no | structure only |
| 268 | Result-Code | Result-Code | base | no | reviewed base result namespace |
| 277 | Auth-Session-State | Auth-Session-State | base | no | presence only |
| 283 | Destination-Realm | Destination-Realm | base | no | presence only |
| 296 | Origin-Realm | Origin-Realm | base | no | presence only |
| 297 | Experimental-Result | Experimental-Result | base | yes | structure only |
| 600 | Visited-Network-Identifier | Visited-Network-Identifier | 10415 | no | presence only |
| 601 | Public-Identity | Public-Identity | 10415 | no | protected, presence only |
| 602 | Server-Name | Server-Name | 10415 | no | presence only |
| 603 | Server-Capabilities | Server-Capabilities | 10415 | yes | structure only |
| 604 | Mandatory-Capability | Mandatory-Capability | 10415 | no | presence and occurrence count |
| 605 | Optional-Capability | Optional-Capability | 10415 | no | presence and occurrence count |
| 606 | User-Data | Cx-User-Data | 10415 | no | protected, presence only |
| 607 | SIP-Number-Auth-Items | 3GPP-SIP-Number-Auth-Items | 10415 | no | presence and occurrence count |
| 608 | SIP-Authentication-Scheme | 3GPP-SIP-Authentication-Scheme | 10415 | no | presence only |
| 609 | SIP-Authenticate | 3GPP-SIP-Authenticate | 10415 | no | protected, presence only |
| 610 | SIP-Authorization | 3GPP-SIP-Authorization | 10415 | no | protected, presence only |
| 611 | SIP-Authentication-Context | SIP-Authentication-Context | 10415 | no | protected, presence only |
| 612 | SIP-Auth-Data-Item | 3GPP-SIP-Auth-Data-Item | 10415 | yes | structure only |
| 613 | SIP-Item-Number | 3GPP-SIP-Item-Number | 10415 | no | presence and occurrence count |
| 614 | Server-Assignment-Type | Server-Assignment-Type | 10415 | no | reviewed enumeration |
| 615 | Deregistration-Reason | Deregistration-Reason | 10415 | yes | structure only |
| 616 | Reason-Code | Reason-Code | 10415 | no | reviewed enumeration |
| 617 | Reason-Info | Reason-Info | 10415 | no | protected free text |
| 623 | User-Authorization-Type | User-Authorization-Type | 10415 | no | reviewed enumeration |
| 624 | User-Data-Already-Available | User-Data-Already-Available | 10415 | no | reviewed enumeration |
| 625 | Confidentiality-Key | Confidentiality-Key | 10415 | no | protected, presence only |
| 626 | Integrity-Key | Integrity-Key | 10415 | no | protected, presence only |
| 628 | Supported-Features | Supported-Features | 10415 | yes | structure only |
| 629 | Feature-List-ID | Feature-List-ID | 10415 | no | presence and occurrence count |
| 630 | Feature-List | Feature-List | 10415 | no | presence and occurrence count |

The decoder aliases are retained for compatibility with the installed decoder
tables. They are not a second normative identity and do not change AVP codes or
semantics.

## Grouped AVP children

Child structure is published only when Diameter Core reports `DECODED` for the
parent. The reviewed child sets follow TS 29.229 V19.1.0:

- Server-Capabilities (603): Mandatory-Capability (604), Optional-Capability
  (605), Server-Name (602).
- SIP-Auth-Data-Item (612): SIP-Item-Number (613),
  SIP-Authentication-Scheme (608), SIP-Authenticate (609),
  SIP-Authorization (610), SIP-Authentication-Context (611),
  Confidentiality-Key (625), Integrity-Key (626).
- Deregistration-Reason (615): Reason-Code (616), Reason-Info (617).
- Supported-Features (628): Vendor-Id (266), Feature-List-ID (629),
  Feature-List (630).

Child AVPs outside the reviewed vocabulary may be listed by numeric code with
null names and no value. Children beyond the direct level are not expanded. If
the decoder does not prove the parent-child relationship, the producer publishes
`structure_proven: false` and no children; it never infers children from AVP
order.

## Reviewed enumerations

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

Cx/Dx result values are carried in Experimental-Result with Vendor-ID 10415 and
Result-Code absent (TS 29.229 clause 6.2).

Reviewed success results:

| Code | Name | Application result |
| --- | --- | --- |
| 2001 | `DIAMETER_FIRST_REGISTRATION` | `SUCCESS_REPORTED` |
| 2002 | `DIAMETER_SUBSEQUENT_REGISTRATION` | `SUCCESS_REPORTED` |
| 2003 | `DIAMETER_UNREGISTERED_SERVICE` | `SUCCESS_REPORTED` |
| 2004 | `DIAMETER_SUCCESS_SERVER_NAME_NOT_STORED` | `SUCCESS_REPORTED` |

Reviewed permanent failures:

| Code | Name |
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

Void and reserved values:

| Code | Reviewed status |
| --- | --- |
| 2005 | Void in clause 6.2.1.5; numeric only, `UNRESOLVED` |
| 5010 | Void in clause 6.2.2.10; numeric only, `UNRESOLVED` |
| 5013–5020 | Reserved/unreviewed; numeric only, no name |
| Other 3GPP codes | Unreviewed; numeric only, no name |

Base Result-Code values retain RFC 6733 semantics. Base 2001/2002 are not Cx
success codes and are never merged with Experimental-Result 2001/2002.

## Unimplemented AVPs

AVPs not listed above remain explicitly unreviewed. Numeric codes may appear in
diameter-core evidence, but this Skill assigns them no name, grouping or value
semantics.