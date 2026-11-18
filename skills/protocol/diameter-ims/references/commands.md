# Cx/Dx command inventory

All reviewed Cx/Dx commands use Application-ID 16777216. Cx and Dx share this
application identity.

| Command Code | Reviewed command | Request | Answer | Reviewed procedure family |
| --- | --- | --- | --- | --- |
| 300 | User-Authorization | UAR | UAA | `USER_AUTHORIZATION` |
| 301 | Server-Assignment | SAR | SAA | `SERVER_ASSIGNMENT` |
| 302 | Location-Info | LIR | LIA | `LOCATION_INFO` |
| 303 | Multimedia-Auth | MAR | MAA | `MULTIMEDIA_AUTH` |
| 304 | Registration-Termination | RTR | RTA | `REGISTRATION_TERMINATION` |
| 305 | Push-Profile | PPR | PPA | `PUSH_PROFILE` |

## Reviewed semantics

- UAR/UAA: user-authorization request and answer evidence. The answer may carry
  Server-Capabilities. The Skill does not decide whether the I-CSCF or HSS
  authorized the user.
- SAR/SAA: server-assignment request and answer evidence. The answer may carry
  User-Data (decoder alias Cx-User-Data) and Supported-Features. The Skill does not decide S-CSCF
  assignment, profile installation or registration success.
- LIR/LIA: location-information request and answer evidence. The answer may carry
  Server-Name. The Skill does not decide the serving S-CSCF location.
- MAR/MAA: multimedia-authentication request and answer evidence. The request and
  answer may carry 3GPP-SIP-Auth-Data-Item. The Skill does not publish
  authentication material or decide that the UE authenticated.
- RTR/RTA: registration-termination request and answer evidence. The request may
  carry Deregistration-Reason. The Skill does not decide that the subscriber was
  deregistered or lost service.
- PPR/PPA: push-profile request and answer evidence. The request may carry
  User-Data (decoder alias Cx-User-Data). The Skill does not decide that a profile update was installed.

## Unreviewed command codes

A command code under Application-ID 16777216 that is not in the reviewed table is
published as `KNOWN_UNSUPPORTED`. Its numeric command code is preserved, its
command name is null, and no AVP semantics are assigned. It is not classified as
malformed.

## Application mismatch

A reviewed Cx/Dx command code observed under a different Application-ID is
published as `CONFLICTING`. The numeric Application-ID and Command Code are
preserved, but no Cx/Dx semantics, AVP vocabulary or result interpretation are
assigned.

## Message status versus transaction status

Command recognition is independent of Diameter Core correlation. A recognized
command may be `MATCHED`, `OPEN_REQUEST`, `RESPONSE_ONLY` or `AMBIGUOUS`. The
Skill never invents the missing Request or Answer.

## Non-Cx/Dx transactions

Transactions for other Diameter applications are not interpreted. They appear in
the command inventory with a non-Cx/Dx scope and are omitted from observations,
except that a reviewed Cx/Dx command code under a wrong Application-ID is kept as
`CONFLICTING`.

## Result evidence

TS 29.229 clause 6.2 requires Cx/Dx result values to be carried inside
Experimental-Result with Vendor-ID 10415; Result-Code shall be absent. The Skill
keeps the base and experimental namespaces separate even when both are supplied.

| Experimental-Result-Code | Reviewed name | Application result |
| --- | --- | --- |
| 2001 | `DIAMETER_FIRST_REGISTRATION` | `SUCCESS_REPORTED` |
| 2002 | `DIAMETER_SUBSEQUENT_REGISTRATION` | `SUCCESS_REPORTED` |
| 2003 | `DIAMETER_UNREGISTERED_SERVICE` | `SUCCESS_REPORTED` |
| 2004 | `DIAMETER_SUCCESS_SERVER_NAME_NOT_STORED` | `SUCCESS_REPORTED` |
| 5001 | `DIAMETER_ERROR_USER_UNKNOWN` | `FAILURE_REPORTED` |
| 5002 | `DIAMETER_ERROR_IDENTITIES_DONT_MATCH` | `FAILURE_REPORTED` |
| 5003 | `DIAMETER_ERROR_IDENTITY_NOT_REGISTERED` | `FAILURE_REPORTED` |
| 5004 | `DIAMETER_ERROR_ROAMING_NOT_ALLOWED` | `FAILURE_REPORTED` |
| 5005 | `DIAMETER_ERROR_IDENTITY_ALREADY_REGISTERED` | `FAILURE_REPORTED` |
| 5006 | `DIAMETER_ERROR_AUTH_SCHEME_NOT_SUPPORTED` | `FAILURE_REPORTED` |
| 5007 | `DIAMETER_ERROR_IN_ASSIGNMENT_TYPE` | `FAILURE_REPORTED` |
| 5008 | `DIAMETER_ERROR_TOO_MUCH_DATA` | `FAILURE_REPORTED` |
| 5009 | `DIAMETER_ERROR_NOT_SUPPORTED_USER_DATA` | `FAILURE_REPORTED` |
| 5011 | `DIAMETER_ERROR_FEATURE_UNSUPPORTED` | `FAILURE_REPORTED` |
| 5012 | `DIAMETER_ERROR_SERVING_NODE_FEATURE_UNSUPPORTED` | `FAILURE_REPORTED` |

Code 2005 is Void (TS 29.229 clause 6.2.1.5) and a Deprecated value (TS 29.230
table 8.1.2). Code 5010 is Void (TS 29.229 clause 6.2.2.10) and unassigned
(TS 29.230 table 8.1.4). The TS 29.230 table 8.1.2 reserved success range
2006–2020 and the table 8.1.4 reserved permanent-failure range 5013–5020 keep
their numeric identity and publish no semantic name. Codes 5021–5040 are
reserved for TS 32.299 and are not Cx/Dx result codes. All such values remain
`UNRESOLVED`; a missing or non-3GPP Vendor-ID never receives Cx semantics.

Base Result-Code 2001/2002 remains base-protocol success and is never merged with
Experimental-Result 2001/2002. Simultaneous base and experimental results remain
`CONFLICTING` and `UNRESOLVED`.