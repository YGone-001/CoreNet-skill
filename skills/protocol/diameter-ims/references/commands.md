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
  Cx-User-Data and Supported-Features. The Skill does not decide S-CSCF
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
  Cx-User-Data. The Skill does not decide that a profile update was installed.

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