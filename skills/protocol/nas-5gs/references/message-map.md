# NAS-5GS Message Map

Reviewed message-type identity tables (TS 24.501 version 19.8.0 Release
19; tool table of TShark 4.7.1 `nas-5gs.mm.message_type` and
`nas-5gs.sm.message_type`). Names are preserved exactly as the reviewed
table spells them. Support status is a Skill-local classification;
recognition never implies semantic support.

## Supported bounded subset (5GMM)

| Code | Reviewed name | Procedure family | Direction (message-definition) | Local result | Bounded IE handling |
| --- | --- | --- | --- | --- | --- |
| 65 | Registration request | REGISTRATION | ue-to-amf | REQUEST | registration type, follow-on request, ngKSI, identity type/presence |
| 66 | Registration accept | REGISTRATION | amf-to-ue | ACCEPT | identity type/presence (5G-GUTI when present) |
| 67 | Registration complete | REGISTRATION | ue-to-amf | COMPLETE | envelope context |
| 68 | Registration reject | REGISTRATION | amf-to-ue | REJECT | 5GMM cause code/name |
| 91 | Identity request | IDENTITY | amf-to-ue | REQUEST | requested identity type |
| 92 | Identity response | IDENTITY | ue-to-amf | RESPONSE | returned identity type, redacted value |
| 86 | Authentication request | AUTHENTICATION | amf-to-ue | REQUEST | parameter presence only (rand/autn) |
| 87 | Authentication response | AUTHENTICATION | ue-to-amf | RESPONSE | parameter presence only (res) |
| 88 | Authentication reject | AUTHENTICATION | amf-to-ue | REJECT | envelope context |
| 89 | Authentication failure | AUTHENTICATION | ue-to-amf | FAILURE | 5GMM cause, auts presence |
| 90 | Authentication result | AUTHENTICATION | amf-to-ue | RESULT | parameter presence only |
| 93 | Security mode command | SECURITY_MODE | amf-to-ue | COMMAND | selected ciphering/integrity algorithm names, ngKSI |
| 94 | Security mode complete | SECURITY_MODE | ue-to-amf | COMPLETE | envelope context |
| 95 | Security mode reject | SECURITY_MODE | ue-to-amf | REJECT | 5GMM cause |
| 76 | Service request | SERVICE | ue-to-amf | REQUEST | service type, envelope, sequence/MAC presence |
| 77 | Service reject | SERVICE | amf-to-ue | REJECT | 5GMM cause |
| 78 | Service accept | SERVICE | amf-to-ue | ACCEPT | envelope context |
| 100 | 5GMM status | STATUS | either side (derived direction null) | STATUS | 5GMM cause |

## Supported bounded subset (5GSM)

5GSM logical peers are UE and SMF even though N1 transport passes
through the AMF; direction is the logical protocol direction, not the
carrier. Reviewed table: TS 24.501 19.8.0 table 9.7.2.

| Code | Reviewed name | Procedure family | Logical direction | Local result | Bounded IE handling |
| --- | --- | --- | --- | --- | --- |
| 193 | PDU session establishment request | PDU_SESSION_ESTABLISHMENT | ue-to-smf | REQUEST | PDU session ID, PTI, request type, PDU session type, SSC mode, DNN, S-NSSAI, always-on request, EPCO presence |
| 194 | PDU session establishment accept | PDU_SESSION_ESTABLISHMENT | smf-to-ue | ACCEPT | PDU session ID, PTI, selected PDU session type, selected SSC mode, DNN, PDU address, S-NSSAI, authorized QoS rules presence, QoS flow descriptions presence, QFI/5QI values, always-on indication, EPCO presence |
| 195 | PDU session establishment reject | PDU_SESSION_ESTABLISHMENT | smf-to-ue | REJECT | PDU session ID, PTI, 5GSM cause |
| 201 | PDU session modification request | PDU_SESSION_MODIFICATION | ue-to-smf | REQUEST | PDU session ID, PTI, QoS metadata presence |
| 202 | PDU session modification reject | PDU_SESSION_MODIFICATION | smf-to-ue | REJECT | PDU session ID, PTI, 5GSM cause |
| 203 | PDU session modification command | PDU_SESSION_MODIFICATION | smf-to-ue | COMMAND | PDU session ID, PTI, QoS rules/flow descriptions presence, QFI/5QI |
| 204 | PDU session modification complete | PDU_SESSION_MODIFICATION | ue-to-smf | COMPLETE | PDU session ID, PTI |
| 205 | PDU session modification command reject | PDU_SESSION_MODIFICATION | ue-to-smf | REJECT | PDU session ID, PTI, 5GSM cause |
| 209 | PDU session release request | PDU_SESSION_RELEASE | ue-to-smf | REQUEST | PDU session ID, PTI |
| 210 | PDU session release reject | PDU_SESSION_RELEASE | smf-to-ue | REJECT | PDU session ID, PTI, 5GSM cause |
| 211 | PDU session release command | PDU_SESSION_RELEASE | smf-to-ue | COMMAND | PDU session ID, PTI, 5GSM cause |
| 212 | PDU session release complete | PDU_SESSION_RELEASE | ue-to-smf | COMPLETE | PDU session ID, PTI |
| 214 | 5GSM status | SESSION_MANAGEMENT_STATUS | either side (derived direction null) | STATUS | PDU session ID, PTI, 5GSM cause |

## Known but unsupported 5GMM messages (name only)

| Code | Reviewed name |
| --- | --- |
| 69 | Deregistration request (UE originating) |
| 70 | Deregistration accept (UE originating) |
| 71 | Deregistration request (UE terminated) |
| 72 | Deregistration accept (UE terminated) |
| 79 | Control plane service request |
| 80 | Network slice-specific authentication command |
| 81 | Network slice-specific authentication complete |
| 82 | Network slice-specific authentication result |
| 84 | Configuration update command |
| 85 | Configuration update complete |
| 101 | Notification |
| 102 | Notification response |
| 103 | UL NAS transport |
| 104 | DL NAS transport |
| 105 | Relay key request |
| 106 | Relay key accept |
| 107 | Relay key reject |
| 108 | Relay authentication request |
| 109 | Relay authentication response |

## Known but unsupported 5GSM messages (name only)

These are recognized by reviewed name and reported `UNSUPPORTED` with no
session semantics; their procedures are deferred to later work.

| Code | Reviewed name |
| --- | --- |
| 197 | PDU session authentication command |
| 198 | PDU session authentication complete |
| 199 | PDU session authentication result |
| 216 | Service-level authentication command |
| 217 | Service-level authentication complete |
| 218 | Remote UE report |
| 219 | Remote UE report response |

## Unknown values

Message-type codes outside the reviewed tables (5GMM or 5GSM) remain
`UNKNOWN` with the numeric code preserved. Values listed as "not used in
current version" in the reviewed table are treated the same way: the
code is preserved and no semantics are invented.

## Bounded IE semantics inside supported messages

- Registration type codes normalize to the reviewed names: initial
  registration, mobility registration updating, periodic registration
  updating, emergency registration; unknown codes stay UNKNOWN. The
  registration type never implies procedure success or failure.
- Follow-on request bit is preserved as present/absent; it never
  authorizes or explains network behavior.
- ngKSI (NAS key set identifier) is preserved as an integer; it is
  protocol context, not a key.
- Identity handling follows `identity-privacy.md`: presence and type
  only by default; raw values require the explicit opt-in flag and are
  never converted (SUCI is not SUPI; 5G-GUTI is not IMSI).
- 5GMM cause handling follows the reviewed code/name table; unknown
  codes keep their numeric value with name null.
- 5GSM cause handling follows the reviewed code/name table; unknown
  codes keep their numeric value with name null. A 5GSM cause states a
  session-level rejection reason and is never promoted to a root cause.
- Request type, PDU session type, and SSC mode normalize to the reviewed
  names; unknown or reserved values keep their code with name null.
- PDU session identity and procedure transaction identity are distinct
  protocol fields; neither is subscriber identity and neither is used to
  join sessions across records.
