# NAS-5GS Message Map

Reviewed 5GMM message-type identity table (TS 24.501; tool table of
TShark 4.7.1 `nas-5gs.mm.message_type`). Names are preserved exactly as
the reviewed table spells them. Support status is a Skill-local
classification; recognition never implies semantic support.

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

These are reported `UNSUPPORTED` with the reviewed name and no message
semantics. UL/DL NAS transport (103/104) wraps 5GSM payloads; the 5GSM
family itself is reported DEFERRED without session semantics.

## 5GSM (deferred)

5GSM message types (PDU session establishment, modification, release,
and related; reviewed tool table `nas-5gs.sm.message_type`, codes in the
193+ range) set `nas_family: 5GSM` and `support_status: DEFERRED`. No
5GSM message names, causes, or session identifiers are emitted.

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
