# NAS-5GS Protocol Model

Bounded basis: 3GPP TS 24.501 (NAS protocol for 5GS; Stage 3), Release 19
lineage, reviewed through the NAS-5GS dissector of Wireshark/TShark 4.7.1
(v4.7.1-0-g667ab240e6de). Every identity table this Skill ships
(message types, 5GMM causes, registration types, identity types, security
algorithm identifiers) was dumped with `tshark -G fields` and
`tshark -G values` and cross-checked against those tool tables; names are
kept exactly as the reviewed tables spell them. Dissector output is
tooling evidence, not normative truth: where a specification edition and
the dissector disagree, the Skill preserves the reviewed table value and
records the tool version instead of inventing a reconciliation.

## Role and context

NAS-5GS is the non-access-stratum protocol between the UE and the AMF over
the logical N1 interface. In captured signaling it appears either as a
direct UE-AMF payload or tunneled inside NGAP uplink/downlink NAS
transport on N2. This Skill answers protocol-local questions only: which
5GMM message a NAS payload carries, which security envelope wraps it,
which bounded information elements it exposes, and what its reviewed
message-local meaning is. It never answers WHY a complete 5G Registration
procedure failed; that belongs to the future `5gc-registration-mobility`
Domain Skill.

## 5GMM versus 5GSM

The 5GS NAS carries two protocol families under one extended protocol
discriminator (0x7E):

- 5GMM (mobility management): registration, identity, authentication,
  security-mode control, service access, status reporting. This Skill's
  v0.1.0 semantic ownership.
- 5GSM (session management): PDU session establishment, modification,
  release. Recognized as 5GSM and marked DEFERRED; no message semantics,
  no session identifiers (PDU session ID, DNN, QFI, SSC mode, session
  type, 5GSM cause) are extracted.

The family distinction in this Skill comes from directly available
protocol information: which sublayer message-type field the dissector
exported (`nas-5gs.mm.message_type` versus `nas-5gs.sm.message_type`), or
the explicitly provided family in structured input. A record carrying
both at once is rejected as ambiguous instead of guessed.

## Plain versus security-protected NAS

Every 5GS NAS message begins with an extended protocol discriminator and
a security header type:

- `0` plain NAS message, not security protected;
- `1` integrity protected;
- `2` integrity protected and ciphered;
- `3` integrity protected with new 5GS security context;
- `4` integrity protected and ciphered with new 5GS security context.

Protected messages carry a security parameter index, a sequence number,
and a message authentication code, and may wrap an inner NAS message that
the dissector cannot decode without security context. The envelope is
recorded independently from inner semantics; see
`security-envelope.md`. This Skill never derives keys, never verifies
MACs, and never cipheres or decipheres anything.

## Message identity and bounded support

Message identity is normalized from reviewed TS 24.501 tables:

- SUPPORTED: the bounded 5GMM subset (registration, identity,
  authentication, security-mode, service, status), with message-local IE
  handling documented in `message-map.md`.
- UNSUPPORTED: known out-of-scope 5GMM messages (deregistration,
  configuration update, notification, NAS transport containers, relay
  messages, and similar), recognized by name only.
- UNKNOWN: message-type values outside the reviewed tables.

`result` labels (REQUEST, ACCEPT, REJECT, and similar) are local
normalized states derived from message identity; they are not 3GPP wire
values and not procedure verdicts.

## Direction

Where the reviewed message identity has a single valid sender, direction
is derived as `ue-to-amf` or `amf-to-ue` with basis `message-definition`
(for example, Registration request is UE-originated; Registration reject
is network-originated). A directly observed carrier direction from the
structured input overrides it with basis `observed-carrier`. 5GMM status
may be sent by either side, so its derived direction stays null. Endpoint
addresses are never mapped to network-function roles.

## Relationship to NGAP transport

`ngap` and `nas-5gs` are sibling Protocol Skills. NGAP carries NAS
payloads but intentionally does not preserve their bytes, so an NGAP
event is not a sufficient input for NAS semantics; this Skill consumes
raw captures through tshark, structured NAS field exports, or synthetic
NAS metadata fixtures. The canonical cross-Protocol join is shared packet
provenance (`capture_file` plus `frame_number`); this Skill does not
parse AMF-UE-NGAP-ID or RAN-UE-NGAP-ID and never duplicates NGAP
correlation logic.

## Evidence boundary

- OBSERVED: security header code, sequence number, MAC presence,
  message-type code, registration type code, identity type code, cause
  code, algorithm codes, service type code.
- DERIVED: message identity names, family classification, protection
  state, direction by message definition, cause names, algorithm names,
  result labels, timestamp conversion.
- INFERRED: protocol-local relationships strongly suggested by behavior
  but not directly proven.
- HYPOTHESIS: explanations needing more evidence.
- CONFIRMED: not claimed by this Skill for procedure outcomes.

Registration type normalization (initial, mobility updating, periodic
updating, emergency) describes the requested procedure kind; it never
implies registration success or failure.
