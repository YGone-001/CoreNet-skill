# NAS-5GS Protocol Model

Bounded basis: 3GPP TS 24.501 version 19.8.0 Release 19 (NAS protocol for
5GS; Stage 3) and 3GPP TS 24.007 version 18.2.0 Release 18 (general
layer-3 aspects), cross-checked through the NAS-5GS dissector of
Wireshark/TShark 4.7.1 (v4.7.1-0-g667ab240e6de). Every identity table
this Skill ships (message types, 5GMM and 5GSM causes, registration
types, identity types, request type, PDU session type, SSC mode, security
algorithm identifiers) was cross-checked against the reviewed
specification tables and the dissector. Dissector output is tooling
evidence, not normative truth: where a specification edition and the
dissector disagree, the Skill preserves the reviewed specification value
and records the tool version instead of inventing a reconciliation.

## Role and context

NAS-5GS is the non-access-stratum protocol for the 5G system. In captured
signaling it appears either as a direct UE-AMF payload or tunneled inside
NGAP uplink/downlink NAS transport on N2. This Skill answers
protocol-local questions only: which NAS message a payload carries, which
family it belongs to, which security envelope wraps it, which bounded
information elements it exposes, and what its reviewed message-local
meaning is. It never answers WHY a complete 5G Registration or PDU
Session procedure failed.

## 5GMM versus 5GSM

The 5GS NAS carries two protocol families:

- 5GMM (mobility management): registration, identity, authentication,
  security-mode control, service access, status reporting.
- 5GSM (session management): PDU session establishment, modification,
  release, and 5GSM status.

The two families use distinct extended protocol discriminator values
(TS 24.007 table 11.2.3.1.1A.1): 5GMM `0x7E` (126) and 5GSM `0x2E` (46).
The family in this Skill is derived from which sublayer message-type
field the dissector exported (`nas-5gs.mm.message_type` versus
`nas-5gs.sm.message_type`) or from the explicitly provided family in
structured input. When the observed discriminator is present it is
preserved, and a discriminator that contradicts the observed family
fails loudly instead of being reconciled. A record carrying both message
types at once is rejected as ambiguous.

## Plain versus security-protected NAS

A plain 5GS NAS message has a three-octet header for 5GMM (extended
protocol discriminator; security header type plus spare half octet;
message type) and a four-octet header for 5GSM (extended protocol
discriminator; PDU session identity; procedure transaction identity;
message type). A security-protected message has a seven-octet header
(extended protocol discriminator; security header type plus spare half
octet; message authentication code; sequence number) followed by a
complete plain 5GS NAS message.

Security header types are:

- `0` plain NAS message, not security protected;
- `1` integrity protected;
- `2` integrity protected and ciphered;
- `3` integrity protected with new 5GS security context;
- `4` integrity protected and ciphered with new 5GS security context.

The envelope is recorded independently from inner semantics; see
`security-envelope.md`. The same envelope model applies to 5GMM and 5GSM
and is never duplicated. This Skill never derives keys, never verifies
MACs, and never cipheres or decipheres anything.

## 5GSM header fields

- Extended protocol discriminator: identifies the 5GSM protocol; 5GSM
  uses `0x2E`. It is never guessed from the message type when the
  observed field exists.
- PDU session identity: a 5GSM protocol field that identifies the PDU
  session within one UE's session set. It is preserved as its raw numeric
  value with its source evidence. It is not subscriber identity, and
  equal numeric values across different records do not prove the same
  session; this Skill performs no global session join.
- Procedure transaction identity (PTI): a protocol transaction identifier
  that may support future message-local or session-procedure correlation.
  It is not the PDU session identity and is never turned into a
  repository-wide session identifier.
- 5GSM message type: the reviewed message identity within the bounded
  subset, or UNKNOWN outside it.

PDU session identity, PTI, and message type stay distinct. None of them
is an NGAP PDU session resource identifier, a PFCP SEID, a GTP-U TEID, or
a QFI; those belong to other protocols and are never derived here.

## Logical direction

5GSM logical peers are UE and SMF even though N1 transport passes through
the AMF. Direction is derived from the reviewed message definition as
`ue-to-smf` or `smf-to-ue`, or stays null for messages either side may
send (5GSM status). A 5GSM protocol-defined message is never labelled
UE-to-AMF merely because N1 transport passes through the AMF. A directly
observed carrier direction from the structured input overrides the
derived direction with basis `observed-carrier`. Endpoint addresses are
never mapped to network-function roles.

## Message identity and bounded support

Message identity is normalized from reviewed TS 24.501 tables:

- SUPPORTED: the bounded 5GMM subset and the bounded 5GSM subset, with
  message-local IE handling documented in `message-map.md`.
- UNSUPPORTED: known out-of-scope messages of either family
  (deregistration, configuration update, notification, NAS transport
  containers, relay messages, PDU session authentication, remote UE
  report, and similar), recognized by name only.
- UNKNOWN: message-type values outside the reviewed tables.

`result` labels (REQUEST, ACCEPT, REJECT, COMMAND, COMPLETE, STATUS, and
similar) are local normalized states derived from message identity; they
are not 3GPP wire values and not procedure verdicts.

## Relationship to NGAP transport

`ngap` and `nas-5gs` are sibling Protocol Skills. NGAP carries NAS
payloads but intentionally does not preserve their bytes, so an NGAP
event is not a sufficient input for NAS semantics; this Skill consumes
raw captures through tshark, structured NAS field exports, or synthetic
NAS metadata fixtures. The canonical cross-Protocol join is shared packet
provenance (`capture_file` plus `frame_number`); this Skill does not
parse AMF-UE-NGAP-ID or RAN-UE-NGAP-ID and never duplicates NGAP
correlation logic.

## Relationship to future PDU session Domain analysis

This Skill is message-local and encodes no PDU session state machine. The
establishment, modification, and release messages are recognized and
normalized individually; composing them into a procedure, and deciding
whether a PDU session was established, modified, or released, belongs to
future `5gc-pdu-session` Domain work that will consume this Protocol
evidence together with NGAP, PFCP, GTP-U, and SBI evidence.

## Evidence boundary

- OBSERVED: security header code, sequence number, MAC presence, extended
  protocol discriminator, message-type code, registration type code,
  identity type code, cause code, algorithm codes, service type code, PDU
  session identity, procedure transaction identity, request type, PDU
  session type, SSC mode, DNN, S-NSSAI, PDU address, QFI/5QI values.
- DERIVED: message identity names, family classification, protection
  state, direction by message definition, cause names, algorithm names,
  result labels, session-management names, timestamp conversion.
- INFERRED: protocol-local relationships strongly suggested by behavior
  but not directly proven.
- HYPOTHESIS: explanations needing more evidence.
- CONFIRMED: not claimed by this Skill for procedure outcomes.

Registration type normalization (initial, mobility updating, periodic
updating, emergency) describes the requested procedure kind; it never
implies registration success or failure. A 5GSM cause states a
session-level rejection reason; it never becomes a root cause.
