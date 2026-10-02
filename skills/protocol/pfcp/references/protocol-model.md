# PFCP Protocol Model

Basis: 3GPP TS 29.244 version 19.6.0 Release 19 (Interface between the
Control Plane and the User Plane nodes), reviewed through the PFCP
dissector of Wireshark/TShark as published in the Wireshark display-filter
reference. The reviewed environment had no local tshark installation, so
field names are published-reference verified rather than locally re-dumped;
that verification debt is recorded in `field-reference.md`. Universal
Release coverage is not claimed.

## Role and context

PFCP is the control protocol between a control-plane function and a
user-plane function. Over N4 it is used between the SMF and the UPF. This
Skill answers protocol-local questions only: which PFCP message a datagram
carries, which transaction it belongs to, which session identifiers it
exposes, which rule groups it provisions, and which Cause it states. It
does not decide why a PDU session failed and it does not observe the user
plane.

## Message header

PFCP uses a variable-length header whose length is a multiple of four
octets (clause 7.2.2.1).

Octet 1:

- bit 1 — the S flag, which indicates whether the SEID field is present;
- bit 2 — the MP flag; when set, octet 16 carries the message priority;
- bit 3 — the FO (Follow On) flag, indicating another PFCP message follows
  in the same UDP/IP packet;
- bits 4-5 — spare, set to zero by the sender;
- bits 6-8 — the version field.

Octet 2 is the message type. Octets 3-4 are the message length, which
excludes the mandatory part of the header.

Two header layouts exist:

- **Node related messages** (clause 7.2.2.2) carry no SEID field and are
  laid out as version/flags, message type, message length, three-octet
  sequence number, one spare octet.
- **Session related messages** (clause 7.2.2.3) additionally carry an
  eight-octet SEID between the message length and the sequence number, and
  a message-priority octet after the sequence number.

This Skill records the observed S flag and reports whether a SEID field is
expected for the reviewed message type.

## Transaction sequence number

The sequence number is a three-octet field (0..16777215). It identifies a
transaction between two PFCP peers. It is scoped to a peer pair: two
independent peer pairs may reuse the same sequence number, so this Skill
never correlates a request with a response on the sequence number alone.
See `correlation.md`.

## SEID

A Session Endpoint Identifier identifies a PFCP session at one IP address
of a PFCP entity (clause 5.6.2). In the header, the SEID field
"unambiguously identify[ies] a session endpoint in the receiving Packet
Forward Control entity" (clause 7.2.2.4.1).

Two consequences matter for evidence:

- The header SEID is set by the sending entity to the SEID value provided
  by the corresponding receiving entity. It is therefore the **peer's**
  identifier, not the sender's own.
- When the peer's SEID is not available the field is still present and is
  set to 0 (clause 7.2.2.4.2). In particular, the **PFCP Session
  Establishment Request on Sxa/Sxb/Sxc/N4** carries SEID 0.

This Skill never "corrects" a zero SEID; it records the observed value and
sets `header.seid_expected_zero` from the reviewed message definition.

## F-SEID

The F-SEID is the Fully Qualified SEID: a SEID together with the IP address
of the PFCP entity that allocated it. The reviewed dissector reference
exposes only `pfcp.f_seid.ipv4`, `pfcp.f_seid.ipv6` and
`pfcp.f_seid_flags.*`; there is no filterable field for the F-SEID's own
64-bit SEID value, so that value is accepted from structured input only.

Role determination:

- A PFCP Session Establishment Request carries the **CP F-SEID** (the
  control-plane function's own identifier and address).
- A PFCP Session Establishment Response carries the **UP F-SEID**.
- For other message types the CP/UP role is not derivable, so a flattened
  F-SEID is left unbound with a limitation rather than assigned a role.

## Establishment identity transition

The reviewed behaviour, verified in clause 7.2.2.4:

    Est. Request   header SEID = 0        (peer SEID not yet available)
                   CP F-SEID  = <cp seid>  (allocated by the CP function)
    Est. Response  header SEID = <cp seid> (SEID provided by the receiving
                                            entity, i.e. the CP function)
                   UP F-SEID  = <up seid>  (allocated by the UP function)
    Later messages header SEID = <up seid> (the UP function is now the
                                            receiving entity)

Do not assume the identifier visible in an Establishment Request is
identical to the identifier used in all subsequent headers. The fixture
`examples/extracted/establishment.jsonl` covers this transition, and
`tests/test_pfcp.py` asserts it.

## Node context

Node related messages carry a Node ID (IPv4, IPv6 or FQDN) and a Recovery
Time Stamp instead of a session context. Association Setup establishes the
PFCP association that must exist before session messages are accepted.
Heartbeat may be initiated by either node, so its logical direction is left
null rather than guessed.

## PFCP session context

A PFCP session is created by Session Establishment and is addressed by the
pair of F-SEIDs. Every session related message carries the peer's SEID in
the header. This Skill groups events into protocol-local session context
only from directly observed identifiers and endpoint scope; it never
overmerges, and it never builds a PDU Session lifecycle.

## Grouped information elements

A Grouped IE contains other IEs, and each entry opens a new scope level
(clause 7.2.3.3). The same grouped IE type may appear several times in one
message, once per rule. Flattened dissector output destroys that
parent-child structure, so this Skill never zips repeated fields by
position; see `rule-model.md` and `failure-cases.md`.

## Session rules

A PFCP session is provisioned as rule groups:

- **PDR** — packet detection rule: an identifier, a precedence, and packet
  detection information (source interface, F-TEID, UE IP address, Network
  Instance, QFI) plus references to the FAR, QER and URR identifiers that
  apply to matched traffic.
- **FAR** — forwarding action rule: an identifier, an apply action, and
  forwarding parameters such as the destination interface and Outer Header
  Creation.
- **QER** — QoS enforcement rule: an identifier, gate status, QFI, and
  maximum/guaranteed bit rates.
- **URR** — usage reporting rule: an identifier and measurement presence.

The same rule type may appear under Create, Update or Remove groupings. The
operation comes from the grouped IE context, never from the identifier.

## Control-plane provisioning versus user-plane observation

Everything this Skill extracts from PFCP is **control-plane provisioning
evidence**. An F-TEID or an Outer Header Creation TEID records what the
control plane asked the user plane to program; it does not observe a
GTP-U packet and cannot prove that a tunnel carries traffic. Actual
user-plane evidence belongs to a future `gtpu` Skill.

## N4 ownership boundary

This Skill owns N4 PFCP message and rule evidence only. It does not own NAS
session management (N1), NGAP PDU session resources (N2), GTP-U (N3),
PFCP-adjacent user-plane behaviour, or SBI/N11 service operations. PFCP
Network Instance is not automatically a DNN or APN, and a PFCP SEID is not
a NAS or NGAP PDU Session ID.

## Evidence boundary

- OBSERVED: message type code, header flags, SEID, sequence number,
  priority, message length, endpoints, Cause, rule identifiers, F-TEID and
  Outer Header Creation values, Network Instance, UE IP Address, QFI.
- DERIVED: message name, procedure family, logical direction, message-level
  result label, source/destination interface names, transaction keys,
  correlation strength, binding basis.
- INFERRED: protocol-local relationships strongly suggested but not proven.
- HYPOTHESIS: explanations needing more evidence.
- CONFIRMED: deliberately rare; this Skill does not confirm end-to-end root
  cause, session success, or user-plane forwarding.
