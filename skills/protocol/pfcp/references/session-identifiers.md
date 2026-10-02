# PFCP Session Identifiers

This Skill carries several distinct identifiers that are easy to confuse.
They are separate pieces of protocol evidence and must never be casually
substituted for one another.

## The identifiers

| Identifier | Scope | Where it appears | Meaning |
| --- | --- | --- | --- |
| PFCP header SEID | one session endpoint at the **receiving** PFCP entity | session related message header, octets 5-12 | "which of my session endpoints this message is for" |
| CP F-SEID | the control-plane entity's session endpoint | F-SEID IE in a Session Establishment Request | fully qualified SEID: the CP function's SEID plus its IP address |
| UP F-SEID | the user-plane entity's session endpoint | F-SEID IE in a Session Establishment Response | fully qualified SEID: the UP function's SEID plus its IP address |
| PFCP sequence number | one transaction between two peers | header octets 13-15 (session) or 5-7 (node) | request/response matching inside one peer pair |
| PDR ID | one packet detection rule | inside a PDR grouped IE | rule-local identifier |
| FAR ID | one forwarding action rule | inside a FAR grouped IE | rule-local identifier |
| QER ID | one QoS enforcement rule | inside a QER grouped IE | rule-local identifier |
| URR ID | one usage reporting rule | inside a URR grouped IE | rule-local identifier |
| F-TEID | a tunnel endpoint provisioned for a rule | inside PDI / forwarding parameters | control-plane provisioning of a TEID plus address |
| QFI | a QoS flow identifier | inside PDI or a QER | QoS flow marking |

## Why the header SEID is not "the session ID"

Per TS 29.244 clause 7.2.2.4.1, the header SEID is set by the sending
entity to the SEID value **provided by the corresponding receiving
entity**. It is the peer's identifier, not the sender's. In the Session
Establishment Request the peer SEID is not yet available, so the field is
present and set to 0 (clause 7.2.2.4.2).

Therefore:

- A header SEID of 0 is a placeholder, not a session identity.
- The header SEID in an Establishment Response equals the CP F-SEID's SEID,
  because the CP function is the receiving entity of that response.
- A later request from the CP function carries the UP F-SEID's SEID in the
  header, because the UP function is now the receiving entity.

## Why the CP and UP F-SEIDs are not interchangeable

They are allocated by different entities and identify different endpoints
of the same session. This Skill keeps them in separate fields and never
collapses them into one value, including when populating the generic trace
`session.seid` — if both roles are represented and they differ, the generic
field is omitted rather than filled with an arbitrary choice.

## Why none of them is a NAS or NGAP PDU Session ID

- A NAS PDU Session ID (N1, owned by `nas-5gs`) is a UE-side session
  identifier carried in 5GSM messages.
- An NGAP PDU Session ID (N2, owned by `ngap`) is the identifier used in
  N2 PDU Session Resource messages.
- A PFCP SEID identifies a PFCP session endpoint on N4.

They are assigned by different entities for different scopes. Their numeric
values may coincidentally match, which proves nothing. Comparing them is a
cross-protocol activity that requires a future Domain Skill with an
explicit, evidence-backed join; this Protocol Skill performs no such join
and never equates them.

## Why a PFCP SEID is not globally unique

The SEID uniquely identifies a session at one IP address of one PFCP entity
(clause 5.6.2). Two unrelated peer pairs may therefore use the same numeric
SEID. Tests cover this: the same numeric SEID on different endpoint pairs
must stay in separate transactions and separate contexts.

## Why an F-TEID is not a tunnel verdict

An F-TEID records what the control plane provisioned for a rule. It is not
an observation of a GTP-U packet, and it does not establish that a tunnel
exists, forwards traffic, or is healthy. Actual user-plane evidence belongs
to a future `gtpu` Skill.
