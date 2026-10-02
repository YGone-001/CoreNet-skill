# GTP-U TEID Model

Several identifiers appear in 5G user-plane evidence. They belong to
different protocols, different layers and different scopes, and none of them
is interchangeable with another.

## The identifiers

| Identifier | Owner | Scope | Meaning |
| --- | --- | --- | --- |
| GTP-U header TEID | `gtpu` (this Skill) | one tunnel endpoint at the receiving GTP-U entity | which tunnel endpoint this datagram is for |
| PFCP F-TEID | `pfcp` | a PFCP-provisioned tunnel endpoint | control-plane provisioning: TEID plus the address the peer should use |
| PFCP Outer Header Creation TEID | `pfcp` | a FAR's forwarding parameters | control-plane provisioning of an outer header the UPF should build |
| NGAP transport tunnel information | `ngap` | an N2 PDU Session resource transfer | transport-layer tunnel information carried in an N2 transfer container |
| NAS PDU Session ID | `nas-5gs` | a UE-side session identity on N1 | which PDU session a 5GSM message concerns |
| NGAP PDU Session ID | `ngap` | an N2 PDU Session resource identity | which PDU session an N2 resource item concerns |
| PFCP SEID | `pfcp` | a PFCP session endpoint at one PFCP entity | which PFCP session a message concerns |
| QFI | `nas-5gs` / `ngap` / `gtpu` in their own contexts | a QoS flow inside one PDU session | which QoS flow a packet belongs to |

## Why a TEID is not a global tunnel identity

The receiving side of a GTP tunnel locally assigns the TEID value the
transmitting side has to use. A numeric TEID is therefore meaningful only
together with the two endpoints and the direction of the packet. Two
unrelated peer pairs may legitimately use the same numeric TEID, and the
same numeric TEID may appear in both directions between the same pair
referring to two different tunnel endpoints.

This Skill therefore keys every directed context as:

    gtpu-path:<capture>:<source>:<destination>:teid<id>

The key is DERIVED and explicitly not a standardized GTP-U identifier. Same
numeric TEIDs that differ by endpoint or by direction remain separate
contexts and are never merged, and tests enforce both cases.

## Why a TEID is not subscriber or session identity

A TEID is not an IMSI, SUPI, SUCI, 5G-GUTI or any other subscriber
identifier, and it is not a PDU Session ID. This Skill never writes a TEID
into a subscriber field and never equates it with a NAS or NGAP PDU Session
ID.

## Reviewed TEID-zero rules

TS 29.281 clause 5.1 states that the header TEID shall be set to all zeroes
for:

- the Echo Request message;
- the Echo Response message;
- the Supported Extension Headers Notification message;
- the Error Indication message.

A G-PDU and an End Marker carry the tunnel TEID instead. A GTP-U entity must
not assign the value all zeroes to its own TEID when setting up a tunnel;
for backward compatibility it must nevertheless accept an all-zeroes peer
TEID from a control-plane message and then send subsequent G-PDUs with an
all-zeroes TEID.

Consequences for this Skill:

- TEID zero is never globally treated as malformed. The reviewed rule is
  message-specific.
- `header.teid_expected_zero` records whether the reviewed message
  definition expects zero, so a deviation stays visible.
- A G-PDU observed with an all-zeroes TEID is preserved with an explicit
  limitation rather than corrected or dropped.

## Why PFCP provisioning is not GTP-U observation

A PFCP F-TEID or Outer Header Creation TEID records what the control plane
asked the user plane to program. It does not observe a GTP-U packet. Even
when the numeric values match, this Skill never joins a GTP-U TEID to a PFCP
F-TEID: that relation requires a future Domain Skill with an explicit,
evidence-backed join across both protocols and a shared observation window.

Conversely, observing a G-PDU proves only that the packet was observed at
this capture point. It does not prove that the control plane provisioned the
tunnel, that the remote endpoint accepted the packet, or that the UE
received it.

## Why an F-TEID is not a tunnel verdict

An F-TEID is control-plane provisioning evidence. It does not establish that
a tunnel exists, that it forwards traffic, or that it is healthy. Only
observed GTP-U packets say anything about observed traffic, and even then
only about the capture point.
