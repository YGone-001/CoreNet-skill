# GTP-U Protocol Model

Basis: 3GPP TS 29.281 version 19.2.0 Release 19 (GPRS Tunnelling Protocol
User Plane, GTPv1-U) for the protocol itself, and 3GPP TS 38.415 version
19.1.0 Release 19 (PDU Session User Plane protocol) for the PDU Session
Container content. Field names were cross-checked against the GTP dissector
of Wireshark/TShark as published in the Wireshark display-filter reference;
the reviewed environment had no local tshark installation, so that is
published-reference verification, not local introspection.

## Role and context

GTP-U carries user-plane packets inside a GTP tunnel. Over N3 it runs
between the 5G access network and the UPF, carried in UDP (commonly port
2152). This Skill answers protocol-local questions only: which GTP-U message
a datagram carries, which TEID it names, which outer endpoints carried it,
which bounded PDU Session Container evidence and inner packet metadata are
visible, and how much traffic was observed in one directed context.

GTP-U is also used on other interfaces (N9, S1-U, S5/S8-U). This version is
bounded to N3; the manifest owns N3 only, and no claim of full GTP-U
interface coverage is made.

## Message classes

- **User plane**: G-PDU carries the original packet (the T-PDU) inside the
  tunnel. An End Marker is a tunnel-management message sent on a data
  forwarding tunnel.
- **Path management**: Echo Request, Echo Response, Error Indication and
  the Supported Extension Headers Notification, plus Tunnel Status.

A G-PDU with a PDU Session Container may be sent without a T-PDU, for
example when the message only conveys control information.

## GTP-U header

The header is a variable-length header whose minimum length is 8 bytes. The
first octet carries:

- the **Version** field, which shall be set to 1;
- the **Protocol Type (PT)** bit, which discriminates GTP (PT = 1) from
  GTP' (PT = 0);
- the **Extension Header flag (E)**, indicating a meaningful Next Extension
  Header value;
- the **Sequence Number flag (S)**, indicating a meaningful Sequence Number
  value;
- the **N-PDU Number flag (PN)**, indicating a meaningful N-PDU Number
  value.

Then follow the Message Type (octet 2), the Length (octets 3-4), the
32-bit TEID (octets 5-8) and, when at least one of S, PN or E is set, the
optional block: Sequence Number, N-PDU Number and Next Extension Header
Type.

**Length** indicates the length in octets of the payload, i.e. the rest of
the packet following the mandatory part of the GTP-U header. This Skill uses
exactly that definition for its byte count and never mixes it with frame or
packet byte counts.

The **Sequence Number** is only meaningful when the S flag is set; the
**N-PDU Number** only when the PN flag is set; the **Next Extension Header
Type** only when the E flag is set. A field whose flag is clear is not
emitted, and this Skill never fabricates a zero in its place.

## TEID

A TEID identifies a tunnel endpoint in the receiving GTP-U entity. The
receiving side locally assigns the TEID value the transmitting side has to
use, so the same numeric TEID can legitimately exist in unrelated contexts.
The TEID is used by the receiving entity to find the PDP context, except
for the reviewed cases where it is set to all zeroes. See `teid-model.md`.

## Extension headers

An extension header is a variable-length structure of at least 4 octets:
Extension Header Length, Extension Header Content, and a Next Extension
Header Type that links to the following header (value 0 means no more
extension headers). Bits 7 and 8 of the type octet define how an unknown
extension header must be handled.

This Skill represents the chain as an array. The reviewed extension header
type table includes, among others, No more extension headers (0x00), UDP
Port (0x40), RAN Container (0x81), NR RAN Container (0x84), PDU Session
Container (0x85) and PDCP PDU Number (0xC0). An extension header type
outside the reviewed table stays UNKNOWN with its numeric value; the packet
is never dropped.

## PDU Session Container

The PDU Session Container extension header shall be transmitted in G-PDUs
over the N3 and N9 user plane interfaces and in End Marker packets over
data forwarding tunnels in 5GS. Its content is specified in TS 38.415 and
reviewed in `pdu-session-container.md`.

## User payload

The encapsulated packet (T-PDU) may be an IP datagram, an Ethernet frame,
or unstructured PDU data. This Skill preserves bounded inner packet
metadata (IP version, addresses, protocol number, L4 ports, length) and an
opacity flag, and stops there. Application payload bytes are never read,
stored, or emitted, and no application protocol is inferred from a port
number.

## Control-plane programming versus packet observation

This is the central distinction of the milestone:

- **PFCP evidence** says the control plane provisioned tunnel or rule
  information. A PFCP F-TEID or Outer Header Creation TEID records what was
  programmed.
- **GTP-U evidence** says user-plane packets were actually observed at a
  capture point. Observing a G-PDU with a given TEID proves only that such a
  packet was observed there.

Neither fact implies the other. A provisioned F-TEID does not prove that
packets used it, and an observed G-PDU does not prove delivery to the UE,
acceptance by the remote endpoint, or end-to-end success. This Skill owns
the second fact only, and it never joins the two.

## N3 bounded ownership

This Skill owns N3 GTP-U packet observation. It does not own N1 NAS session
management, N2 NGAP PDU session resources, N4 PFCP session control, N11
SBI, application protocols, or radio delivery. Cross-protocol PDU Session
composition belongs to a future Domain Skill.

## Capture-point limitation

GTP-U analysis is observation-point specific. Packets observed on a
UPF-facing interface do not prove they were transmitted over the radio to
the UE, and the absence of a G-PDU in one capture does not prove that no
G-PDU existed elsewhere in the network. Every summary and report built from
this Skill must name the capture boundary.

## Evidence boundary

- OBSERVED: message type code, header flags, TEID, sequence number, N-PDU
  number, next extension header, length, outer endpoints, extension header
  types, container PDU type / QFI / RQI / PPI, Error Indication affected
  TEID, Recovery value.
- DERIVED: message name, message class, Echo role label, extension header
  and container type names, the directed stream key, discontinuity and
  duplicate candidates.
- INFERRED: protocol-local relationships strongly suggested but not proven.
- HYPOTHESIS: explanations needing more evidence.
- CONFIRMED: deliberately rare; this Skill never confirms tunnel or
  user-plane behaviour.
