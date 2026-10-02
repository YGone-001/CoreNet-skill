# GTP-U PDU Session Container

Bounded semantics of the 5GS PDU Session Container, reviewed against
3GPP TS 38.415 version 19.1.0 Release 19 (PDU Session User Plane protocol).
The container itself is carried as a GTP-U extension header of type 0x85,
per 3GPP TS 29.281.

## Where it appears

TS 29.281 states that the PDU Session Container extension header shall be
transmitted in:

- G-PDUs over the N3 and N9 user plane interfaces, between the 5G access
  network and the UPF, or between two UPFs;
- G-PDUs over the N3mb and N19mb user plane interfaces;
- End Marker packets over data forwarding tunnels in 5GS.

A G-PDU carrying this extension header may be sent without a T-PDU, for
example when the message conveys only control information.

## PDU types

TS 38.415 defines two frame formats inside the container:

| PDU type | Name | Direction of use |
| --- | --- | --- |
| 0 | DL PDU SESSION INFORMATION | toward the access network |
| 1 | UL PDU SESSION INFORMATION | toward the UPF |

A PDU type outside this reviewed set stays numeric with a null name; no
semantics are invented.

## Bounded fields preserved

| Field | TS 38.415 basis | Notes |
| --- | --- | --- |
| pdu_type / pdu_type_name | frame format selection | DL or UL PDU SESSION INFORMATION |
| qfi | QoS Flow Identifier, present in both frame formats | preserved only when directly decoded and safely attributable |
| rqi | Reflective QoS Indicator (DL frame) | protocol evidence only; no policy conclusion |
| ppi | Paging Policy Indicator (DL frame, when the PPP bit is set) | protocol evidence only; no paging-policy conclusion |

The DL frame format also defines QMP, SNP, MSNP, PPP, BSSI, TTNBI, DL
Sending Time Stamp, DL QFI Sequence Number, DL MBS QFI Sequence Number,
BSSize and TTNB fields, and the UL frame format defines QoS-monitoring and
UL QFI Sequence Number fields. Those are outside this version's bounded
scope: this Skill does not emit them, and it makes no claim about QoS
monitoring, delay measurement, or sequence-number semantics.

## QFI

QFI is critical protocol evidence and is preserved **only** when it is
directly decoded from the container. It is never inferred from a TEID, a
DSCP value, a UDP port, a PFCP rule, or an NGAP record inside this Skill.

One GTP-U event normally represents one G-PDU context:

- exactly one QFI decoded → preserved in `pdu_session_container.qfi`;
- several container values observed → the container object is omitted and
  every observed value is preserved in
  `unbound_metadata.pdu_session_container_values` with a limitation.

No QFI is ever selected arbitrarily, and a G-PDU without a PDU Session
Container remains fully valid evidence.

## RQI and PPI

RQI and PPI are preserved as directly decoded bit or field values. This
Skill does not conclude that reflective QoS is configured correctly, that a
paging policy is correct, or that either bit was honoured by any node.

## Binding rules

The container values attach to the event when:

- structured input declares the container explicitly
  (`binding_basis: structured-input`); or
- exactly one container is observed in the message
  (`binding_basis: single-source-order`).

Otherwise the values are unbound and a limitation is recorded. Repeated
container fields are never zipped against repeated rule or extension fields
by array position.

## Not implemented

Full QoS policy semantics, 5QI interpretation, GBR/MBR evaluation, ARP
analysis, reflective-QoS policy correctness, QoS flow lifecycle across
N1/N2/N3/N4, QoS monitoring and delay measurement, and any conclusion about
subscriber policy are explicitly out of scope for this version.
