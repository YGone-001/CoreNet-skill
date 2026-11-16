# TShark field and PDML reference

Verified against Wireshark/TShark 4.2.2.

## Header fields

| Field | Meaning |
| --- | --- |
| `diameter.version` | protocol version |
| `diameter.length` | declared message length |
| `diameter.flags` | flags octet |
| `diameter.flags.request` | R bit |
| `diameter.flags.proxyable` | P bit |
| `diameter.flags.error` | E bit |
| `diameter.flags.T` | T bit |
| `diameter.cmd.code` | Command Code |
| `diameter.applicationId` | Application-ID |
| `diameter.hopbyhopid` | Hop-by-Hop Identifier |
| `diameter.endtoendid` | End-to-End Identifier |

## AVP fields

| Field | Meaning |
| --- | --- |
| `diameter.avp` | one AVP node, including nested group children |
| `diameter.avp.code` | AVP Code |
| `diameter.avp.flags` | AVP flags octet |
| `diameter.flags.vendorspecific` | V bit |
| `diameter.flags.mandatory` | M bit |
| `diameter.avp.flags.protected` | P bit |
| `diameter.avp.vendorId` | Vendor-ID when V is set |
| `diameter.avp.len` | AVP length |
| `diameter.avp.pad` | padding, never published as a value |
| `diameter.Result-Code` | base result value |
| `diameter.Experimental-Result-Code` | vendor result value |
| `diameter.Session-Id` | session identifier; value withheld |
| `diameter.User-Name` | subscriber identifier; value withheld |

Grouped AVPs appear as `diameter.avp` fields nested inside a parent
`diameter.avp` field. Flat `-T fields` output does not prove child ownership and
is therefore not used for grouped structure.

## PDML expectations

- One `proto name="diameter"` node per Diameter message in a frame.
- `size` on the Diameter proto is the observed dissected length.
- `frame.number` and `frame.time_epoch` provide provenance.
- `sctp` or `tcp` plus `ip`/`ipv6` provide transport identity.

## Sanitized dissector-record JSONL

Each line is a JSON object with:

```text
capture_file frame_number frame_time_epoch message_occurrence
transport {protocol source_address source_port destination_address
           destination_port verification_tag stream_id}
header    {version length flags {request proxyable error retransmitted}
           command_code application_id hop_by_hop_id end_to_end_id}
avps      [{code name vendor_specific mandatory protected vendor_id length
            value children}]
```

The replay path re-applies privacy classification; a supplied sensitive value is
never published.