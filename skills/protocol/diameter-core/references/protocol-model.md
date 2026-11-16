# Diameter base protocol model

## Message header

```text
version             1 octet
length              declared message length
flags               R P E T plus reserved bits
command code        4 octets
application id      4 octets
hop-by-hop id       4 octets
end-to-end id       4 octets
AVPs                zero or more
```

The R bit identifies a Request; an Answer has R clear. P is proxyable, E marks a
protocol error and T marks a potentially retransmitted message. Individual bits
are published separately and are never collapsed into one opaque flag.

## Reviewed base commands

| Code | Command |
| --- | --- |
| 257 | Capabilities-Exchange |
| 258 | Re-Auth |
| 271 | Accounting |
| 274 | Abort-Session |
| 275 | Session-Termination |
| 280 | Device-Watchdog |
| 282 | Disconnect-Peer |

Other command codes are published numerically with `command_name = null` and
`command_scope = APPLICATION_OR_UNKNOWN`. Application-ID 0 is the common base
application; every other Application-ID is preserved numerically and marked
unsupported. A numeric Application-ID never implies an S6a, Gx, Rx or IMS
procedure.

## Result namespaces

`Result-Code` (AVP 268) belongs to the base result namespace. A reviewed subset
of RFC 6733 base values receives a name. Unknown base values keep their numeric
code and publish no name.

`Experimental-Result` (AVP 297) is a grouped AVP that may contain
`Experimental-Result-Code` (298) and `Vendor-Id` (266). That code is always
published in the vendor-specific namespace with no base name. The Skill never
copies a base success or failure meaning into an experimental code.

A protocol error flag is separate from the result code. It is published as an
observed header flag and is not turned into a procedure verdict.

## Identifiers

- The Hop-by-Hop Identifier is scoped to one Diameter transport hop and is used
  for Request/Answer matching.
- The End-to-End Identifier is a Diameter header identifier. It is not a telecom
  session identity and does not identify a subscriber.
- Session-Id is a Diameter AVP and is published only as opaque presence and
  length metadata because a real value may embed a subscription identifier.

## Message occurrence

A frame may contain more than one Diameter message. The Skill publishes a
1-based `message_occurrence` within the frame and keeps protocol-local
references stable by capture, frame and occurrence.

## Transport

Diameter is supported over TCP and SCTP where the installed decoder reassembles
a complete message.

- TCP association identity uses `tcp.stream` when available.
- SCTP association identity uses the unordered endpoint and port pair; the
  verification tag remains published evidence but is direction-specific and is
  not used as the association key.
- A transport segment without a complete Diameter message is not published as a
  complete observed message.

## Application boundary

The Skill owns only base-protocol meaning. It does not answer whether an EPC
Attach, IMS registration, charging operation, bearer activation or VoLTE call
succeeded. Application-specific Skills may consume these events later.