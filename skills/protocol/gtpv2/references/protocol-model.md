# GTPv2-C protocol model

## Header

GTPv2-C is carried over UDP port 2123. The mandatory header is 4 octets when the
TEID flag is clear and 8 octets when it is set.

| Element | Source field | Notes |
| --- | --- | --- |
| Version | `gtpv2.version` | 2 for GTPv2. |
| Piggybacking flag (P) | `gtpv2.p` | Nested inside `gtpv2.flags`. |
| TEID flag (T) | `gtpv2.t` | Nested inside `gtpv2.flags`. |
| Message type | `gtpv2.message_type` | TS 29.274 Table 6.1-1. |
| Message length | `gtpv2.msg_length` | Octets after the first 4. |
| Header TEID | `gtpv2.teid` | Present only when T=1. |
| Sequence number | `gtpv2.seq` | 3 octets. |

`gtpv2.flags` is the raw flags octet; `gtpv2.t` and `gtpv2.p` are bit fields
nested under it in the dissector tree, so the extractor reads them from the
flags subtree rather than from the protocol root.

## Header TEID states

The header TEID is evidence about the peer context the sender addresses, not a
session identity, and it is never merged with an F-TEID IE.

| State | Condition | Typical case |
| --- | --- | --- |
| `ABSENT` | The TEID field is absent from the header (T=0). | Echo Request/Response before any context exists. |
| `ZERO` | The TEID field is present with value 0. | Initial Create Session Request addressing a peer with no TEID yet. |
| `PRESENT` | The TEID field is present with a non-zero value. | Any message inside an established control context. |

A response does not echo the request header TEID: each side addresses the TEID
the other side advertised. In the bundled laboratory exchange the Create
Session Request carries header TEID 0, the response carries the MME TEID 6
(from the request's S11 MME GTP-C F-TEID), and the following Modify Bearer
Request carries the SGW-C TEID 969 (from the response's S11/S4 SGW GTP-C
F-TEID). Correlation therefore treats the TEID relation as corroboration, never
as a matching key.

## Information-element scope

Three scopes are published, and they are never mixed:

| Scope | Where it comes from | Example |
| --- | --- | --- |
| `message` | A top-level IE of the message. | Create Session Response: Cause 16, F-TEID S11/S4 SGW GTP-C 969, F-TEID S5/S8 PGW GTP-C 1691. |
| `bearer` | An IE nested inside a Bearer Context IE (type 93). | Same message: EBI 5, Cause 16, F-TEID S1-U SGW GTP-U 34351, F-TEID S5/S8 PGW GTP-U 25193, Charging ID present. |
| `unbound` | A flat fields input where item boundaries are unavailable. | Any F-TEID from `-T fields` output. |

## Grouped Bearer Context

TS 29.274 defines the Bearer Context IE (type 93) as a grouped IE: its value is
a sequence of member IEs. The dissector renders it as a node whose children are
the member IEs, each carrying its own `gtpv2.ie_type`:

```
Bearer Context (93)
├── EBI (73)               value 5
├── F-TEID (87)            S1-U SGW GTP-U, TEID 34351
├── F-TEID (87)            S5/S8 PGW GTP-U, TEID 25193
├── Cause (2)              value 16
└── Charging ID (94)       present
```

Binding is only published when this parent-child relationship is available. The
extractor identifies a Bearer Context node by `gtpv2.ie_type == 93` and its
members by the IE nodes that are its direct children; it never infers grouping
from list order or index alignment.

## Cause scope

A message can carry two Cause IEs with the same value: one at message scope and
one inside the Bearer Context. In the bundled capture a Create Session Response
carries `16` in both places. Flattened field output renders this as `16,16` and
cannot say which is which; the PDML tree can, and the event keeps
`message_cause.scope = "message"` and `bearer_contexts[].cause.scope = "bearer"`
separately.

`pdn_connection_ie_error` and `bearer_context_ie_error` are the PCE and BCE bits
of the Cause IE. `cause_source_flag` is the raw CS bit; this Skill does not
interpret which node originated the cause.

## F-TEID

The F-TEID IE (type 87) carries an interface type, an IPv4 and/or IPv6 address,
and a TEID/GRE key. Interface type values follow TS 29.274 Table 8.22-1:

| Value | Interface |
| --- | --- |
| 0 | S1-U eNodeB GTP-U |
| 1 | S1-U SGW GTP-U |
| 4 | S5/S8 SGW GTP-U |
| 5 | S5/S8 PGW GTP-U |
| 6 | S5/S8 SGW GTP-C |
| 7 | S5/S8 PGW GTP-C |
| 10 | S11 MME GTP-C |
| 11 | S11/S4 SGW GTP-C |

## What this model does not claim

A Cause of `Request accepted` is evidence that the peer accepted that message.
It is not evidence that a PDN connection, a default bearer or an EPS bearer
lifecycle completed, and it says nothing about user-plane forwarding. Session
and bearer lifecycle reconstruction is out of scope for this Protocol Skill.
