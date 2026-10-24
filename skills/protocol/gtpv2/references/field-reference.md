# Field reference

Fields were verified against the TShark 4.7.1 GTPv2 dissector registry
(`tshark -G fields`, `tshark -G values`). Values in the "observed" column come
from the bundled laboratory PDML excerpt; they are illustrative, not constants.

## PDML input

| Field | Meaning | Observed example |
| --- | --- | --- |
| `frame.number` | Frame number. | `8` |
| `frame.time_epoch` | Capture timestamp. | `1792850867.419250457` |
| `ip.src` / `ip.dst` | Transport endpoints. | `127.0.0.3` / `127.0.0.2` |
| `udp.srcport` / `udp.dstport` | GTPv2-C port 2123. | `2123` |
| `gtpv2.version` | Protocol version. | `2` |
| `gtpv2.flags` | Raw flags octet. | `0x48` |
| `gtpv2.t` | TEID-present flag, nested in flags. | `1` |
| `gtpv2.p` | Piggybacking flag, nested in flags. | `0` |
| `gtpv2.message_type` | Message type code. | `33` |
| `gtpv2.msg_length` | Message length. | `103` |
| `gtpv2.teid` | Header TEID; absent when T=0. | `0x00000006` |
| `gtpv2.seq` | Sequence number. | `0x000017` |
| `gtpv2.ie_type` | IE type discriminator on every IE node. | `93` |
| `gtpv2.instance` | IE instance. | `0` |
| `gtpv2.cause` | Cause value inside a Cause IE. | `16` |
| `gtpv2.pce` / `gtpv2.bce` | PCE / BCE bits of the Cause IE. | `False` |
| `gtpv2.cs` | CS bit of the Cause IE. | `False` |
| `gtpv2.ebi` | EPS Bearer ID. | `5` |
| `gtpv2.f_teid_interface_type` | F-TEID interface type. | `11` |
| `gtpv2.f_teid_gre_key` | F-TEID TEID/GRE key. | `0x000003c9` |
| `gtpv2.f_teid_ipv4` / `.ipv6` | F-TEID address. | `127.0.0.3` |
| `gtpv2.f_teid_v4` / `.v6` | Address-family presence bits. | `True` / `False` |
| `gtpv2.apn` | APN network name. Read for length only; never published. | `internet` |
| `gtpv2.pdn_type` | PDN type (IE 99, or inside PAA IE 79). | `1` |
| `gtpv2.pdn_addr_and_prefix.ipv4` | PAA address. Read for family only. | `10.45.0.7` |
| `gtpv2.rat_type` | RAT type. | `6` |
| `gtpv2.ambr_up` / `.ambr_down` | AMBR values. | `1000000` |
| `gtpv2.response_to` | Decoder transaction link: frame number of the request. | `5` |
| `gtpv2.response_time` | Decoder transaction response time. | `0.083312560` |

Identity-bearing fields (`gtpv2.imsi`, `gtpv2.msisdn`, `gtpv2.mei`,
`gtpv2.tmsi`) are read only to record presence and are never emitted.

## Flat fields JSONL input

A JSON object per line with any of the following keys. Missing keys are treated
as unavailable; a repeated field is a comma-separated list in decoder order.

```text
frame.number, frame.time_epoch,
ip.src, ip.dst, ipv6.src, ipv6.dst, udp.srcport, udp.dstport,
gtpv2.version, gtpv2.flags, gtpv2.t, gtpv2.p, gtpv2.message_type,
gtpv2.msg_length, gtpv2.teid, gtpv2.seq, gtpv2.cause, gtpv2.ebi,
gtpv2.apn, gtpv2.pdn_type, gtpv2.pdn_addr_and_prefix.ipv4,
gtpv2.pdn_addr_and_prefix.ipv6, gtpv2.rat_type, gtpv2.ambr_up,
gtpv2.ambr_down, gtpv2.f_teid_interface_type, gtpv2.f_teid_gre_key,
gtpv2.f_teid_ipv4, gtpv2.f_teid_ipv6
```

`frame.number`, `frame.time_epoch` and `gtpv2.message_type` are required. A
record missing one of them is rejected with exit 5.

### Flat input limitations

- Grouped IE boundaries are unavailable, so `bearer_contexts` stays empty and
  `unbound_ie_metadata` carries the decoded values with an explicit limitation.
- `f_teids[].scope` is `unbound`; a bearer-nested F-TEID and a message-scope
  F-TEID cannot be told apart.
- Message-scope and bearer-scope Cause values arrive as one list; the first is
  published as `message_cause` and the remainder as
  `unbound_ie_metadata.additional_causes`.
- Cause PCE/BCE/CS bits are not part of the documented flat field set.
- Identity-IE presence is only available if the producer included those fields,
  which the default field set does not.

## Value tables

Message types, cause values, interface types, PDN types and RAT types are
declared in `scripts/gtpv2_model.py`. They are bounded subsets of the TS 29.274
tables and were checked against the decoder value tables; a code outside the
subset keeps its numeric value and is published with a `null` name rather than
an invented one.
