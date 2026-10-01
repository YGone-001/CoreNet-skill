# tshark Fields

Direct capture parsing invokes tshark field output with this fixed metadata-only
list:

- `frame.number`, `frame.time_epoch`, `frame.protocols`
- `ip.src`, `ip.dst`, `ipv6.src`, `ipv6.dst`
- `tcp.srcport`, `tcp.dstport`, `tcp.stream`
- `udp.srcport`, `udp.dstport`, `udp.stream`
- `sctp.srcport`, `sctp.dstport`

The command requires this exact header. A tshark version that cannot expose the
required generic fields fails clearly instead of silently changing output.
Optional values may be blank per frame. The fields do not request payload,
subscriber, message-type, or semantic session data.
