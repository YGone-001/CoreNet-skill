# Telecom Core-Network Host Context

## Host Investigation

Use `systemctl status`, `systemctl show`, and `journalctl` to establish service
state. Mobile-core daemons, SIP servers, media engines, databases, DNS, and
IPsec services are host examples only; this file does not define their signaling
or configuration semantics. Inspect sockets with `ss` and `lsof`, including
local address, LISTEN state, UDP bind, supported SCTP endpoints, and process
ownership.

Use `ip addr`, `ip route`, `ip rule`, `ip link`, `ip neigh`, and `ip -s link`
for host networking, including namespace and VRF context. Inspect nftables,
iptables, conntrack, and, where applicable, `ip xfrm state` and `ip xfrm policy`.
Check CPU, memory, file descriptors, socket limits, disk, I/O, process limits,
and chrony or timedatectl; resource pressure or clock drift can be hypotheses,
not proof of a signaling cause.

## Evidence-Safe Examples

- OBSERVED: A process is running and owns a UDP socket.
- OBSERVED: The selected service log reports resource pressure.
- HYPOTHESIS: Host pressure may contribute to timeout symptoms.
- NEXT EVIDENCE: Compare resource counters and timing at the failure boundary.

## Handoff to Higher Layers

Process and socket state do not prove service or SIP/protocol procedure health.
Hand off semantic questions to future Protocol or Domain Skills and source
questions to a future Implementation Skill.
