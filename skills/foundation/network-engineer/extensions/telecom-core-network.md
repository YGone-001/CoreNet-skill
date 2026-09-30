# Telecom Core-Network Transport Context

## Path Investigation

For EPC, IMS, 5GC, or VoWiFi environments, inspect IPv4, IPv6, dual-stack
source selection, routes, policy routes, forwarding, return paths, VRFs or
namespaces, multi-homed endpoints, and rp_filter where relevant. Asymmetric
routing, NAT, firewall state, and conntrack can affect signaling, media, or user
plane observations without defining their protocol correctness.

## MTU, DNS, and Transport

Account for GTP and IPsec encapsulation overhead, PMTUD, IPv6 fragmentation, and
unknown deployment MTU values; configuration is authoritative. Investigate A,
AAAA, SRV, NAPTR, resolver path, cache/TTL, and authoritative versus recursive
responses. SCTP, UDP, TCP, Diameter transport, SIP transport, and HTTP/2 SBI
transport are workload classifications. Common ports, where observed, are
deployment-dependent hints; reachability never proves procedure correctness.

## Evidence-Safe Examples

- OBSERVED: UDP packets leave host A and no counterpart is captured on host B.
- HYPOTHESIS: A route, firewall, NAT, or observation gap may be involved.
- NEXT EVIDENCE: Compare return route, counters, and a capture between hosts.

## Handoff to Higher Layers

Transport reachability does not establish PFCP, SIP, Diameter, or other protocol
procedure correctness. Hand off semantic questions to the applicable future
Protocol Skill and procedure questions to a future Domain Skill.
