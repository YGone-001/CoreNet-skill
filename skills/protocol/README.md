# Protocol Skills

Implemented: `core-network-pcap`, a common capture-ingestion, metadata
classification, and protocol-neutral trace-event normalization package. It does
not implement protocol message semantics or procedure diagnosis.

Implemented: `ngap`, the first telecom signaling-semantic Protocol Skill.
Version 0.1.0 supports a bounded UE-context subset of NGAP over N2:
InitialUEMessage, UplinkNASTransport, DownlinkNASTransport,
InitialContextSetup (request/response/failure), UEContextReleaseRequest,
UEContextRelease (command/complete), and Paging, plus identity-only
handling of ErrorIndication and NASNonDeliveryIndication. It extracts
RAN-UE-NGAP-ID and AMF-UE-NGAP-ID, preserves NGAP Cause category/value,
correlates frames into UE contexts scoped by capture and SCTP association,
and projects detailed events into the shared trace-event schema. It does
not decode NAS, does not model 5GC registration, and does not claim
full-Release NGAP coverage.

Planned: `nas-5gs`, `nas-eps`, `s1ap`, `gtpv2`, `gtpu`, `pfcp`, `sip`,
`sdp-rtp`, `diameter-core` and its domain layers, and `sbi-http2`.
