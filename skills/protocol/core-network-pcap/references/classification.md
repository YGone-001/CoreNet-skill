# Classification

Classification consumes only names present in tshark's reported protocol stack.
Known aliases normalize to `SCTP`, `TCP`, `UDP`, `TLS`, `HTTP2`, `NGAP`,
`NAS_EPS`, `NAS_5GS`, `S1AP`, `GTPV2`, `GTPU`, `PFCP`, `DIAMETER`, `SIP`,
`SDP`, and `RTP`. If no known stack token is present, the result is `UNKNOWN`.

For example, a stack containing `eth:ip:sctp:ngap` produces an `OBSERVED`
`NGAP` classification because tshark reported `ngap`. It does not identify a
message type or establish a procedure result. No port or endpoint-pattern
heuristics are implemented.
