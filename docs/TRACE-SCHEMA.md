# Normalized Trace Event Contract

`shared/schemas/trace-event.schema.json` defines one protocol-neutral normalized event. It can represent future NGAP, NAS-EPS, NAS-5GS, S1AP, GTPv2, GTP-U, PFCP, SIP, Diameter, RTP, and SBI/HTTP2 observations without pretending their identifiers are interchangeable.

The required minimum is `timestamp` and `protocol`. Message, network-function, subscriber, session, correlation, result, packet, and evidence data are optional because not every protocol exposes them. A producer must set unavailable values to `null` or omit optional fields; it must not invent identifiers. `evidence.level` uses the frozen evidence vocabulary and `evidence.source` identifies the primary artifact.

Correlation fields are opaque identifiers from their source protocol. Consumers must retain source context and must not infer identity solely from a matching value in unrelated protocols.
