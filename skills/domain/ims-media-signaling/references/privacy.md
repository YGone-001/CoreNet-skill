# Privacy

## Never published

The analysis JSON, text report, examples and tests never publish:

- raw SDP bodies;
- raw SIP bodies;
- Call-ID values;
- SIP URIs;
- From, To or Contact tags;
- subscriber identity values such as IMPI, IMPU, MSISDN or IMEI;
- raw IPv4 or IPv6 addresses;
- ICE username fragments, passwords or credentials;
- certificate or DTLS fingerprint digests;
- SRTP key material;
- arbitrary FMTP parameter values;
- unreviewed SDP attribute values.

## Published

Only privacy-safe references and structural metadata:

- capture-scoped SIP Event references such as
  `sip-event:synthetic-capture.pcapng:12.1`;
- capture-scoped IMS Session, SDP and exchange references;
- association status, exchange type, observation type and reason codes;
- bounded counts and conservation counters;
- capture file name, SDP capture SHA-256 and input file SHA-256 values;
- role labels `OFFERER` and `ANSWERER`;
- `negotiation_compatibility = NOT_EVALUATED`.

The capture SHA-256 is a capture identity, not subscriber data. The SIP Event
artifact does not publish a capture SHA-256; the Domain publishes the SHA-256 of
the supplied SIP Event file for provenance verification and never claims it is a
capture hash.

## Boundary

This Domain consumes artifacts that were already redacted by the accepted SIP
and SDP Protocol Skills. It does not read PCAP files, decode packets or open SDP
bodies. A caller that supplies unredacted intermediate data outside these
artifacts is outside the supported contract.

## Tests

The test suite asserts that private SIP tokens, addresses, Call-ID and tag
values, and raw SDP lines (`v=`, `m=`, `a=rtpmap`) never appear in the JSON
analysis or the text report.