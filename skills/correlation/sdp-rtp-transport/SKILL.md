# SDP/RTP Transport Correlation

## Purpose

Match accepted SDP media transport endpoints against observed RTP UDP
transport streams using exact capture-scoped HMAC endpoint equality. The Skill
answers only which observed RTP streams carry endpoint evidence corresponding to
which SDP media descriptions.

It does not answer whether a call succeeded, whether media was delivered, whether
audio is bidirectional, whether codecs negotiated, whether NAT or ICE succeeded,
whether RTP quality is acceptable, or which network function caused a media
failure.

## Inputs

1. SDP Analysis JSON (`sdp-rtp` analysis `0.2.0`, event schema `1.1.0`) with
   optional `transport_endpoint` evidence.
2. RTP/RTCP Analysis JSON (`rtp-rtcp` analysis `0.4.0`, event schema `1.2.0`)
   with optional RTP source/destination endpoint references.

Both artifacts must describe the same privacy-safe capture basename and the same
capture SHA-256. Endpoint references are already opaque; the correlation CLI
does not need the HMAC key.

## Workflow

1. Validate accepted analysis names, versions, event schemas and capture
   provenance.
2. Reject artifacts from different captures or different endpoint keys.
3. Collect SDP media sections with an `ESTABLISHED` endpoint reference.
4. Group accepted RTP packets by capture identity and `udp.stream`.
5. Match exact endpoint references; preserve source versus destination
   direction.
6. Group media sections only when they share one resolved BUNDLE group and one
   endpoint reference.
7. Publish `MATCHED_ENDPOINT`, `BUNDLE_TRANSPORT_MATCHED`, `AMBIGUOUS`,
   `INSUFFICIENT_EVIDENCE`, `UNMATCHED` or `OUT_OF_SCOPE`.
8. Preserve counts, missing evidence, conflicts and limitations.

## Evidence Rules

- `OBSERVED`: accepted SDP and RTP/RTCP Protocol evidence.
- `DERIVED`: the transport correspondence itself.
- `STRONG` means exact capture-scoped HMAC endpoint equality only. It never means
  confirmed IMS session identity, call identity or successful media delivery.
- One SDP endpoint matching one RTP UDP stream is `MATCHED_ENDPOINT`.
- Multiple candidate streams, multiple unrelated media sections sharing one
  endpoint, or a stream whose endpoint set changes remain `AMBIGUOUS`; no
  candidate is selected.
- A resolved BUNDLE group whose media sections share one endpoint and one stream
  is `BUNDLE_TRANSPORT_MATCHED`. The Skill does not claim that the stream was
  demultiplexed into a particular bundled media section.
- Missing UDP stream identity, missing endpoint token, ICE-based endpoint
  unavailability or incomplete packet endpoint evidence never becomes an
  established association.
- Timestamp proximity is never used to create or select an association.
- Advertised/observed endpoint differences are `UNMATCHED` or
  `INSUFFICIENT_EVIDENCE`; no NAT mapping is invented.

## Failure Handling

Malformed, contradictory, cross-capture, duplicate-reference or different-key
artifacts return a non-zero exit before output is written. Missing endpoint or
stream evidence is published explicitly as insufficient, unmatched or
out-of-scope evidence, never as a fabricated match.

## Validation

```bash
python3 -m unittest discover -s skills/correlation/sdp-rtp-transport/tests -p 'test_*.py' -v
python3 scripts/validate-sdp-rtp-transport.py
```

Fixtures are synthetic and sanitized. No capture, subscriber identity, key file
or raw endpoint is published.