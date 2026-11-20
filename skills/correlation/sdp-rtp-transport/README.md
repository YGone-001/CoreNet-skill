# SDP/RTP Transport Correlation

`sdp-rtp-transport` is a bounded Correlation Skill that associates accepted SDP
media transport endpoints with accepted RTP UDP transport streams. It answers
position-and-reference questions only: which observed RTP streams carry endpoint
evidence corresponding to which SDP media descriptions.

It is not an IMS media-session Domain, a call-success detector, a NAT/ICE
implementation, an RTP stream reconstructor or a QoS component.

## Installation

The Skill is a self-contained directory. It consumes the accepted `sdp-rtp`
package artifacts and reuses its version constants. There is no network
dependency and no cloud service.

```text
skills/correlation/sdp-rtp-transport/
├── SKILL.md
├── README.md
├── manifest.yaml
├── references/
├── schemas/
├── scripts/
├── examples/
└── tests/
```

## Endpoint key workflow

1. Create a local owner-only key outside the repository:

   ```bash
   python3 scripts/create-endpoint-key.py --output /secure/path/endpoint.key
   ```

2. Run both Protocol extractors for the same capture with the same key:

   ```bash
   python3 skills/protocol/sdp-rtp/scripts/parse-sdp.py \
     --input sdp-input.jsonl --output sdp-analysis.json \
     --endpoint-key-file /secure/path/endpoint.key

   python3 skills/protocol/sdp-rtp/scripts/extract-rtp-rtcp.py \
     --input rtp-input.jsonl --input-format jsonl --output rtp-analysis.json \
     --endpoint-key-file /secure/path/endpoint.key
   ```

3. Correlate the already-generated artifacts. The correlation CLI does not need
   the key:

   ```bash
   python3 scripts/correlate-sdp-rtp-transport.py \
     --sdp-analysis sdp-analysis.json \
     --rtp-rtcp-analysis rtp-analysis.json \
     --output transport-correlation.json \
     --report transport-correlation.txt
   ```

The key generator writes exactly 32 random bytes, refuses an existing file,
sets POSIX `0600`, refuses paths inside the repository and never prints key
material. No key is generated automatically by the Protocol extractors, tests
or CI.

## Outputs

The analysis version is `0.1.0`. The JSON contains bounded `correlations`,
`unmatched_streams`, conservation-checked `completeness`, `input_provenance`,
`limitations` and `not_confirmed`. Endpoint references are keyed
`endpoint-hmac-sha256:v1:<digest>` values; the shared capture context is
`endpoint-context-hmac-sha256:v1:<digest>`.

Statuses:

- `MATCHED_ENDPOINT`: one SDP media endpoint equals one RTP stream endpoint.
- `BUNDLE_TRANSPORT_MATCHED`: one resolved BUNDLE group shares one endpoint and
  one RTP stream.
- `AMBIGUOUS`: multiple streams, multiple unrelated media owners or conflicting
  endpoint sets.
- `INSUFFICIENT_EVIDENCE`: endpoint, stream, ICE or evidence status is missing.
- `UNMATCHED`: an SDP endpoint has no observed RTP stream.
- `OUT_OF_SCOPE`: disabled, multicast, unspecified, link-local,
  unresolved-name, bundle-only or unsupported-transport media.

## Compatibility impact

This Skill requires `sdp-rtp >=0.4.0`. Endpoint fields in the Protocol
artifacts are optional; running the Protocol extractors without a key preserves
the previous privacy-safe output. Adding the key changes the Protocol artifact
version and may add endpoint evidence, but does not change any previously
published field meaning.

## Known limitations

- Exact advertised endpoint correspondence only; NAT rewriting, symmetric RTP
  source-port changes, ICE candidate selection, STUN, TURN, DTLS and SRTP are not
  interpreted.
- RTP header-extension MID demultiplexing is not implemented, so a bundled stream
  is not assigned to a particular bundled media section.
- RTCP stream correlation, RTP stream reconstruction, sequence analysis, packet
  loss, jitter, MOS and QoS are not implemented.
- GTP-U inner RTP endpoint association is not claimed; encapsulated or multiple
  transport-layer candidates are unresolved.
- No IMS session identity, call success, media delivery or two-way audio verdict
  is produced.
- The unified `scripts/corenet-analyze.py` workflow does not execute this Skill.

## Testing

```bash
python3 -m unittest discover -s skills/correlation/sdp-rtp-transport/tests -p 'test_*.py' -v
python3 scripts/validate-sdp-rtp-transport.py
```

Fixtures are synthetic and sanitized. No production capture, subscriber
identity, raw endpoint tuple or key material is used.