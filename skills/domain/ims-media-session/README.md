# IMS Media Session Evidence

`ims-media-session` is a bounded Domain Skill that composes accepted IMS Session,
IMS Media Signaling, SDP Analysis and SDP/RTP Transport Correlation artifacts
into branch-scoped media transport evidence.

It is not an RTP decoder, stream reconstructor, temporal media analyzer, codec
negotiation checker, QoS component or call-success detector.

## Installation

The Skill is a self-contained directory. It requires the accepted
`ims-session`, `ims-media-signaling`, `sdp-rtp` and `sdp-rtp-transport` packages
in the same repository tree. There is no network dependency and no cloud
service.

```text
skills/domain/ims-media-session/
├── SKILL.md
├── README.md
├── manifest.yaml
├── schemas/
├── scripts/
├── references/
├── examples/
└── tests/
```

## Usage

```bash
python3 skills/domain/ims-media-session/scripts/analyze-ims-media-session.py \
  --ims-session-analysis ims-session-analysis.json \
  --ims-media-signaling-analysis ims-media-signaling-analysis.json \
  --sdp-analysis sdp-analysis.json \
  --transport-correlation transport-correlation.json \
  --output ims-media-session-analysis.json \
  --report ims-media-session-report.txt
```

Exit codes:

- `0`: accepted analysis written.
- `2`: input contract, provenance or ownership failure; no analysis published.
- `6`: output destination or write failure.

The CLI does not need the endpoint HMAC key and never reads a capture.

## Inputs

1. IMS Session Analysis (`0.1.0`): attempt, branch, Dialog and release identity.
2. IMS Media Signaling Analysis (`0.3.0`): Offer/Answer exchange association.
3. SDP Analysis (`0.2.0`, event schema `1.1.0`): media-section metadata and
   optional endpoint references.
4. SDP/RTP Transport Correlation (`0.1.0`): capture-wide endpoint
   correspondence, stream references and unmatched streams.

All four must identify the same capture basename. The Domain additionally
verifies the actual SHA-256 of the supplied IMS Session and SDP files against the
IMS Media Signaling provenance, and the actual SDP SHA-256 against the Transport
Correlation provenance.

## Outputs

The analysis version is `0.1.0`. The JSON contains bounded `attempts`,
`exchanges`, `transport_observations`, `unbound_signaling_observations`,
`unmatched_rtp_streams`, conservation-checked `completeness`,
`input_provenance`, `limitations` and `not_confirmed`.

Binding scopes:

- `ATTEMPT`: shared attempt-level initial-offer transport evidence.
- `BRANCH`: one uniquely owned Dialog Branch.
- `AMBIGUOUS`: the Correlation record spans multiple attempts or branches.
- `UNBOUND`: no signaling exchange owns the SDP message(s).

Binding statuses are independent of the original transport-correlation status.
A Correlation record is never split or duplicated to manufacture branch matches.

Every observation preserves the original matching direction and publishes
`temporal_association_status = NOT_EVALUATED` and
`association_scope = CAPTURE_WIDE_ENDPOINT_CORRESPONDENCE_ONLY`.

## Compatibility impact

This Skill requires the accepted versions above and does not modify any upstream
Skill, schema or `scripts/corenet-analyze.py`. It is standalone and is not
executed by the unified workflow.

## Known limitations

- Endpoint correspondence is capture-wide; no RTP packet is associated with a
  Dialog active lifetime.
- No NAT, ICE, STUN, TURN, DTLS or SRTP interpretation.
- No RTP stream reconstruction, sequence analysis, packet loss, jitter, RTCP
  quality, MOS or QoS.
- No RTP header-extension MID demultiplexing; BUNDLE stays one shared transport.
- No codec compatibility, media delivery, two-way audio or IMS call-success
  verdict.
- Provisional SDP, PRACK, re-INVITE and UPDATE session modification remain
  outside this milestone.

## Testing

```bash
python3 -m unittest discover -s skills/domain/ims-media-session/tests -p 'test_*.py' -v
python3 scripts/validate-ims-media-session.py
```

Fixtures are synthetic and sanitized. No production capture, subscriber
identity, raw endpoint tuple or key material is used.
Temporal association remains `NOT_EVALUATED` in this Domain. Per-call bounded
temporal evidence is published by the unified application-level call diagnostics over
the accepted SIP and RTP artifacts; it never upgrades capture-wide transport
correspondence to call ownership.
