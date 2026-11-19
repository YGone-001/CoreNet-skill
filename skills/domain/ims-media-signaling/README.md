# IMS Media Signaling

`ims-media-signaling` is a bounded Domain Skill that associates accepted SIP
session attempts and dialog branches with accepted SDP structural messages. It
answers position-and-reference questions only: which initial INVITE carries an
offer, which accepted branch carries an answer, and which SDP-bearing messages
remain unbound, provisional or out of scope.

It is not a media analyzer, a negotiation checker, a call-success detector or
an RTP/QoS component.

## Installation

The Skill is a self-contained directory. It requires the accepted `sip`,
`sdp-rtp` and `ims-session` packages in the same repository tree because it
consumes their artifacts and reuses their version constants. There is no
network dependency and no cloud service.

```text
skills/domain/ims-media-signaling/
├── SKILL.md
├── README.md
├── manifest.yaml
├── references/
├── schemas/
├── scripts/
├── examples/
└── tests/
```

## Usage

```bash
python3 skills/domain/ims-media-signaling/scripts/analyze-ims-media-signaling.py \
  --sip-events /path/to/sip-events.jsonl \
  --ims-session /path/to/ims-session-analysis.json \
  --sdp-analysis /path/to/sdp-analysis.json \
  --output /path/to/ims-media-analysis.json \
  --report /path/to/ims-media-report.txt
```

Exit codes:

- `0`: accepted analysis written.
- `2`: input contract, provenance or reference failure; no analysis published.

Use `--force` only to replace intentional outputs; the CLI never overwrites an
input artifact.

## Inputs

1. SIP Event JSONL from the accepted SIP Protocol Skill (schema `1.0.0`).
2. IMS Session Analysis JSON from the accepted IMS Session Domain (`0.1.0`).
3. SDP Analysis JSON from `parse-sdp.py` (`sdp-rtp` analysis `0.1.0`, SDP event
   schema `1.0.0`).

All three must describe the same capture identity. The IMS Session artifact's
`event_sha256` must equal the SHA-256 of the supplied SIP Event file.

## Outputs

The analysis JSON contains bounded `exchanges`, `unbound_observations`,
conservation-checked `completeness`, `input_provenance`, `limitations` and
`not_confirmed`. References remain resolvable to the originating artifacts.

## Known limitations

- SDP negotiation compatibility is always `NOT_EVALUATED`.
- Reliable provisional responses and PRACK Offer/Answer are not interpreted
  because the accepted SIP Event contract does not expose 100rel, RSeq, RAck or
  complete PRACK binding.
- re-INVITE, UPDATE, INFO and other in-dialog SDP bodies are preserved as
  out-of-scope observations.
- No RTP stream, endpoint correlation, media QoS, Diameter Rx or charging
  evidence is produced.
- The unified `scripts/corenet-analyze.py` workflow does not execute this Skill
  in this phase because the accepted SIP Event contract deliberately does not
  publish message bodies.

## Testing

```bash
python3 -m unittest discover -s skills/domain/ims-media-signaling/tests -p 'test_*.py' -v
python3 scripts/validate-ims-media-signaling.py
```

Fixtures are synthetic and sanitized. No production capture, subscriber
identity or credential material is used.