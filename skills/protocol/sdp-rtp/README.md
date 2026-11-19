# sdp-rtp Protocol Skill

Bounded, privacy-safe structural parsing of explicitly supplied SDP bodies.

The parser follows the RFC 8866 line grammar and recognised media-attribute vocabulary.
It publishes session/media structure and evidence classifications only. It does not
extract RTP, reconstruct streams, compute RTCP statistics, interpret Offer/Answer,
associate SIP dialogs, correlate media endpoints, or produce IMS media/call verdicts.

## Usage

```bash
python3 skills/protocol/sdp-rtp/scripts/parse-sdp.py \
  --input skills/protocol/sdp-rtp/examples/inputs/sdp-cases.jsonl \
  --output /tmp/sdp-analysis.json \
  --report /tmp/sdp-analysis.txt \
  --force
```

Input is JSONL with `source_reference`, `capture_file`, `capture_sha256`,
`frame_number`, `frame_reference`, `message_occurrence` and `sdp_body`. All records
must share one capture identity.

## Output

`analysis.json` contains per-message evidence status, session structure, independent
media sections, recognised attributes, unknown attributes, redacted sensitive
attributes, reference integrity and bounded counts. `report.txt` is a human-readable
summary.

## Privacy

Raw SDP bodies, IP addresses, domain names, session names, usernames, session IDs,
ICE credentials, candidate data, fingerprints, crypto keys and arbitrary attribute
values are never published. Only bounded classifications, lengths and safe reviewed
metadata values are exposed.

## Limitations

Capture extraction, SIP-to-SDP association, SDP Offer/Answer pairing, RTP/RTCP,
media QoS, ICE verification and IMS media semantics are outside this Skill. The
presence of an `m=` line or a `200 OK`-adjacent SDP body does not establish media
delivery or call success.

See `SKILL.md`, `references/field-reference.md`, `references/failure-cases.md` and
`references/privacy.md`.