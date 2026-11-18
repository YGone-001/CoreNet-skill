# IMS Registration Domain

## Purpose

Answer WHAT IMS registration evidence is present in already-extracted SIP and
optional Diameter IMS Cx/Dx protocol evidence, WHICH SIP REGISTER transactions can
be grouped into one evidence-supported registration attempt, and WHICH registration
lifecycle observations are supported. This is a Domain-layer Skill: it consumes
protocol evidence and publishes bounded procedure evidence. It never decodes packets,
reconstructs subscriber identity, verifies cryptographic authentication or issues IMS
session, media, call or root-cause verdicts.

## Scope

- Inventory SIP REGISTER transactions from the accepted SIP transaction document.
- Group multiple REGISTER transactions into a registration attempt only when
  capture, Call-ID, Request-URI, From identity and CSeq evidence support it.
- Preserve 401 and 407 as authentication challenges, not terminal failures.
- Recognize an authorized retry only when a distinct later REGISTER follows the
  observed challenge with a compatible CSeq and the appropriate credential header.
- Distinguish initial-registration candidates, re-registration candidates, refresh
  observations and de-registration requests.
- Preserve Expires, Contact expires, wildcard Contact and non-wildcard Contact
  evidence. RFC 3261 all-bindings removal requires `Contact: *` with `Expires: 0`;
  wildcard alone, a nonzero Expires, a mixed Contact set or malformed expiration
  evidence is retained as invalid or incomplete protocol evidence.
- Classify negative SIP responses and keep missing responses as `OPEN_IN_CAPTURE`.
- Preserve multi-hop REGISTER observations without claiming proxy roles or
  forwarding relationships.
- Consume optional Diameter IMS Cx/Dx observations as an independent inventory.
- Keep SIP-to-Diameter association `NOT_ESTABLISHED` without a privacy-safe
  subscriber identity bridge.
- Produce a deterministic timeline with truthful total/published/omitted accounting.
  SIP and Diameter rows from unverified sources are source-local only and never claim
  a global frame order.

## Non-Goals

- No IMS session establishment, session modification, media, SDP or RTP analysis.
- No Diameter Rx, Sh or charging analysis.
- No SIP or Diameter packet decoding, transaction rematching or Dialog analysis.
- No P-CSCF, I-CSCF or S-CSCF role inference from addresses, ports or hostnames.
- No cryptographic authentication verification, authentication-vector handling or
  proof that a registration remains active.
- No fabricated cross-protocol subscriber identity, time-window or address-based
  association.
- No IMS failure-boundary orchestration, root cause or end-to-end VoLTE verdict.

## Inputs

| Input | Description |
| --- | --- |
| SIP capture / PDML / sanitized JSONL | The accepted SIP Protocol input modes. The same capture-local private message records and transaction correlator are reused. |
| Diameter IMS analysis JSON | Optional accepted `diameter-ims` Cx/Dx analysis document. It is never decoded or rematched here. |

A SIP-only analysis is fully supported. A supplied but invalid Diameter artifact is
an input error, not an absence.

## Outputs

- `schemas/ims-registration-analysis.schema.json`
- Optional plain-text report

The output separates:

- SIP REGISTER transaction inventory;
- registration attempts;
- Diameter Cx/Dx observations;
- cross-protocol associations;
- timeline;
- completeness accounting;
- limitations and `not_confirmed`.

## Evidence semantics

All registration conclusions are `DERIVED` from observed SIP or Diameter evidence.
`OBSERVED` applies to source events. A SIP 200 OK to REGISTER is an observed
registration response, not proof of persistent registration, HSS assignment or call
reachability. A 401/407 is an authentication challenge, not a terminal failure.
Authorization presence does not prove cryptographic authentication. Diameter
success is an independent application result.

## Registration model

| Dimension | Values |
| --- | --- |
| registration type | `INITIAL_REGISTRATION_CANDIDATE`, `INITIAL_REGISTRATION_SUPPORTED`, `RE_REGISTRATION_CANDIDATE`, `REFRESH_OBSERVED`, `DEREGISTRATION_REQUESTED`, `UNDETERMINED` |
| authentication evidence | `NOT_OBSERVED`, `CHALLENGE_OBSERVED`, `RETRY_OBSERVED`, `CHALLENGE_RETRY_ASSOCIATED`, `CHALLENGE_WITHOUT_OBSERVED_RETRY`, `RETRY_WITHOUT_OBSERVED_CHALLENGE`, `AUTHENTICATION_OUTCOME_UNPROVED` |
| SIP outcome | `SUCCESS_RESPONSE_OBSERVED`, `NEGATIVE_RESPONSE_OBSERVED`, `OPEN_IN_CAPTURE`, `AMBIGUOUS`, `INCOMPLETE_EVIDENCE` |
| Diameter status | `OBSERVED`, `NOT_OBSERVED_IN_SUPPLIED_ARTIFACT`, `NOT_SUPPLIED`, `AMBIGUOUS`, `CONFLICTING` |
| cross-protocol association | `ESTABLISHED`, `SUPPORTED`, `AMBIGUOUS`, `NOT_ESTABLISHED`, `INSUFFICIENT_EVIDENCE` |

See `references/registration-procedures.md`, `references/authentication-evidence.md`,
`references/diameter-context.md` and `references/evidence-model.md`.

## Privacy

Raw Call-ID, From/To tags, SIP URIs, Request-URI, Contact values, subscriber
identities, authentication headers, nonces, responses and message bodies remain in
memory only. The published document uses evidence-derived opaque references and
numeric or boolean protocol facts. See `references/privacy.md`.

## Reproduction

```bash
python3 skills/domain/ims-registration/scripts/analyze-ims-registration.py \
  skills/domain/ims-registration/examples/input/registration-cases.jsonl \
  --output /tmp/ims-registration.json \
  --report /tmp/ims-registration.txt \
  --force

python3 skills/domain/ims-registration/scripts/analyze-ims-registration.py \
  skills/domain/ims-registration/examples/input/registration-cases.jsonl \
  --diameter-ims skills/domain/ims-registration/examples/input/diameter-ims-cases.json \
  --output /tmp/ims-registration.json \
  --report /tmp/ims-registration.txt \
  --force

python3 -m unittest discover -s skills/domain/ims-registration/tests -p 'test_*.py' -v
python3 scripts/validate-ims-registration.py
```

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Analysis succeeded. |
| 2 | Invalid SIP or Diameter input. |
| 3 | No plaintext SIP messages observed. |
| 4 | TShark is unavailable. |
| 5 | TShark execution or dissection failure. |
| 6 | Output destination or publication failure. |

## Known limitations

- Real IMS capture compatibility is not claimed without an authorized capture.
- Cx/Dx interface identity and SIP-to-Diameter subscriber identity remain unproved.
- Multi-hop REGISTER observations are not merged into one logical procedure without
  forwarding evidence.
- A first observed REGISTER is not necessarily the subscriber's first registration.
- Missing messages at the capture boundary are incompleteness, not evidence of a
  timeout or failure.
- Cross-source SIP/Diameter timeline ordering stays unproved unless common capture
  provenance is independently verified; matching filenames or frame numbers are not
  proof.
- CLI output destinations cannot alias any input artifact or each other, even with
  `--force`.
- IMS session, media, SDP, RTP, Rx, Sh and failure-boundary analysis are out of scope.