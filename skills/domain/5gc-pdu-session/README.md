# 5gc-pdu-session

`5gc-pdu-session` is the bounded Domain Skill for 5GC PDU Session Establishment
and Modification procedures and immediate post-establishment / post-modification N3
user-plane observation evidence, version 0.2.0.
It consumes already-extracted structured evidence from N1 (nas-5gs), N2 (ngap),
N3 (gtpu), N4 (pfcp), and N11 (sbi-http2), plus optional cross-protocol-evidence
correlation output. It forms evidence-safe procedure instances, evaluates the
partial-order stage model across 7 establishment stages and 7 modification stages
per repeated attempt, associates cross-plane modification evidence through an
explicit candidate model with per-attempt control and observation windows,
recognizes protocol-defined rejections and negative causes, reports missing
evidence relative to the capture window, binds planes with explicit association
strength, preserves ambiguous and unbound modification evidence with
`CORRELATION_AMBIGUITY` visibility, scopes NAS PTI per UE context, and exposes
lower-layer field findings and procedure-local deviations.
It decodes no raw packets, requires no unredacted subscriber identity, and never
issues success, failure, or root-cause verdicts.

Normative basis: 3GPP TS 23.502 Release 19, version 19.5.0 (5G System procedures,
clause 4.3.2.2 PDU Session Establishment and clause 4.3.3 PDU Session Modification),
with protocol semantics supplied through lower-layer Skill contracts (TS 24.501,
TS 38.413, TS 29.244, TS 29.281, TS 29.502, TS 29.518). No incompatible Release
mixing is claimed.

## Package Structure

- `scripts/pdu_session_model.py`: standalone analysis engine (loaders, instance
  formation, multi-plane binding, repeated modification attempt evaluation, deviations,
  field findings, sanitization).
- `scripts/analyze_pdu_session.py`: CLI driver producing analysis summary JSON
  and generic procedure-evidence stage JSONL.
- `scripts/pdu_session_timeline.py`: per-instance evidence timeline (text or JSON).
- `schemas/5gc-pdu-session-analysis.schema.json`: analysis summary JSON contract.
- `schemas/procedure-evidence.schema.json`: byte-identical package-local copy of
  the generic procedure-evidence contract.
- `references/`: procedure model, stage model, association model, deviation model,
  field findings, failure cases.
- `examples/inputs/`, `examples/expected/`: 49 synthetic scenarios covering normal
  establishment, rejections, negative causes, ambiguous SBI, TEID reuse, mixed NGAP
  resources, pending delivery, partial captures, repeated modification attempts,
  branch conditionality, PTI isolation, PFCP rule operations, and GTP-U observations.
- `tests/`: package-local test suite (`test_5gc_pdu_session.py`).

## Usage

```bash
# Analyze events from individual protocol JSONL files:
python scripts/analyze_pdu_session.py \
  --nas nas.jsonl \
  --ngap ngap.jsonl \
  --pfcp pfcp.jsonl \
  --gtpu gtpu.jsonl \
  --sbi sbi.jsonl \
  --output analysis.json \
  --stages-output stages.jsonl

# Or analyze an input directory containing protocol JSONL files:
python scripts/analyze_pdu_session.py \
  --input-dir examples/inputs/normal-establishment \
  --output analysis.json \
  --stages-output stages.jsonl

# Render a chronological timeline:
python scripts/pdu_session_timeline.py analysis.json --format text
python scripts/pdu_session_timeline.py analysis.json --format json
```

## Output and Limitations

The analysis summary reports, per procedure instance: the derived instance identifier
(`5gc-pdu-session:<capture>:ran<id>-amf<id>:psi<id>`, explicitly DERIVED and not a
standardized 3GPP identifier), NGAP UE context, PDU Session ID, stage evaluations,
repeated modification attempts (0..N per instance), terminal observation (Accept,
Reject, Command Reject, No Terminal Observation, or Partial Capture), deviations,
earliest observed procedure-local deviation, field findings, and plane bindings.

- PDU Session ID alone is not globally unique: different UEs allocate identical IDs.
- PTI is strictly scoped to its UE context; concurrent attempts on different UEs with
  the same PTI remain completely isolated.
- Sanitized subscriber identities in SBI HTTP/2 mean identical PDU Session IDs across
  concurrent UEs remain unbound in `unbound_evidence` with `CORRELATION_AMBIGUITY`.
- Matching GTP-U traffic to PFCP requires matching both header TEID and outer endpoint IP.
- Post-modification GTP-U attaches to an attempt only inside its bounded observation
  window AND with a tunnel identity match; packets with several compatible attempts
  stay ambiguous and are never attached by temporal proximity.
- Missing post-modification GTP-U packets are reported as conditional `NOT_OBSERVED`
  evidence with limitations, never as a missing required counterpart and never as
  `USER_PLANE_FAILED`.
- HTTP 202 Accepted on N11 remains `PENDING`, never delivery success.
- NGAP resource outcomes are evaluated per item; mixed success/failure is preserved.
- PDU Session Release lifecycle remains deferred in this version.

## Standalone Validation

Copy this directory anywhere and run:
```bash
python -m unittest tests/test_5gc_pdu_session.py
```
No repository-root runtime files or external network access are required.
