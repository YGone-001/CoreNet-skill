# Domain Deviation Adjudication Area

This directory is a separate evaluation area inside the Golden Capture benchmark. It records an
independent, packet-level adjudication of the deviations and abnormal-boundary candidates that the
5GC Domain Skills and Analysis Orchestration emit for the public capture corpus. It is benchmark
infrastructure, not a Skill, not an architecture layer, and not a second scoring comparator.

## 1. Relationship To The Accepted Benchmark

| Artifact | Authority | Touched here |
| --- | --- | --- |
| `cases/*/human-baseline.json` | Accepted independent human baseline | Never |
| `cases/*/differential.json`, `cases/*/skill-result-summary.json`, `benchmark-summary.json` | Accepted benchmark scoring output | Never |
| `scripts/compare_results.py`, `scripts/summarize_benchmark.py`, `schemas/` | Accepted comparator and contracts | Never |
| `skills/**` | Accepted Skill runtimes | Never |
| `adjudications/cases/*.json`, `adjudications/summary.json` | This area only | Yes |

Adjudication results are deliberately kept out of the scored records. A deviation may be judged
`UNSUPPORTED_BY_PACKET_EVIDENCE` here while the accepted benchmark still reports the case exactly as
the frozen comparator computed it. The match rate in `benchmark-summary.json` is never adjusted from
here.

## 2. Evidence Model

Every adjudication is anchored to one of two things:

1. A concrete frame in the original capture, checked independently with TShark field output.
2. An observation window, when the underlying Skill claim is a derived absence rather than an
   observed event.

Only structured fields are used as evidence: frame number, protocol, message identity, and named
dissector fields. Human-readable limitation, description, and `Info` column prose are read as
context, never as the identity of a fact. Upstream scenario directory names are treated as
secondary metadata and never as packet truth.

Evidence levels follow the repository vocabulary. `OBSERVED` means directly visible in the capture
artifact and always carries at least one `packet_evidence` entry. `DERIVED` means computed from
observed evidence by a lower layer. This area never upgrades an adjudication to a proven conclusion
and never records cause attribution of any kind.

## 3. Adjudication Statuses

| Status | Meaning |
| --- | --- |
| `SUPPORTED_BY_PACKET_EVIDENCE` | The claim matches independently inspected packet evidence. |
| `VALID_CAPTURE_LIMITATION` | The claim honestly reports evidence that cannot be observed from this capture vantage point. |
| `POTENTIALLY_SPURIOUS` | The claim is probably an artifact of Skill construction rather than of the network; never final. |
| `UNSUPPORTED_BY_PACKET_EVIDENCE` | The claim is contradicted, or has no packet basis at all. |
| `INSUFFICIENT_EVIDENCE` | Available evidence cannot decide. |
| `OUT_OF_IMPLEMENTED_SCOPE` | The behavior is correct for the bounded Skill, and the underlying procedure is simply not owned yet. |

`POTENTIALLY_SPURIOUS` forces `finality: NONFINAL`. Source Domain identity is recorded separately
from `proposed_owner_domain`, because the layer that emitted an artifact is not automatically the
layer that should be corrected.

## 4. First Differing Layer

Each case names the earliest layer where the record actually diverges from packet evidence, chosen
from `PROTOCOL_EXTRACTION`, `CORRELATION`, `DOMAIN_INSTANCE_FORMATION`, `DOMAIN_STAGE_ACTIVATION`,
`DOMAIN_DEVIATION_EMISSION`, `ORCHESTRATION_CANDIDATE_CONSTRUCTION`, `ORCHESTRATION_ORDERING`,
`HUMAN_BASELINE`, `CAPTURE_LIMITATION`, `NONE_OBSERVED`.

A downstream symptom is never attributed to Orchestration when the candidate originated from an
unsupported Domain emission. Orchestration only republishes what a Domain handed it, so an
unverifiable candidate is reported at the Domain layer that produced it.

## 5. Reproduction

Records in `cases/` were produced against the frozen runtime named in each file's
`runtime_provenance.corenet_commit`, using the public corpus at the pinned source commit recorded in
`cases/*/case.json`, with the TShark version stated there. Captures, raw Protocol event JSONL, and
raw Domain output stay outside the repository. Committed content carries only sanitized frame,
protocol, and case references: no capture bytes, no unredacted protocol events, no subscriber
identifier, no authentication material, and no workstation path.

To reproduce the underlying run without modifying anything:

```bash
python benchmarks/golden-captures/scripts/run_public_corpus.py \
  --source-root <external capture clone> \
  --work-root <external work directory> \
  --output-root <external sanitized output>
```

## 6. Contract Files

- `schemas/deviation-adjudication.schema.json` — one adjudicated deviation or candidate.
- `schemas/case-adjudication.schema.json` — one adjudicated case, its provenance, and its items.
- `summary.json` — cross-case rollup, ranked correction plan, and regression test plan.
- `tests/test_adjudications.py` in the benchmark test tree — deterministic contract and record checks.

The correction plan in `summary.json` is planning only. No correction is implemented from this area,
and ranked order expresses dependency sequence and evidentiary certainty, never a severity claim.
