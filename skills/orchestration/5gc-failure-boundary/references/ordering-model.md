# Ordering Model

## First Means Earliest

First means the earliest safely orderable abnormal evidence boundary, never the
most serious abnormality. No severity ranking exists anywhere in the Skill.

## Ordering Bases

Ordering relies on evidence provenance only:

1. exact frame provenance for directly observed events (from the deviation
   description or the Domain stage evidence of the deviation's stage);
2. bounded source observation windows for derived candidates (attempt
   observation windows from the PDU Session contract, or the registration
   observation window);
3. the source Domain stage order within one source procedure instance or
   attempt, when the stage order is part of the Domain output contract.

Timestamps are preserved as supporting metadata and never override
contradictory frame ordering. No new 3GPP state machine is reconstructed here.

## Pairwise Ordering Rules

- Two framed candidates: frame comparison; equal frames tie.
- A framed candidate against a windowed candidate: a frame below the window is
  before it, a frame above it is after it. A frame at the window end is before
  a derived absence claim when the framed candidate is `OBSERVED` and the
  windowed candidate is `DERIVED` (derived missing evidence never outranks an
  observed event); otherwise an overlapping frame ties.
- Two windowed candidates: disjoint windows decide; overlapping windows tie.
- Two candidates inside one source instance or attempt without frames or
  windows: the Domain stage order decides; equal stages tie.
- Otherwise no safe ordering basis exists.

## Selection Statuses

| Status | Meaning |
| --- | --- |
| `SELECTED` | Exactly one candidate is safely ordered before every competing candidate. |
| `NO_ABNORMAL_BOUNDARY_OBSERVED` | No selectable abnormal Domain deviation was observed; never success or health. |
| `AMBIGUOUS_FIRST_BOUNDARY` | Two or more candidates tie or overlap at the first position; all tied candidate ids are returned. |
| `INSUFFICIENT_COMPARABLE_EVIDENCE` | Abnormalities exist but their provenance cannot be safely placed in one comparable ordered path (missing ordering provenance), or every missing-evidence candidate is blocked by a partial source window. |

## Downstream and Earlier Observations

Candidates and limitation observations ordered after the selected boundary are
reported with the neutral relation `OBSERVED_AFTER_BOUNDARY`; ordered-before
context uses `OBSERVED_BEFORE_BOUNDARY`. Downstream observations are never
described as caused by the selected boundary. Earlier positive terminal
observations (for example a Registration Complete) are preserved as context and
never translated into global success.
