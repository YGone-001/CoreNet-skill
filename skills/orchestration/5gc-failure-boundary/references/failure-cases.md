# Failure Cases and Diagnostic Boundaries

## 1. Directly observed negative outcome
- Evidence: Domain-emitted reject / negative outcome / failed item with frame provenance.
- Boundary: selected when safely earliest; confidence `HIGH`.
- Boundary statement: the negative outcome was observed at that frame. It does
  not attribute blame to any network function or implementation.

## 2. Derived missing counterpart
- Evidence: `MISSING_EXPECTED_COUNTERPART` bounded by the source observation window.
- Boundary: selectable only when the window is sufficient; confidence `MEDIUM`.
- The absence is `DERIVED`, never an observed negative response; no failure
  time is fabricated.

## 3. Partial capture
- Evidence: source Domain marks the window partial.
- Behavior: missing-evidence candidates are blocked; the group reports
  `INSUFFICIENT_COMPARABLE_EVIDENCE` with the capture requirement stated.

## 4. Ambiguous ordering
- Evidence: same-frame candidates or overlapping windows.
- Behavior: `AMBIGUOUS_FIRST_BOUNDARY` with all tied candidate ids; no severity
  tiebreak.

## 5. Incomparable provenance
- Evidence: candidates without any common ordering basis.
- Behavior: `INSUFFICIENT_COMPARABLE_EVIDENCE` plus the exact provenance
  requirement needed to resolve it.

## 6. Unlinked subjects
- Evidence: different captures, different associations, or missing UE context.
- Behavior: analyses stay in separate single-source groups (subject-link
  `UNBOUND`); no timestamp or numeric-identifier merging.

## 7. No abnormal deviation
- Evidence: supplied Domain analyses carry no eligible deviation.
- Behavior: `NO_ABNORMAL_BOUNDARY_OBSERVED`; never success, health, or a
  problem-free statement.
