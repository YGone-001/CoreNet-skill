# Service Access Reference

Bounded service-request procedure evidence, grounded in the reviewed TS
23.502 service-request procedure with TS 24.501 semantics supplied by
the nas-5gs Skill.

## Observed messages

- Service request (UE side, usually carried inside an NGAP uplink NAS
  transport frame).
- Service accept and Service reject (network side).

## Rules

- Service reject is a PROTOCOL_REJECT_OBSERVED deviation with the 5GMM
  Cause supplied by nas-5gs. Paging failure, RRC failure, or AMF defects
  are never inferred from Service reject alone.
- Service accept is recorded as the observed accept outcome. The
  analyzer asserts no further completion expectation: only the
  reject/accept observations are definitive in the reviewed basis, and
  Service accept is not claimed as mandatory in every context.
- A Service request with neither accept nor reject visible before the
  capture ends is a MISSING_EXPECTED_COUNTERPART deviation with the
  capture-boundary limitation.

## Boundary

Complete 5GC service-resumption state and session establishment are
outside this Skill. Service-access evidence participates in the
procedure timeline and deviation report but never produces an outcome
verdict.
