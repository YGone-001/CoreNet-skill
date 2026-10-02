# Context Release and Paging Reference

N2 release and paging observations, grounded in the reviewed TS 38.413
and TS 23.502 semantics supplied by the ngap Skill.

## UE context release

- Observed messages: UEContextReleaseRequest (NG-RAN-initiated path),
  UEContextReleaseCommand (AMF-initiated), UEContextReleaseComplete.
- A UEContextReleaseRequest does not have to precede a
  UEContextReleaseCommand; either may start the observed release path.
- The observed sender direction (sender_role supplied by ngap), the NGAP
  Cause category/value, the UE NGAP context identifiers, and the frames
  and timestamps are preserved.
- Mandatory reasoning rule: release initiator is not root cause. The
  analysis may state that NG-RAN-side release initiation evidence was
  observed; it must not state that the NG-RAN caused any problem without
  independent confirmation.

## Release after completion

A UE context release observed after Registration completion is recorded
as separate access/mobility evidence. The registration completion
evidence is never retroactively reclassified as a registration failure
because a later release occurred. This separation is what allows the
real-world pattern — registration completed, later release, later
paging, no UE response — to be reported accurately.

## Paging

- Paging is a non-UE-associated NGAP observation in its common form; it
  forms capture-level context and never fabricates a UE instance.
- Paging itself is not evidence that the UE responded.
- If no subsequent service or access evidence appears within the
  observation window, the analysis reports "paging response evidence
  not observed within the available observation window". It never
  reports paging failure: the UE response occurs on the air interface,
  outside the N1/N2 observation scope.
