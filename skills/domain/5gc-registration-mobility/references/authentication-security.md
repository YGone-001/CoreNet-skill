# Authentication and Security Mode Reference

Conditional branch behavior for the authentication and NAS security
stages, grounded in the reviewed TS 23.502 procedures with TS 24.501
semantics supplied by the nas-5gs Skill.

## Authentication branch

- Trigger: Authentication request.
- Observed outcomes: Authentication response, Authentication reject,
  Authentication failure, Authentication result (where supplied).
- Authentication reject and Authentication failure are
  PROTOCOL_REJECT_OBSERVED / UNSUCCESSFUL_OUTCOME_OBSERVED deviations
  with the 5GMM Cause preserved (for example Synch failure).
- An Authentication request with no visible outcome inside the
  observation window is MISSING_EXPECTED_COUNTERPART with capture-
  boundary limitations.
- Prohibited conclusions: defective SIM, defective UDM or AUSF,
  defective AMF, or clock problems. Those are hypotheses that require
  evidence this Skill does not hold.

## Secret handling

The analyzer never emits RAND, AUTN, RES, AUTS, KSEAF, KAMF, or any NAS
key material. Lower-layer events already carry presence-only
authentication metadata; this Skill propagates no secret values in any
output.

## Security mode branch

- Trigger: Security mode command.
- Observed outcomes: Security mode complete, Security mode reject.
- Security mode reject is a PROTOCOL_REJECT_OBSERVED deviation; its 5GMM
  Cause, the selected NAS algorithms (when supplied), and the security
  envelope context are preserved as field findings.
- Security mode complete is not proof that the security context is
  correct; it proves the message was observed. A command with neither
  outcome visible is a missing-counterpart deviation with the
  capture-boundary limitation.

## Protected NAS envelopes

When nas-5gs reports a security-protected envelope whose inner message
was not decodable (inner_message_available false), the analyzer records
the PROTECTED_INNER_MESSAGE_UNAVAILABLE deviation. The inner message is
never guessed from sequence numbers, timing, or direction. Procedure
interpretation continues with the evidence that is available, and the
limitation is stated in the analysis.
