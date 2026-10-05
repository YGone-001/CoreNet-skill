# Mobility Procedure Model

Basis: 3GPP TS 23.502 Release 19 for Domain procedure structure; NGAP
message semantics remain owned by TS 38.413 Release 19 through the ngap
Skill (>=0.3.0). This Skill consumes already-extracted detailed events and
never re-decodes protocols.

## Two attempt families

The analysis maintains two separate families:

- `handover_attempts[]` — N2 handover evidence (Handover Preparation,
  Handover Resource Allocation, Handover Notification, Handover Cancel).
- `path_switch_attempts[]` — Path Switch evidence (Path Switch Request
  procedure).

A Path Switch attempt MAY later be linked to a handover attempt when
evidence safely supports the relationship (see
`source-target-association.md`); it MUST remain independent when that
relationship cannot be proven. Neither family is mandatory for the other:
a PathSwitchRequest does not presume an observed HandoverRequired/Command
sequence (an Xn handover produces a Path Switch without any N2 handover
signaling this Skill would see), and a HandoverNotify does not presume a
Path Switch.

## Conditional stages, no universal ordering

No universal total ordering is encoded. Stages are conditional: a stage
record appears only when its trigger evidence exists, and expected
counterparts are branch-aware. Handover stages: HANDOVER_INITIATION,
HANDOVER_PREPARATION_OUTCOME, TARGET_RESOURCE_ALLOCATION,
HANDOVER_EXECUTION_NOTIFICATION, HANDOVER_CANCELLATION, plus the optional
supporting-plane stages CONTROL_PLANE_UPDATE (N11),
USER_PLANE_CONTROL_UPDATE (N4), and USER_PLANE_OBSERVATION (N3). Path
Switch stages: PATH_SWITCH_REQUEST, PATH_SWITCH_OUTCOME,
SESSION_CONTROL_UPDATE, USER_PLANE_CONTROL_UPDATE, and post-switch
user-plane observation.

## Attempt identity

`attempt_id` values (5gc-ho:... / 5gc-ps:...) are derived display
references only; consumers must read the structured context fields and
never parse the strings. `attempt_id_basis` records this in every attempt.
