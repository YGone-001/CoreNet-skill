# PDU Session Resource Model

Resource evidence stays item-scoped inside each attempt. For every PDU
Session ID observed in the attempt's NGAP resource items, the attempt
preserves:

- `n2_roles` — every observed resource-list role with its message, frame,
  and operation (REQUIRED, HANDOVER, TO_RELEASE, REQUEST, ADMITTED,
  TO_BE_SWITCHED, SWITCHED, RELEASED, FAILED, ...);
- `n2_outcomes` — item-scoped outcome observations
  (RESOURCE_FAILED_ITEM_OBSERVED for FAILED roles;
  ADMITTED/SWITCHED/RELEASED role observations otherwise);
- `n11_evidence`, `n4_evidence`, `n3_observations` — safely associated
  supporting-plane entries;
- `lifecycle_generation` — optional, only from a supplied
  5gc-pdu-session (>=0.4.0) context;
- `limitations` — explicit unattributed-evidence statements.

Hard rules:

- Mixed outcomes stay independent: ADMITTED + FAILED, or SWITCHED +
  RELEASED, in one message never collapse into a message-wide verdict.
- A FAILED item produces RESOURCE_FAILED_ITEM_OBSERVED for that
  resource only; it never becomes a complete attempt failure unless a
  separate protocol unsuccessful outcome establishes that branch.
- Contradictory roles across safely linked stages (for example FAILED in
  the Path Switch Request and SWITCHED in the Acknowledge for the same
  PSI) produce FIELD_CONFLICT with both observations preserved.
- PDU Session IDs are never globally joined by number alone; resource
  identity is scoped to the attempt context.

## Lifecycle generation

When PDU Session Domain context is supplied, a generation is attached only
when exactly one context instance for that PSI has an observation window
overlapping the attempt window; instance_id, session_generation, and
reuse_status are preserved verbatim. Multiple overlapping generations keep
the finding generation-less with a LIFECYCLE_AMBIGUITY deviation; mobility
evidence is never attached to the wrong generation merely because the
numeric PSI matches.
