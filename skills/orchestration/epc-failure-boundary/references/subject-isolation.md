# Subject isolation and the evidence-link audit

## What the accepted Domains actually provide

| Evidence | EPS Attach Domain | Session-control Domain |
| --- | --- | --- |
| Subject identity | `procedure_reference` per Attach attempt | `subject_reference` per control-plane context |
| Capture provenance | `association.capture_file` | `capture_file` |
| Frame anchors | `deviations[].frame_number` + `evidence_refs` | `procedure_local_deviations[].frame_number` + `evidence_refs` |
| Observation window | `first_frame` / `last_frame`, per-deviation window | `observation_window`, per-deviation window |
| Negative outcome | `ATTACH_REJECT_OBSERVED`, `AUTHENTICATION_*`, `SECURITY_MODE_REJECT_OBSERVED`, `S1_CONTEXT_SETUP_FAILURE_OBSERVED` | `*_REJECTED_OBSERVED` (message scope) and `BEARER_CONTEXT_REJECTED_OBSERVED` (bearer scope) |
| Candidate completeness | All deviations are published | Bounded list plus `procedure_local_deviation_count` and `procedure_local_deviations_omitted` |
| Cross-subject link | none | `attach_association = NOT_ESTABLISHED`, `cross_interface_association = NOT_ESTABLISHED` |

## Why groups stay independent

The accepted Domains publish two explicit limits: an Attach subject is not
linked to a GTPv2-C subject, and an S11 subject is not linked to an S5/S8
subject. Orchestration treats those limits as authoritative.

A shared capture does not override them. A common EBI does not override them. A
common Cause value does not override them. A timestamp does not override them. A
single simulated UE does not authorize a software-level join.

Consequences:

- One group per Attach instance, per S11 subject and per S5/S8 subject.
- `subject_link.cross_subject_link` is always `NOT_ESTABLISHED`.
- Two groups can both select a boundary in the same capture. The earlier of the
  two is not a shared EPC failure point.
- `unbound_domain_analyses` lists subjects whose internal association is
  `UNBOUND` or `AMBIGUOUS`, with the reason that no cross-subject link is
  authorized.

## Interface evidence

An `UNKNOWN_INTERFACE` session subject keeps that interface. It may still carry
an explicit, frame-supported GTPv2-C rejection, and that rejection remains
selectable. Orchestration never assigns a fictitious S11 or S5/S8 interface to
make the report look complete.

## What a future phase would need

Linking Attach to session control, or S11 to S5/S8, requires a reviewed identity
bridge that the accepted Domains do not yet publish. Until such a bridge exists,
the limitation is recorded and no merge is attempted.
