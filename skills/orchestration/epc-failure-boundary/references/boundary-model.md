# Boundary candidate model

## Where candidates come from

A candidate is built from one Domain deviation that already exists in the
accepted Domain output. Orchestration never invents a candidate and never parses
an explanation string to recover a cause or a frame.

| Subject type | Selectable deviation types |
| --- | --- |
| `EPS_ATTACH` | `ATTACH_REJECT_OBSERVED`, `AUTHENTICATION_FAILURE_OBSERVED`, `AUTHENTICATION_REJECT_OBSERVED`, `SECURITY_MODE_REJECT_OBSERVED`, `S1_CONTEXT_SETUP_FAILURE_OBSERVED` |
| `EPC_SESSION_CONTROL` | `CREATE_SESSION_REJECTED_OBSERVED`, `MODIFY_BEARER_REJECTED_OBSERVED`, `DELETE_SESSION_REJECTED_OBSERVED`, `BEARER_CONTEXT_REJECTED_OBSERVED` |

## Non-selectable evidence quality

These types describe completeness, association or interpretation limits. They
never become a negative network outcome:

`OPEN_REQUEST_OBSERVED`, `RESPONSE_ONLY_OBSERVED`,
`AMBIGUOUS_TRANSACTION_OBSERVED`, `INTERFACE_EVIDENCE_UNAVAILABLE`,
`INTERFACE_EVIDENCE_CONFLICT`, `CONTEXT_REUSE_AFTER_DELETION`,
`BEARER_CONTEXT_BINDING_UNAVAILABLE`, `PROTECTED_INNER_MESSAGE_UNAVAILABLE`,
`INSUFFICIENT_TERMINAL_EVIDENCE`.

They still matter: an ambiguous transaction at or before the earliest eligible
candidate blocks the claim that the candidate is first.

Any other deviation type is reported as `UNKNOWN_DEVIATION_TYPE` and stays
ineligible.

## Provenance contract

Every candidate publishes:

```text
candidate_reference          deterministic, derived from subject + deviation + ordinal
source_domain                epc-procedures
source_subject_reference     the Domain subject the deviation belongs to
deviation_type               the reviewed type
procedure_family_or_stage    procedure family (GTPv2-C) or stage (Attach)
protocol                     S1AP / NAS-EPS / GTPv2-C
message_type                 the concrete message identity
frame_number                 the exact anchor
evidence_level               OBSERVED / DERIVED / ...
evidence_refs                bounded, allowlisted source references
observation_window           start_frame / end_frame
selection_eligibility        ELIGIBLE / INELIGIBLE
eligibility_reasons          why an ineligible candidate cannot be selected
limitations                  source limitations carried through
```

When the Domain publishes them, a candidate also keeps
`transaction_reference`, `cause_code`, `cause_scope` and `bearer_item_index`.

## Eligibility rules

A candidate is eligible only when all of the following hold:

1. Its type is in the selectable set for its subject type.
2. `frame_number` is an integer.
3. That frame appears in the source `evidence_refs`.
4. The frame lies inside the source observation window.
5. `protocol` and `message_type` are present.
6. Session candidates carry a `transaction_reference`.
7. The evidence level is `OBSERVED` or `DERIVED`; `INFERRED` and `HYPOTHESIS`
   are refused.

An ineligible candidate stays visible with its reasons so a reader can see what
was excluded and why.

## Message and bearer scope

A message-level acceptance and a bearer-level rejection in the same response are
different facts. The message-level candidate is absent and the bearer candidate
keeps `cause_scope = "bearer"` and its `bearer_item_index`. A response whose
message Cause is accepted is never classified as a message-level rejection
because one bearer item failed.

## Anchoring

A response-defined negative outcome is anchored at the response frame, because
that frame is where the result became visible. An open request has no response,
so its deviation anchors at the request frame as an observation anchor only. An
ambiguous transaction keeps its request anchor and never selects an arbitrary
response frame.
