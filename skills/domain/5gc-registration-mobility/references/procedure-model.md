# Procedure Model

The registration procedure is modeled as a conditional observation graph
(rules/registration-model.json), grounded in 3GPP TS 23.502 Release 19,
version 19.9.0, with TS 24.501 Release 19 lineage and TS 38.413 semantics
supplied by the lower-layer Skill contracts. The model describes expected
observation points; it is never a rigid linear state machine.

## Observation families

| Stage | Conditional | Trigger observation | Expected counterparts |
| --- | --- | --- | --- |
| registration-initiation | no | NGAP InitialUEMessage or NAS Registration request | — (entry point) |
| identity | yes | Identity request | Identity response |
| authentication | yes | Authentication request | Authentication response / reject / failure / result |
| security-mode | yes | Security mode command | Security mode complete / reject |
| registration-decision | no | Registration accept or reject | — (the observation is the decision) |
| registration-completion | yes | Registration accept | Registration complete |
| n2-context-establishment | yes | InitialContextSetupRequest | InitialContextSetupResponse / Failure |
| context-release | yes | UEContextReleaseRequest or UEContextReleaseCommand | UEContextReleaseComplete |
| paging | yes | Paging | none required (air-interface response is outside the N1/N2 observation) |
| service-access | yes | Service request | Service accept / reject (conditional; see service-access-model.json) |

## Conditional rule

Identity, authentication, and security mode depend on existing context
and validly may be absent. If a conditional branch was not entered, its
absence is not a deviation. If its trigger was observed, the branch's
expected outcomes become relevant evidence: observing the trigger
without any outcome within the observation window produces a
MISSING_EXPECTED_COUNTERPART deviation with capture-boundary
limitations.

## Reaction-driven expectations

Expectations exist only where the reviewed procedure defines them:
Identity request expects Identity response; Authentication request
expects one of its defined outcomes; Security mode command expects
Security mode complete or reject; Registration accept makes Registration
complete relevant completion evidence; UEContextReleaseCommand makes
UEContextReleaseComplete relevant; InitialContextSetupRequest expects
the response or failure branch. No expectation is invented beyond this
model.

## Decision and completion are distinct

Registration decision (accept or reject) and Registration completion
(complete after accept) are separate stages. Registration completion
evidence stays independent from later N2 context release, paging, or
service events: a completed registration followed by a later release is
never retroactively classified as a registration failure.

## Evidence classification

Stage assignment, instance formation, frame joins, missing-counterpart
determination, duplicate detection, and ordering normalization are
DERIVED. The protocol events themselves, their causes, and their
protocol fields are OBSERVED as supplied by the lower layers.
