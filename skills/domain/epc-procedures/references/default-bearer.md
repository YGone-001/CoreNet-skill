# Bounded default-bearer evidence model

This Domain capability reconstructs **bounded signalling evidence** for the EPS
default bearer that an initial attach establishes. It consumes accepted
lower-layer output and never decodes a protocol.

## Inputs

| Input | Required | Used for |
| --- | --- | --- |
| NAS-EPS detailed events | yes | ESM messages with their container, protection state and direction |
| S1AP detailed events | optional | UE context binding and item-scoped E-RAB evidence |
| EPS Attach analysis | optional | Attach-instance association by S1AP UE context |
| EPC session-control analysis | optional | provenance only; no subject is joined |
| GTPv2-C detailed events | optional | exact S1-U tunnel endpoint identity only |

The GTPv2-C input is the only protocol-level input that is not already a Domain
artifact. It is consumed because the accepted session-control analysis publishes
F-TEID interface type and TEID but not the transport address, and an exact
endpoint comparison needs both. See `identity-linking.md`.

## Stages

| Stage | Conditional | Evidence |
| --- | --- | --- |
| `pdn-connectivity-request` | no | ESM 208 / 209 |
| `esm-information-exchange` | yes | ESM 217 / 218 |
| `default-bearer-activation-request` | no | ESM 193 |
| `default-bearer-activation-response` | no | ESM 194 / 195 |
| `s1-erab-setup` | yes | S1AP Initial Context Setup request/response/failure with E-RAB items |
| `supporting-gtpv2-session-control` | yes | a GTPv2-C message matched by exact S1-U endpoint equality |

Stage statuses:

```text
OBSERVED               evidence of this stage is visible
NOT_OBSERVED           the enclosing NAS was readable and the stage is absent
UNAVAILABLE_PROTECTED  the enclosing NAS carried ciphered payload and nothing decoded
AMBIGUOUS              competing evidence prevents attribution
INSUFFICIENT_EVIDENCE  the capture cannot decide, e.g. no terminal outcome
```

`UNAVAILABLE_PROTECTED` exists so a protected Attach Accept can never be reported
as `ACTIVATE_DEFAULT_BEARER_ABSENT`.

## Outcomes

```text
PDN_CONNECTIVITY_REQUEST_OBSERVED
PDN_CONNECTIVITY_REJECT_OBSERVED
DEFAULT_BEARER_ACTIVATION_REQUEST_OBSERVED
DEFAULT_BEARER_ACTIVATION_ACCEPT_OBSERVED
DEFAULT_BEARER_ACTIVATION_REJECT_OBSERVED
S1_ERAB_SETUP_REQUEST_OBSERVED
S1_ERAB_SETUP_RESPONSE_OBSERVED
DEFAULT_BEARER_SIGNALING_INCOMPLETE
PROTECTED_ESM_UNAVAILABLE
```

An accepted activation response is **protocol-level** evidence. It is not proof
that the default bearer carries user traffic, and the analysis never emits a
bearer, PDN-connection or user-plane verdict.

## Instance formation

An instance is one S1AP UE context (`capture`, `sctp association`,
`eNB-UE-S1AP-ID`, `MME-UE-S1AP-ID`) that carries ESM evidence. A NAS message that
carries an ESM container but no decoded ESM message also forms an instance, so a
protected stage stays visible instead of disappearing.

ESM evidence with no provable enclosing S1AP UE context forms one explicit
`UNBOUND` instance per capture; it never borrows a context from a neighbouring
frame.

## Deviations

Negative outcomes are typed and frame-anchored at the message that carries them:

| Type | Anchor |
| --- | --- |
| `PDN_CONNECTIVITY_REJECT_OBSERVED` | the PDN connectivity reject frame |
| `DEFAULT_BEARER_ACTIVATION_REJECT_OBSERVED` | the activation reject frame |
| `ESM_REJECTION_OBSERVED` | another reviewed ESM reject frame |

Each deviation publishes `esm_cause_code`, `esm_cause_name`, the EBI where
decoded, `evidence_refs` and the observation window. An ESM Cause is a
protocol-level rejection and never identifies a responsible network function.

Completeness and association limitations are published as their own deviation
types (`PROTECTED_ESM_UNAVAILABLE`, `ERAB_ITEM_EVIDENCE_UNAVAILABLE`,
`TUNNEL_ENDPOINT_LINK_AMBIGUOUS`, `ESM_EVIDENCE_UNBOUND`) and are never treated
as negative network outcomes.

## Boundary selection

`boundary_selection_status` stays `NOT_EVALUATED` and `first_abnormal_boundary`
stays `null`. Per-subject abnormal-boundary selection belongs to the
`epc-failure-boundary` Orchestration Skill.
