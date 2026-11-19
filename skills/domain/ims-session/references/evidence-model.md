# IMS session evidence model

## Evidence levels

- `OBSERVED`: an accepted SIP event, transaction or dialog observation.
- `DERIVED`: deterministic attempt, branch, ACK, CANCEL or release evidence assembled
  from accepted references.
- `INFERRED`, `HYPOTHESIS`, `CONFIRMED`: not used for a call, media or service verdict
  in this phase.

## Attempt dimensions

Every attempt publishes separate axes:

| Axis | Values |
| --- | --- |
| INVITE outcome | `ACCEPTED_2XX_OBSERVED`, `NEGATIVE_FINAL_OBSERVED`, `PROVISIONAL_ONLY`, `NO_RESPONSE_OBSERVED`, `INCOMPLETE_EVIDENCE` |
| Branch outcome | `ACCEPTED_2XX`, `NEGATIVE_FINAL`, `EARLY_ONLY`, `PROVISIONAL_ONLY`, `NO_FINAL_RESPONSE`, `UNRESOLVED` |
| ACK | `OBSERVED_FOR_ALL_ACCEPTED_BRANCHES`, `MISSING_FOR_ACCEPTED_BRANCH`, `NOT_APPLICABLE` |
| CANCEL | `NO_CANCEL_OBSERVED`, `CANCEL_REQUEST_OBSERVED`, `CANCEL_RESPONSE_OBSERVED`, `CANCEL_INVITE_SEQUENCE_OBSERVED`, `CANCEL_ASSOCIATION_NOT_ESTABLISHED`, `CANCEL_AFTER_INVITE_FINAL_RESPONSE` |
| Release | `NO_BYE_OBSERVED`, `BYE_REQUEST_OBSERVED`, `BYE_RESPONSE_OBSERVED`, `BYE_RESPONSE_NOT_OBSERVED`, `BYE_NEGATIVE_RESPONSE_OBSERVED`, `SIP_TERMINATION_SIGNALING_SUPPORTED` |
| Capture | `COMPLETE`, `PARTIAL`, `UNKNOWN` |

These axes are never collapsed into one success boolean.

## References

- Attempt: `ims-session:<capture>:<frame>.<occurrence>`
- Branch: an accepted `sip-dialog` reference when a dialog exists, otherwise an accepted
  event or transaction reference
- Stage evidence: accepted SIP Event references
- ACK, CANCEL and BYE: accepted SIP Event and Transaction references
- In-dialog observation: the accepted request Event reference plus the accepted
  Transaction and Dialog references

All published references resolve to accepted source objects in the same capture.

## Branch semantics

A branch is one accepted SIP Dialog reference. A 2xx branch without an accepted
Confirmed Dialog remains a branch with `dialog_reference: null` and explicit missing
evidence. A 100 Trying does not create a branch. A tagged 180/183 may create an Early
branch. A non-2xx final response creates a negative branch without a confirmed dialog.

## Missing and conflicting evidence

Missing final response, missing 2xx ACK, missing Confirmed Dialog, negative BYE
response, CANCEL after the INVITE final response and mixed forked outcomes are explicit
fields. Missing evidence is not transformed into a negative service result.

## Bounded output

Attempts, branches, unbound observations and in-dialog observations have fixed
publication limits. `completeness` publishes observed totals, published counts and
omitted counts. The invariants are:

    session_attempt_count = published_attempts + attempts_omitted
    branch_count = published_branches + branches_omitted
    unbound_observation_count = published_unbound + unbound_observations_omitted
    in_dialog_observation_count = published_in_dialog + in_dialog_observations_omitted

## Not confirmed

The result explicitly lists `IMS_CALL_SUCCESS`, `IMS_CALL_FAILURE`, `TWO_WAY_AUDIO`,
`RTP_DELIVERY`, `EARLY_MEDIA_DELIVERY`, `SESSION_MODIFICATION`,
`SUBSCRIBER_REACHABILITY`, `VOLTE_SERVICE_SUCCESS`, `SIP_TIMEOUT`,
`REGISTRATION_TO_SESSION_ASSOCIATION` and `CROSS_PROTOCOL_ASSOCIATION` as not confirmed.