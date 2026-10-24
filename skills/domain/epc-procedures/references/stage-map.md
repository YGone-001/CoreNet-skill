# Stage and Message Map

| Stage | Conditional | Protocol | Messages |
| --- | --- | --- | --- |
| attach-initiation | no | NAS-EPS | Attach request |
| identity | yes | NAS-EPS | Identity request, Identity response |
| authentication | yes | NAS-EPS | Authentication request, Authentication response, Authentication failure, Authentication reject |
| security-mode | yes | NAS-EPS | Security mode command, Security mode complete, Security mode reject |
| attach-decision | no | NAS-EPS | Attach accept, Attach reject |
| attach-completion | no | NAS-EPS | Attach complete |
| s1-context-setup | yes | S1AP | InitialContextSetupRequest, InitialContextSetupResponse, InitialContextSetupFailure |
| context-release | no | S1AP | UEContextReleaseRequest, UEContextReleaseCommand, UEContextReleaseComplete |

## Observation types

`ATTACH_REQUEST_OBSERVED`, `ATTACH_ACCEPT_OBSERVED`, `ATTACH_COMPLETE_OBSERVED`,
`AUTHENTICATION_RESPONSE_OBSERVED`, `SECURITY_MODE_COMPLETE_OBSERVED`,
`S1_CONTEXT_SETUP_RESPONSE_OBSERVED`, `CONTEXT_RELEASE_OBSERVED`,
`IDENTITY_EXCHANGE_OBSERVED`, `REPEATED_ATTACH_REQUEST_OBSERVED`.

## Deviation types

| Deviation | Stage | Meaning |
| --- | --- | --- |
| ATTACH_REJECT_OBSERVED | attach-decision | Explicit Attach rejection with observed EMM cause |
| AUTHENTICATION_FAILURE_OBSERVED | authentication | UE-reported authentication failure |
| AUTHENTICATION_REJECT_OBSERVED | authentication | Network-reported authentication rejection |
| SECURITY_MODE_REJECT_OBSERVED | security-mode | Explicit security mode rejection |
| S1_CONTEXT_SETUP_FAILURE_OBSERVED | s1-context-setup | Explicit S1 Initial Context Setup failure |
| PROTECTED_INNER_MESSAGE_UNAVAILABLE | attach-decision | Protected envelope hides the inner message |
| INSUFFICIENT_TERMINAL_EVIDENCE | attach-decision | No Attach accept or reject observed |

Authentication and security mode control are separate stages with separate messages
and separate deviations; consecutive occurrence never merges them.
