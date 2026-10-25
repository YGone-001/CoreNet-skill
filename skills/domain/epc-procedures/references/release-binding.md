# Release Binding

Contract for binding an accepted Delete Session transaction to a hop-local
session context and, conditionally, to a bearer generation. The release outcome
classification itself is unchanged: it comes only from the accepted
`message_cause` (scope `message`) of the correlated response, exactly as the
bearer-lifecycle contract fixes it.

## Accepted outcome versus session binding are distinct facts

```text
release_outcome_status = ACCEPTED
```

can coexist with

```text
release_session_binding_status = NOT_ESTABLISHED
```

and with

```text
bearer_generation_closure_status = NOT_ESTABLISHED
```

An accepted release is never reclassified as unresolved because its session
binding cannot be established, and a proved binding never upgrades a non-accepted
outcome.

## Release-to-session binding

A Delete Session request binds to a hop-local session context when its request
addresses exactly one context through the receiver-scoped rule of the session
identity bridge (request header TEID and destination address equal one hop-local
control-plane F-TEID of the context; the request source address equals the
context's path peer). The binding keeps:

- exact request and accepted-response provenance (`MATCHED` transaction with
  reviewed correlation strength);
- the resolved interface class of the bound context;
- the receiving-side control-plane endpoint (F-TEID interface type, TEID and
  address);
- exact source frames for request and confirmation.

A release request does **not** have to repeat an S1-U F-TEID to close a proved
control-plane context. However, closing a control-plane context is not
automatically proof of closing a particular S1-U bearer generation.

## Release-to-generation chain

The bearer-lifecycle capability keeps its direct endpoint-bound release path and
adds one reviewed alternative path. The alternative path closes a generation only
when the whole chain passes its own gates:

```text
Accepted Delete Session transaction
      |   (provenance: MATCHED, accepted message-scope Cause, exact frames)
      v
Proved hop-local session context
      |   (receiver-scoped addressing, exactly one candidate)
      v
Independently supported session-to-bearer relationship
      |   (SESSION_CONTEXT_TO_BEARER_GENERATION = ESTABLISHED)
      v
Specific bearer generation
```

Required for a closure candidate:

1. the Delete Session outcome is accepted;
2. the request and response belong to one accepted transaction;
3. the release uniquely names the intended control-plane context;
4. that context is linked to one specific bearer endpoint per receiving role by
   accepted source evidence (the advertising transaction is a member of the
   context);
5. no competing endpoint of the same receiving role shares the context;
6. the binding does not require an invented S11<->S5/S8 join (a cross-hop link
   is admissible only through a separately proved session identity bridge that
   is cited in the link);
7. capture and transaction provenance are exact;
8. the release request and confirmation frames remain distinct;
9. the release's message-scope bearer identities (Linked EPS Bearer ID) are
   compatible with the endpoint's item-scoped identities whenever both are
   present.

If any required link is missing the result is
`GENERATION_CLOSURE_NOT_ESTABLISHED` and the accepted release stays visible.

## Same-hop before cross-hop

- **Case A** — allocation, bearer evidence and Delete Session connect within one
  reviewed hop-local context: a safe release-to-generation relationship needs no
  cross-interface claim.
- **Case B** — allocation observed only on S5/S8 and release only on S11: never
  connected by timestamp proximity or shared EBI; a separately proved
  cross-interface bridge is required and is cited in the link.
- **Case C** — the release identifies only a common numeric TEID: unresolved.
- **Case D** — several bearer generations share one context: none closes
  automatically; item-scoped bearer identity or the receiving-role uniqueness
  gate must isolate each intended target.

## Temporal contract

The lifecycle capability continues to publish `release_request_frame`,
`release_confirmation_frame` and
`release_effective_frame_proven = false`. The exact instant GTP-U forwarding
stopped is never asserted, and packets inside a pending-release interval stay
conservatively unresolved.
