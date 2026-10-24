# EPC session-control evidence

This Domain capability consumes the accepted `gtpv2` Protocol Skill output and
reconstructs bounded EPC session-control subjects. It does not decode captures,
does not reinterpret GTPv2 binary fields, and never asserts that a PDN
connection, a default bearer, a user-plane path or an end-to-end service exists.

## Inputs

| Input | Producer | Contract |
| --- | --- | --- |
| Detailed GTPv2-C events | `skills/protocol/gtpv2/scripts/extract-gtpv2.py` | `schemas/gtpv2-event.schema.json` |
| Transaction correlation | `skills/protocol/gtpv2/scripts/correlate-gtpv2.py` | `schemas/gtpv2-transaction.schema.json` |

The Domain consumes both artifacts unchanged. It does not call TShark and does
not read a capture file.

## Transaction outcomes

The correlation status and the protocol Cause are two independent facts.

| Outcome | Meaning |
| --- | --- |
| `RESPONSE_ACCEPTED_OBSERVED` | A matched response carries Cause 16 or 17. |
| `RESPONSE_REJECTED_OBSERVED` | A matched response carries any other Cause. |
| `RESPONSE_OUTCOME_UNKNOWN` | A response was matched but carries no decoded Cause. |
| `OPEN_REQUEST` | No response inside this capture. Not a proven timeout. |
| `RESPONSE_ONLY` | A response without its request in this capture. |
| `AMBIGUOUS_TRANSACTION` | Several responses satisfy the correlation keys; none is selected. |

`REQUEST_OBSERVED` is recorded in each transaction's `observations` list.

## Cause scope

Message-scope and bearer-scope Cause values are never merged. A Create Session
Response can carry Cause 16 at message scope and Cause 72 inside a Bearer
Context; the analysis publishes both, in different fields, with different
scopes.

## Interface evidence

An interface is published only when reviewed evidence establishes the hop:

| Basis | Evidence |
| --- | --- |
| `control_plane_f_teid_in_message` | A non-zero control-plane F-TEID IE in the request or response: types 10/11 mean S11, types 6/7 mean S5/S8. |
| `control_plane_teid_continuity` | The request header TEID matches a control-plane F-TEID observed in an earlier transaction of the same capture. |
| `conflicting_control_plane_f_teids` / `conflicting_control_plane_teid_continuity` | Evidence points at both hops; the interface stays `UNKNOWN_INTERFACE`. |
| `unavailable` | No control-plane evidence; the interface stays `UNKNOWN_INTERFACE`. |

A transport address, a UDP port, a timestamp, an EBI, a sequence number or a
Cause value never establishes an interface on its own.

## Subject grouping

A subject groups transactions that belong to one control-plane context. Grouping
requires all of:

1. The same resolved interface.
2. The same directed request endpoint pair.
3. At least one shared control-plane TEID.

Transactions with an unresolved interface never join another subject. A
transaction that shares only an EBI, a timestamp, an address or a Cause value
with another transaction stays separate.

`association_strength` is `STRONG` when several transactions share a
control-plane TEID, and `UNBOUND` for a single transaction, which asserts no
grouping.

## Generation handling

An accepted Delete Session closes its context generation. A later transaction
that reuses one of the closed TEIDs starts a new subject and records a
`CONTEXT_REUSE_AFTER_DELETION` deviation with the prior subject reference. The
new generation never inherits the preceding generation's evidence.

## What is never asserted

| Not asserted | Why |
| --- | --- |
| S11 to S5/S8 association | The capture shows both hops, but no reviewed identity bridge links a specific S11 transaction to a specific S5/S8 transaction. |
| Attach UE to session association | S1AP/NAS-EPS evidence and GTPv2-C evidence have no reviewed common identifier; a shared timestamp or an E-RAB ID equal to an EBI is not a bridge. |
| PDN connection or default bearer success | A Cause of 16 accepts a message, not a connection. |
| User-plane forwarding | An F-TEID in an accepted exchange says nothing about packet delivery. |
| Deletion completeness | An accepted Delete Session Response accepts the request, not immediate state removal. |
| Global EPC boundary | `boundary_selection_status` is always `NOT_EVALUATED`; no first abnormal boundary is selected. |

## Evidence references

Every deviation carries `frame_number`, `protocol`, `message_type`,
`transaction_reference`, `evidence_refs` and an `observation_window`, so a
reader can return to the exact frames. Lists are bounded and any omission is
reported.
