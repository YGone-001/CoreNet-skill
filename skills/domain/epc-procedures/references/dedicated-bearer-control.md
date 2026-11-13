# Dedicated Bearer Control-Plane Outcome Evidence

## Scope

This reference defines the bounded EPC Domain interpretation of GTPv2-C Create,
Update and Delete Bearer control messages:

| Procedure | Messages | Accepted family |
| --- | --- | --- |
| Create Bearer | 95 Request, 96 Response | `create-bearer` |
| Update Bearer | 97 Request, 98 Response | `update-bearer` |
| Delete Bearer | 99 Request, 100 Response | `delete-bearer` |

The producer consumes already-extracted detailed GTPv2-C events and the accepted
transaction-correlation artifact. It never re-correlates a request and response,
never re-decodes a capture and never replaces the Protocol Skill.

## Specification review

Normative reference: 3GPP TS 29.274, message identities, grouped Bearer Context
IE, message-level and bearer-level Cause, Linked EPS Bearer ID and reviewed
dedicated-bearer procedure structure. Field values were cross-checked against the
installed TShark 4.2.2 GTPv2 registry. The exact 3GPP release number was not
independently verified because no local specification copy was available; this
limitation is preserved in the analysis.

## Independent evidence dimensions

1. **Transaction correlation** is copied from the accepted Protocol transaction
   artifact: `MATCHED`, `OPEN_REQUEST`, `RESPONSE_ONLY` or `AMBIGUOUS`, with its
   strength and basis. A Response remains uniquely owned by one transaction.
2. **Message-level observed outcome** is derived only from the selected response
   message Cause. `16 Request accepted` is `MESSAGE_ACCEPTED_OBSERVED`; another
   valid Cause is `MESSAGE_REJECTED_OBSERVED`; absent or unselected evidence is
   `MESSAGE_OUTCOME_NOT_OBSERVED` or `MESSAGE_OUTCOME_AMBIGUOUS`.
3. **Bearer-item outcome** is derived only from that grouped Bearer Context's own
   Cause. A missing item Cause is `ITEM_OUTCOME_NOT_OBSERVED`. The message Cause is
   never copied to an item and an item Cause is never promoted to the message.

Transaction classifications:

```text
CONTROL_ACCEPTED_OBSERVED
CONTROL_REJECTED_OBSERVED
CONTROL_PARTIAL_OR_MIXED
CONTROL_OUTCOME_UNRESOLVED
```

`CONTROL_PARTIAL_OR_MIXED` is used when the message outcome is accepted but at
least one observed response Bearer Context item is rejected or lacks its own
Cause. A non-matched correlation is always `CONTROL_OUTCOME_UNRESOLVED`.

## Bearer item identity

Each grouped Bearer Context item keeps:

- capture, transaction reference, side, frame, message occurrence and item index;
- EBI, EBI validity and duplicate status;
- item Cause, F-TEIDs, QoS and bounded TFT presence;
- source completeness and item-specific limitations.

An EBI is valid only in the reviewed dedicated-bearer range 1–15. Missing EBI,
EBI zero/out-of-range, duplicate values inside one context and duplicate values
across contexts fail closed. EBI is never a globally unique identity by itself.

## Request/response item association

An association is `ITEM_ASSOCIATION_ESTABLISHED` only when all of the following
hold:

- the transaction is `MATCHED`;
- request and response observations belong to the same capture and a uniquely
  selected response;
- each side has exactly one grouped item with the same valid EBI;
- neither side has duplicate or invalid EBI evidence.

Array order, frame proximity, TEID and QCI are never used. Reordered arrays still
associate by EBI. Duplicate evidence is `ITEM_ASSOCIATION_AMBIGUOUS`; missing or
invalid identity is `ITEM_ASSOCIATION_NOT_ESTABLISHED`.

Delete Bearer top-level EBI evidence is published as a bounded message-scope
reference. It does not manufacture a grouped request item and cannot establish an
item association.

## Evidence boundaries

The following are never inferred:

- dedicated-bearer activation, modification or effective removal;
- UE acceptance or ESM activation confirmation;
- E-RAB or radio-bearer establishment;
- QoS admission or installed GBR/MBR values;
- TFT installation or packet-filter rules;
- S1-U forwarding or packet delivery;
- policy decisions, root cause or release effective time.

A matched control transaction and a properly scoped Cause prove only an observed
signalling exchange and an observed control-plane outcome.

## Bounded output

`control_transactions`, `bearer_item_observations` and `item_associations` each
publish a total count, a published subset and an explicit omitted count. The
input does not declare an exhaustive universe, so
`source_completeness.exhaustive_coverage_proven` stays false. Output ordering and
references are deterministic and capture-scoped.

## Optional Session Identity

A supplied Session Identity artifact is preserved as capture-scoped context only.
The accepted contract does not publish an established relationship from a
dedicated-bearer control transaction to a hop-local session context; the producer
therefore reports `session_identity_context.status = NOT_ESTABLISHED` and never
joins by header TEID or EBI alone.

## Real-capture boundary

The accepted dedicated-bearer fixture is synthetic PDML. Real dedicated-bearer
capture replay remains `NOT EXECUTED` unless an authorized capture containing the
relevant control messages is supplied and verified.