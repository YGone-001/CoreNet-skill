# Boundary Model

## Boundary Candidate Classes

Boundary candidates come only from deviations already emitted by a supported
Domain Skill. The source vocabulary is mapped exactly and never renamed:

| Source deviation | Boundary class |
| --- | --- |
| `PROTOCOL_REJECT_OBSERVED` | Directly observed protocol rejection. |
| `UNSUCCESSFUL_OUTCOME_OBSERVED` | Directly observed unsuccessful protocol outcome. |
| `PROTOCOL_NEGATIVE_OUTCOME_OBSERVED` | Directly observed negative response (status or cause). |
| `RESOURCE_FAILED_ITEM_OBSERVED` | Item-scoped failed resource evidence. |
| `DELIVERY_FAILURE_NOTIFICATION_OBSERVED` | Directly observed delivery-failure notification. |
| `MISSING_EXPECTED_COUNTERPART` | Derived absence of an expected counterpart. |
| `FIELD_CONFLICT` | Cross-plane conflicting values, when emitted as a deviation. |

## Boundary Anchors

A candidate never fabricates an exact failure time. For a directly observed
negative event the anchor preserves the exact provenance carried by the Domain
output: `capture_file`, `frame_number` (from the deviation description or the
Domain stage evidence for that deviation's stage), and `timestamp` where the
Domain supplies a frame-to-timestamp mapping. `message_type` is preserved only
when a Domain contract supplies it. For a derived missing-evidence candidate
the anchor is the source observation window, never a fabricated frame.

## Evidence-Limitation Classes

`PARTIAL_CAPTURE`, `CORRELATION_AMBIGUITY`, `CORRELATION_CONFLICT`,
`LIFECYCLE_AMBIGUITY`, `PROTECTED_OR_UNAVAILABLE_PAYLOAD`,
`PROTECTED_INNER_MESSAGE_UNAVAILABLE`, `OUT_OF_ORDER_EVIDENCE`, and
`DUPLICATE_OR_RETRANSMITTED_EVIDENCE` are evidence-quality or association
limitations. They are preserved under `evidence_limitations` and are never
selected as the first abnormal network-procedure boundary by default.

`UNKNOWN_OR_RESERVED_PROTOCOL_VALUE` remains visible as a supporting protocol
anomaly under `supporting_anomalies`; in this version it is never preferred
over a direct protocol reject or negative outcome.

## Missing-Evidence Safety

`MISSING_EXPECTED_COUNTERPART` differs from an observed negative response: its
boundary is `DERIVED` from an expected branch, the source observation window,
and sufficient capture coverage. When the source Domain simultaneously marks
the observation window partial, the missing candidate is blocked
(`BLOCKED_BY_PARTIAL_CAPTURE`) and cannot be selected as a proven first
boundary; the group reports `INSUFFICIENT_COMPARABLE_EVIDENCE` with the
additional evidence needed.
