# PDU Session Procedure Deviation Model

## Deviation Vocabulary

Procedure deviations categorize observed protocol signaling anomalies, unfulfilled expectations, or correlation ambiguities. They report **what was observed on the wire**, never why or who is to blame.

| Deviation Type | Triggering Evidence | Example |
| --- | --- | --- |
| `PROTOCOL_REJECT_OBSERVED` | Direct protocol rejection message observed on N1. | NAS `PduSessionEstablishmentReject` with 5GSM Cause 27 (`MISSING_OR_UNKNOWN_DNN`). |
| `PROTOCOL_NEGATIVE_OUTCOME_OBSERVED` | Protocol negative response status or error representation. | PFCP `SessionEstablishmentResponse` with Cause = 64 (`Context not found`); SBI HTTP 400 ProblemDetails with Cause = `DNN_NOT_SUPPORTED`. |
| `RESOURCE_FAILED_ITEM_OBSERVED` | Target PDU session resource appears in NGAP failed list. | NGAP `PDUSessionResourceSetupResponse` containing failed item for target PSI with Cause = `radioNetwork: resources-not-available`. |
| `DELIVERY_FAILURE_NOTIFICATION_OBSERVED` | AMF Failure Notification callback observed on N11. | `Namf_Communication_N1N2Transfer Failure Notification` with Cause = `UE_NOT_RESPONDING`. |
| `MISSING_EXPECTED_COUNTERPART` | Expected counterpart message not observed within capture window. | PFCP Session Establishment Request observed without any matching Response before capture end. |
| `CORRELATION_AMBIGUITY` | Multiple candidate instances match an observed event. | SBI transaction for PSI=10 observed while two concurrent UEs both establish PSI=10. |
| `CORRELATION_CONFLICT` | Conflicting values observed across safely associated planes. | NAS accepted PDU Address is `198.51.100.1` while associated PFCP session allocates `198.51.100.2`. |
| `OUT_OF_ORDER_EVIDENCE` | Observed message sequence violates normative causal ordering. | N1 Accept observed before N1 Request in capture. |
| `PARTIAL_CAPTURE` | Capture begins after procedure initiation or terminates prematurely. | Capture starts directly with PFCP Response or ends before Session Decision. |
| `PROTECTED_OR_UNAVAILABLE_PAYLOAD` | Signaling payload is unavailable due to security or TLS. | SBI HTTP/2 payload encrypted under TLS without key material. |
| `UNKNOWN_OR_RESERVED_PROTOCOL_VALUE` | Unrecognized or non-standard protocol cause or IE value. | Unmapped 5GSM cause code or undefined NGAP cause value. |
| `DUPLICATE_OR_RETRANSMITTED_EVIDENCE` | Retransmission or duplicated signaling frame observed. | Repeated NAS Establishment Request with identical PTI and parameters. |

---

## Earliest Observed Procedure-Local Deviation

Within a safely formed procedure instance, the analysis identifies the `earliest_observed_deviation`:
- **Definition**: The deviation belonging to the earliest stage (by normative causal order or frame timestamp) that exhibits direct or deterministic evidence of an anomaly.
- **Scoping**: Must be strictly scoped to the single procedure instance. Deviations from unrelated or ambiguous instances are never compared.
- **Non-Causal Principle**:
  > [!WARNING]
  > The earliest observed deviation represents only the first anomalous event recorded in the capture artifact.
  > It **DOES NOT** prove root cause.
  > It **DOES NOT** identify a software defect or implementation bug in any network function.
  > Causation can only be determined with external implementation logs, configuration, and multi-interface validation.

---

## Capture Truncation and Missing Evidence Rules

1. **Window Awareness**: Missing evidence is strictly reported relative to the available capture window.
   - Example: PFCP Request observed at frame 100, capture terminates at frame 105 without response:
     - Report: `"PFCP Session Establishment Response not observed within capture window"` with `PARTIAL_CAPTURE` limitation.
     - **DO NOT** report: `"PFCP Session Establishment failed"`.
2. **User-Plane Traffic Absence**:
   - If an N3 tunnel is successfully provisioned via PFCP F-TEID, but no GTP-U G-PDU packet is observed:
     - Report: `"no matching N3 G-PDU evidence observed within the available capture window"`.
     - **DO NOT** report: `"USER_PLANE_FAILED"`.
     - User plane may be idle, delayed, or routed outside the capture vantage point.
