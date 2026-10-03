# PDU Session Procedure Deviation Model

## Deviation Vocabulary

Procedure deviations categorize observed protocol signaling anomalies, unfulfilled expectations, or correlation ambiguities. They report **what was observed on the wire**, never why or who is to blame.

| Deviation Type | Triggering Evidence | Example |
| --- | --- | --- |
| `PROTOCOL_REJECT_OBSERVED` | Direct protocol rejection message observed on N1. | NAS `PduSessionEstablishmentReject` with 5GSM Cause 27 (`MISSING_OR_UNKNOWN_DNN`); NAS `PduSessionModificationReject` / `PduSessionModificationCommandReject`. |
| `PROTOCOL_NEGATIVE_OUTCOME_OBSERVED` | Protocol negative response status or error representation. | PFCP `SessionEstablishmentResponse` / `SessionModificationResponse` with Cause = 64 (`Context not found`); SBI HTTP 400 ProblemDetails with Cause = `DNN_NOT_SUPPORTED`. |
| `RESOURCE_FAILED_ITEM_OBSERVED` | Target PDU session resource appears in NGAP failed list. | NGAP `PDUSessionResourceSetupResponse` or `PDUSessionResourceModifyResponse` containing failed item for target PSI with Cause = `radioNetwork: resources-not-available`. |
| `DELIVERY_FAILURE_NOTIFICATION_OBSERVED` | AMF Failure Notification callback observed on N11. | `Namf_Communication_N1N2Transfer Failure Notification` with Cause = `UE_NOT_RESPONDING`. |
| `MISSING_EXPECTED_COUNTERPART` | Expected counterpart message not observed within capture window. | PFCP Session Modification Request observed without any matching Response before capture end. |
| `CORRELATION_AMBIGUITY` | Multiple candidate instances match an observed event. | SBI transaction for PSI=10 observed while two concurrent UEs both establish PSI=10; concurrent modification requests without distinct PTIs. |
| `LIFECYCLE_AMBIGUITY` | Reuse of the same UE context and PDU Session ID without an evidence-supported release boundary. | New `PduSessionEstablishmentRequest` observed after a Release Command without any `PduSessionReleaseComplete`; lifecycle generation cannot be proven and is never guessed. |
| `CORRELATION_CONFLICT` | Conflicting values observed across safely associated planes. | NAS accepted PDU Address is `198.51.100.1` while associated PFCP session allocates `198.51.100.2`. |
| `FIELD_CONFLICT` | Conflicting QoS, address, or identifier values observed across planes during modification. | NAS authorized QFI differs from PFCP provisioned QFI in a modification attempt. |
| `OUT_OF_ORDER_EVIDENCE` | Observed message sequence violates normative causal ordering. | N1 Accept observed before N1 Request in capture. |
| `PARTIAL_CAPTURE` | Capture begins after procedure initiation or terminates prematurely. | Capture starts directly with PFCP Response or ends before Session Decision / Modification Completion. |
| `PROTECTED_OR_UNAVAILABLE_PAYLOAD` | Signaling payload is unavailable due to security or TLS. | SBI HTTP/2 payload encrypted under TLS without key material; ciphered NAS message without security context. |
| `UNKNOWN_OR_RESERVED_PROTOCOL_VALUE` | Unrecognized or non-standard protocol cause or IE value. | Unmapped 5GSM cause code or undefined NGAP cause value. |
| `DUPLICATE_OR_RETRANSMITTED_EVIDENCE` | Retransmission or duplicated signaling frame observed. | Repeated NAS Modification Request with identical PTI and parameters. |

---

## Earliest Observed Procedure-Local Deviation

Within a safely formed procedure instance or modification attempt, the analysis identifies the `earliest_observed_deviation`:
- **Definition**: The deviation belonging to the earliest stage (by normative causal order or frame timestamp) that exhibits direct or deterministic evidence of an anomaly.
- **Scoping**: Must be strictly scoped to the single procedure instance or modification attempt. Deviations from unrelated or ambiguous instances are never compared.
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
     - Report: `"PFCP Session Modification Response not observed within capture window"` with `PARTIAL_CAPTURE` limitation.
     - **DO NOT** report: `"PFCP Session Modification failed"`.
2. **User-Plane Traffic Absence**:
   - If an N3 tunnel is successfully provisioned via PFCP F-TEID, but no GTP-U G-PDU packet is observed:
     - Report: `"no matching N3 G-PDU evidence observed within the available capture window"`.
     - **DO NOT** report: `"USER_PLANE_FAILED"`.
     - User plane may be idle, delayed, or routed outside the capture vantage point.
3. **Post-Modification GTP-U Absence**:
   - Post-modification GTP-U is conditional observation, not a mandatory procedure counterpart: a valid modification can finish while the user plane stays idle.
   - When no matching packet exists within the attempt observation window, report stage status `NOT_OBSERVED` with empty `missing_evidence` and explicit limitations.
   - **DO NOT** report it as a missing required GTP-U message or emit `MISSING_EXPECTED_COUNTERPART` for idle user plane.
4. **Post-Release N3 Observation**:
   - Post-release G-PDU, End Marker, and Error Indication are conditional observations inside the release attempt observation window; none is universally mandatory.
   - G-PDU observed after release-related evidence is reported neutrally; it is never labeled stale traffic, user-plane failure, or teardown failure (packets may be in flight, reordered, or belong to another safely distinguished lifecycle).
   - No matching packet is reported `NOT_OBSERVED`; absence of traffic does not prove release success.
   - Missing End Marker never produces `MISSING_EXPECTED_COUNTERPART`; an End Marker observation does not prove all old user-plane state was deleted.
   - PFCP deletion acceptance, NGAP release responses, and ReleaseSMContext 2xx responses are bounded plane-local evidence and never overall release success verdicts.
