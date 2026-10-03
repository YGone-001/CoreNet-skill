# 5GC PDU Session Procedure Model

## Normative Basis

The procedure model is grounded in **3GPP TS 23.502 Release 19 (v19.5.0)**:
- Clause 4.3.2.2 (*UE Requested PDU Session Establishment for non-roaming and roaming with local breakout*)
- Clause 4.3.3 (*PDU Session Modification*)

It integrates supporting protocol-level evidence from:
- **3GPP TS 24.501** (NAS-5GS / 5GSM) on N1
- **3GPP TS 38.413** (NGAP) on N2
- **3GPP TS 29.244** (PFCP) on N4
- **3GPP TS 29.281** and **3GPP TS 38.415** (GTP-U / N3 user plane) on N3
- **3GPP TS 29.502** (Nsmf_PDUSession) on N11
- **3GPP TS 29.518** (Namf_Communication N1/N2 delivery) on N11

## Architecture Boundary and Layer Separation

CoreNet Skill adheres to a strict five-layer dependency model:

```
Foundation -> Protocol -> Correlation -> Domain / Procedure -> Analysis Orchestration
```

1. **Protocol Skills** (`nas-5gs`, `ngap`, `pfcp`, `gtpu`, `sbi-http2`) answer:
   *What message and field was observed on the wire?*
   They own encoding, headers, information elements, transaction correlation, and protocol-local errors.
2. **Correlation Skills** (`cross-protocol-evidence`) answer:
   *Which observations share deterministic provenance or connection keys?*
   They own provenance-key joins without protocol or domain semantics.
3. **Domain / Procedure Skills** (`5gc-pdu-session`) answer:
   *How do observed protocol events fit the telecom procedure stage model?*
   *Which expected evidence is present, missing, or abnormal?*
   *What is the earliest procedure-local deviation observed within the procedure instance?*
4. **Analysis Orchestration** (future layer) answers:
   *Where is the overall failure boundary across procedures?*

The Domain Skill **never** performs raw byte decoding, **never** maps vendor or product source code, and **never** emits `root_cause` or implementation blame verdicts.

## Partial-Order Execution Model

A valid PDU Session procedure in real networks does not strictly follow a single rigid linear sequence. Network latency, parallelized SBI requests, asynchronous AMF scheduling, and capture vantage points can reorder or interleave observed signaling frames across interfaces.

The procedure is modeled as a set of bounded stages with required causal precedence where normatively verified while supporting conditional and asynchronous execution:
- N11 SM Context creation/update and N4 PFCP Session control may proceed concurrently or sequentially depending on SMF deployment.
- N1/N2 transfer may complete synchronously with HTTP 200 or asynchronously with HTTP 202 followed by later delivery.
- User-plane packets on N3 may appear immediately, after delay, or not at all (idle sessions).

## Repeated Modification Attempt Model

PDU Session Modification is an ongoing lifecycle event rather than a single static stage. One established PDU Session instance may experience zero, one, or multiple modification attempts over its operational lifetime.

Each modification attempt is modeled as an independent element in `modification_attempts`:
- **Attempt Identity**: Assigned a sequential identifier `mod-1`, `mod-2`, etc.
- **Trigger Type**: Classified as `UE_REQUESTED` (initiated by NAS `PduSessionModificationRequest`), `NETWORK_REQUESTED` (initiated by SMF via NAS `PduSessionModificationCommand`, N11 `UpdateSMContext`, or PFCP `SessionModificationRequest`), or `UNKNOWN`.
- **Branch Conditionality**: In a network-requested modification, the absence of a UE Modification Request is normal branch behavior and is never flagged as missing evidence or a deviation.
- **Transaction Scoping**: NAS `procedure_transaction_identity` (PTI) is scoped strictly per UE context and PDU Session ID. Two distinct UEs utilizing identical PTI values remain completely isolated.
- **Continuity**: Modification attempts require continuity with the established session context: the established PFCP SEID, the SM Context URI, and the PDU Session ID.
- **Scope Limits**: Modification analysis covers QoS flow updates, F-TEID tunnel updates, and session parameter changes. PDU Session Release lifecycle, handover, and UPF relocation remain explicitly deferred.

## Evidence Planes

The Domain Skill composes evidence across all five primary planes:
1. **N1 Plane**: UE <-> AMF / SMF signaling (Establishment Request/Accept/Reject, Modification Request/Command/Complete/Reject/Command Reject).
2. **N2 Plane**: gNB <-> AMF signaling (Resource Setup Request/Response, Resource Modify Request/Response/Failed Items).
3. **N3 Plane**: gNB <-> UPF user-plane traffic (GTP-U G-PDU observation, Echo, Error Indication, post-modification traffic).
4. **N4 Plane**: SMF <-> UPF session control (PFCP Session Establishment/Modification Request/Response, PDR/FAR/URR/QER rule operations, F-TEID allocation/update).
5. **N11 Plane**: AMF <-> SMF service based interface (Nsmf_PDUSession CreateSMContext / UpdateSMContext, Namf_Communication N1N2MessageTransfer, N1N2Transfer Failure Notification).
