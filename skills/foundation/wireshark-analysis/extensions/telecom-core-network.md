# Telecom Core-Network Capture Context

## Capture Planning

For EPC, IMS, 5GC, or mobile-core work, define the observation point, direction,
time window, and known subscriber or session scope before capturing. Decide
whether equivalent captures are needed on access-side, core-side, IMS, and
user-plane observation points. Record clock synchronization, snap length,
rotation, and size limits. Control-plane and user-plane captures answer
different questions.

## Transport Classification and Workflow

Classify traffic first by endpoint and transport such as SCTP, UDP, TCP,
HTTP/2, or IPsec-protected traffic. Begin broad, reduce by endpoint and
transport, then use identifiers already known from the case. Save exact display
or tshark filters, timestamps, selected fields, stream-follow steps, and any
capture splitting operation. Do not visually cherry-pick packets or create a
protocol field database here.

## Multi-Capture Evidence

Compare equivalent observation points before interpreting an absence. A packet
absent from one capture is not proof that it did not exist on the network; the
capture point, filter, loss, encryption, and time alignment may limit it.

## Evidence-Safe Examples

- OBSERVED: SCTP packets are present in the selected RAN capture window.
- OBSERVED: No matching transport packet is visible in the selected core capture.
- HYPOTHESIS: The path, observation point, or capture coverage may differ.
- NEXT EVIDENCE: Collect a synchronized capture at an intermediate point.

## Handoff to Higher Layers

Packet extraction and capture coverage do not establish message meaning. Future
Protocol Skills interpret NGAP, NAS, PFCP, Diameter, SIP, or SBI semantics; a
future Domain or Orchestration Skill evaluates procedure behavior and cause.
