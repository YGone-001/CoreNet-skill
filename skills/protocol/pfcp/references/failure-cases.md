# PFCP Failure Cases

Protocol-local abnormal or inconclusive patterns this Skill can report.
Each pattern names what is OBSERVED, what is DERIVED, and the hard boundary
against causal overreach.

## Response outcomes

- Establishment Response with a Cause that is not "Request accepted" — for
  example 64 Request rejected (reason not specified), 65 Session context
  not found, or 75 No resources available. The Cause is OBSERVED and
  preserved with its reviewed name. It is protocol-defined outcome
  evidence, never a root cause, and it never identifies a defective node.
- Modification Response with a non-acceptance Cause — for example 73 Rule
  creation/modification Failure. A message-level rejection is **not**
  automatically attributable to one rule merely because that rule appeared
  in the request. This Skill does not fabricate "QER 5 failed".
- Deletion Response with a non-acceptance Cause — for example 65 Session
  context not found. Treated as PFCP protocol response evidence only.

## Transaction-level patterns

- Request with no response inside the capture window — reported as an open
  transaction with an explicit limitation. Not a network failure.
- Response with no request inside the capture window — reported as an open
  transaction. The capture may simply start after the request.
- Same sequence number on different endpoint pairs — kept as two separate
  transactions. They must never be correlated.
- Same numeric SEID in different endpoint contexts — kept separate. A
  numeric SEID is not globally unique across every PFCP node.
- Retransmitted request — preserved as separate frames with the extra
  requests reported as duplicate candidates. Original evidence is never
  deleted.
- Out-of-order input — a response record appearing before its request in
  the JSONL input still correlates, because grouping is order-independent.
- Partial capture — the capture starts after the request that would explain
  a response, or ends before the counterpart. The observation window bounds
  every missing-evidence conclusion.

## Message-level patterns

- Malformed structured input — missing or non-integer frame number,
  message type outside 0..255, sequence number outside the 24-bit range,
  SEID outside the 64-bit range, an invalid rule operation or binding
  basis. The extractor fails loudly per record; it never guesses.
- Unknown message type — a code outside the reviewed table is UNKNOWN with
  the numeric code preserved and no invented name, family, direction, or
  result.
- Known but unsupported message — a reviewed message outside the bounded
  subset (Association Update, Node Report, Session Report, Session Set
  Deletion, and similar) is UNSUPPORTED with its reviewed name and no
  deeper semantics.
- Session Report semantics — deliberately deferred. Downlink-data and
  usage-report content is not interpreted in this version.

## Grouped-IE patterns

- Ambiguous grouped IE hierarchy — a message carries several PDR/FAR/QER/URR
  groups and the flattened export does not preserve which nested value
  belongs to which group. Identifiers are preserved as items with a null
  operation and no nested values; the nested values are preserved in
  `unbound_ie_metadata` with a limitation. They are never zipped by array
  position.
- F-TEID visible but not safely bound to one PDR — preserved in
  `unbound_ie_metadata.teids`.
- QFI visible but not safely bound to one QER or PDR — preserved in
  `unbound_ie_metadata.qfis`.
- Conflicting F-SEID evidence — an explicit structured role and flattened
  F-SEID fields disagreeing about which role is present. The explicit role
  is used and a limitation is recorded.
- F-SEID observed on a message type whose CP/UP role is not derivable — left
  unbound with a limitation instead of being assigned a role.

## Capture-boundary uncertainty

    outcome not observed in this capture
    !=
    outcome not sent on the network

- A missing response may be absent because the capture window ended, a
  filter dropped frames, or the capture point never saw the reply.
- A Heartbeat Response absent from a partial capture does **not** mean the
  peer is unavailable.
- A Deletion Command observed without a response does **not** mean the user
  plane has already stopped forwarding.

Reports must name the capture boundary and phrase missing outcomes as
unobserved-in-capture.

## F-TEID boundary

An F-TEID or Outer Header Creation TEID observed in PFCP is control-plane
provisioning evidence. It never establishes that a GTP-U tunnel exists,
carries traffic, or is healthy. Actual user-plane evidence belongs to a
future `gtpu` Skill.

## Explicitly out of scope for causal claims

This Skill does not confirm PDU session success or failure, does not
diagnose SMF, UPF, or transport defects, does not interpret SBI service
operations, and does not produce an end-to-end root cause. Its evidence
ceiling for cause attribution is INFERRED, and only for protocol-local
relationships such as the reviewed logical direction of a message.
