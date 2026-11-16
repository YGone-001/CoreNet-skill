# Diameter Core

## Purpose

Answer WHAT an observed Diameter base-protocol message and its AVPs mean at the
protocol layer: header fields and flags, command identity, Application-ID,
Hop-by-Hop and End-to-End identifiers, bounded AVP structure, grouped-AVP
nesting proven by the dissector, Result-Code and Experimental-Result namespace
separation, and protocol-local Request/Answer correlation.

This is a Protocol-layer Skill for RFC 6733 Diameter base behavior. It does not
own S6a, Gx, Rx, Cx, credit-control, IMS or any other application procedure.

## Scope

- Publish the Diameter version, declared message length, observed dissected
  length, individual R/P/E/T flag states, Command Code, Application-ID,
  Hop-by-Hop Identifier, End-to-End Identifier, direction, frame number and
  message occurrence within the frame.
- Recognize the reviewed base commands Capabilities-Exchange, Re-Auth,
  Accounting, Abort-Session, Session-Termination, Device-Watchdog and
  Disconnect-Peer. Other commands remain numerically observable with no
  application meaning attached.
- Preserve the numeric Application-ID and distinguish the common base
  application from unsupported application namespaces.
- Publish bounded AVP evidence: code, flags, Vendor-ID, length, reviewed name,
  occurrence index, nesting depth, parent-provided path, safe value, data
  presence and grouping status.
- Publish grouped-AVP child relationships only when the dissector proves them.
- Publish Result-Code in the base namespace and Experimental-Result-Code in the
  vendor namespace separately. An Experimental-Result-Code is never mapped to a
  base Result-Code name.
- Provide deterministic protocol-local Request/Answer correlation with
  `MATCHED`, `OPEN_REQUEST`, `RESPONSE_ONLY` and `AMBIGUOUS` status.
- Support a live PCAP/PCAPNG capture through TShark, a stored PDML dissection,
  and sanitized dissector-record JSONL for deterministic offline replay.

## Non-Goals

- No Diameter application procedure semantics, no S6a/S6d/Gx/Rx/Cx interpretation,
  no EPC Attach, IMS registration, charging, bearer or call verdict.
- No subscriber identity, authentication vector, keying material, raw
  User-Name, Subscription-Id value or raw grouped payload publication.
- No custom TCP/SCTP reassembly engine.
- No grouping inferred from AVP list position or decoder-independent heuristics.
- No timeout, retransmission or peer-failure conclusion from an unanswered
  request.
- No application-level success or failure conclusion from a Diameter result.
- No cross-protocol identity invention, hashing of sensitive values, or
  correlation between application namespaces by numeric identifier coincidence.

## Inputs

| Input | Description |
| --- | --- |
| PCAP / PCAPNG | A capture containing Diameter over TCP or SCTP. Requires a user-installed TShark; the capture is dissected to PDML so message occurrences and grouped AVPs survive. |
| PDML | A stored `tshark -T pdml` dissection. No decoder is required at run time. |
| Sanitized JSONL | One dissector record per line using the reviewed shape in `references/field-reference.md`. No decoder is required. |

## Outputs

- Detailed Diameter event JSONL (`schemas/diameter-event.schema.json`).
- Protocol-local transaction JSON (`schemas/diameter-transaction.schema.json`).
- Shared trace-event JSONL projection (`schemas/trace-event.schema.json`).
- Readable protocol-local timeline.

## Evidence semantics

Header values, AVP structure and result values are `OBSERVED` when present in the
verified dissection. Transaction status and latency are `DERIVED` from those
observations. The Skill never emits `INFERRED`, `HYPOTHESIS` or `CONFIRMED`
application or procedure conclusions.

The End-to-End Identifier is a Diameter header identifier, not a telecom session
identity. The Hop-by-Hop Identifier is transport-hop scoped and is never treated
as globally unique.

## Correlation

Correlation requires the same capture, the same transport association, opposite
endpoint direction, equal Command Code, equal Application-ID and equal
Hop-by-Hop Identifier. Equal End-to-End Identifier evidence raises the result to
`STRONG`; otherwise the pair is not claimed. Frame proximity is never a matching
basis. A single Answer occurrence is assigned to at most one Request.

An unanswered request is `OPEN_REQUEST`; it does not prove a timeout. An Answer
without a matching Request is `RESPONSE_ONLY`. Competing Requests or Answers
remain `AMBIGUOUS` with every candidate published.

A Request is never selected before the End-to-End Identifier matches. A
contradictory identifier is not an eligible candidate and does not create false
ambiguity. Non-`MATCHED` records never publish a selected Request or latency.

Association identity is decoder-proven: TCP stream or SCTP Association Index.
Without that evidence the event is `ENDPOINT_ONLY` and correlation is
fail-closed; an endpoint tuple alone never proves Association continuity. The
SCTP Verification Tag is direction-specific evidence, not an association key.

## Privacy

Sensitive AVPs publish only structural metadata: code, flags, Vendor-ID, length,
occurrence and presence. User-Name, Subscription-Id, authentication information
and authentication vectors never publish a raw value. Session-Id is published as
opaque presence and length metadata because real values may embed a subscription
identifier.

## Supported decoder

Verified against TShark 4.2.2. The implementation uses PDML field names actually
emitted by that decoder and does not decode packet bytes itself.

## Known limitations

- Application-specific semantics are unsupported and remain numeric.
- Grouped structure is published only when the decoder exposes child AVPs.
- PDML and JSONL are bounded to 128 published AVP nodes and 4 nesting levels per
  message; JSONL input above 4096 nodes or 64 nesting levels is rejected.
- A transport segment without a complete dissected Diameter message is not
  published as a complete message.
- The Skill does not reassemble TCP or SCTP streams itself.
- Correlation requires a decoder-proven TCP stream or SCTP Association Index;
  endpoint-only evidence is fail-closed.
- Experimental-Result-Code names are not interpreted.
- Result success is protocol-local and never an EPC, IMS or VoLTE outcome.

## Provenance

Original CoreNet Protocol-layer package. No upstream material imported. Standards
basis: RFC 6733 and the reviewed IANA registries exposed by the installed
Wireshark/TShark decoder.