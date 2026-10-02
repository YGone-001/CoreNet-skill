# PFCP Transaction Correlation

Protocol-local correlation of PFCP requests and responses into
transactions. Deterministic, endpoint-scoped, and evidence-safe.

## Transaction scope

A transaction is scoped by:

1. capture identity (safe capture basename plus frame provenance);
2. the observed endpoint pair, order-normalized (address:port on both
   sides);
3. the three-octet PFCP sequence number;
4. a compatible reviewed procedure family.

A sequence number alone never correlates two peers. Two independent PFCP
peer pairs may legitimately reuse the same sequence number, and the same
numeric SEID may exist in unrelated endpoint contexts.

## Derived transaction key

    pfcp-tx:<capture-file>:<endpoint-pair>:seq<sequence>:<family>

The key is explicitly DERIVED, documented here, and is **not** a
standardized PFCP identifier. It never enters a field whose semantics would
claim it was observed on the wire.

## Request/response matching

Within one transaction key, frames are split by the reviewed transaction
role of their message type: a request message and its response message
share the family (for example SessionEstablishment), so the request and the
response land in the same group. Grouping is order-independent: a response
record that appears before its request in the JSONL input still correlates,
because the key does not depend on input order.

## Correlation strength

- **STRONG** — exactly one request frame and exactly one response frame
  share the transaction evidence.
- **MEDIUM** — both a request and a response are present, but at least one
  side carries more than one frame (for example a retransmitted request).
- **WEAK** — only one side is present inside the capture window.

Strength classifies evidence grouping, never causal confidence.

## Duplicates and retransmissions

A repeated request sharing one transaction is reported in
`duplicate_request_candidates`. It is a **candidate** only: every observed
frame is preserved, nothing is deduplicated, and no original evidence is
removed.

## Partial and open transactions

A request with no response, or a response with no request, inside the
capture window is reported as an open transaction with an explicit
limitation. This is a capture boundary, never a network failure: the
response may have been sent outside the window, dropped by a filter, or
observed at a point that never saw it.

## What this correlation does not do

- It does not model a PDU Session lifecycle, and it does not match PFCP
  messages to NAS or NGAP session messages.
- It does not build a session state machine across messages; grouping by
  F-SEID is preserved as evidence only.
- It does not merge transactions that share a numeric SEID across different
  endpoint pairs.
- It does not assign SMF or UPF roles to endpoints. Port 8805 is the
  registered PFCP port but never determines network-function identity.
