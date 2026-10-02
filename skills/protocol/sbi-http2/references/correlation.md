# SBI HTTP/2 Transaction Correlation

## Correlation Model

This Skill implements protocol-local request/response correlation within HTTP/2 streams
and API resource grouping across SM Context transactions.

## Stream-Scoped Transaction Key

HTTP/2 streams multiplex concurrent requests and responses over a single transport connection.
Because stream IDs repeat across connections, a transaction key must be scoped by the
underlying connection context:

    sbi-tx:<capture>:<connection-context>:stream<stream_id>

Where:
- `<capture>` is the sanitized capture file name.
- `<connection-context>` is the dissector TCP stream (`tcp-stream:<id>`), explicit connection
  identifier (`conn:<id>`), or ordered endpoint pair.
- `stream<stream_id>` is the HTTP/2 stream ID.

**Note:** The transaction key is DERIVED; it is not a standardized 3GPP protocol identifier.

### Connection Isolation Requirement

- Stream 1 on Connection A and Stream 1 on Connection B produce distinct transaction keys:
  - `sbi-tx:capture.pcap:tcp-stream:0:stream1`
  - `sbi-tx:capture.pcap:tcp-stream:1:stream1`
- They are processed as separate transactions and never combined.

## Correlation Strength Classification

| Strength | Criteria | Status |
| :--- | :--- | :--- |
| `STRONG` | Both request (HEADERS with method) and response (HEADERS with status) are observed on the same connection and stream | `transactions` array |
| `PARTIAL` | Open request with no observed response, or orphan response with no observed request | `open_transactions` array |
| `WEAK` | Fragmentary or single-frame stream with ambiguous boundaries | `open_transactions` array |

Neither `PARTIAL` nor `WEAK` correlation indicates a network failure by itself; captures
may start after a request or stop before a response.

## SM Context Identity and Resource Correlation

### SM Context Reference Scope

An individual SM Context resource is identified by its URI reference (`sm_context_ref`).
- The reference is scoped by the API root / authority of the serving SMF.
- Identical textual suffixes under different API roots or authorities (e.g.,
  `smf-a.example.org/.../sm-contexts/c1` vs. `smf-b.example.org/.../sm-contexts/c1`)
  must not be merged.

### Creation Transition

- A `CreateSMContext` request targets the collection resource `/sm-contexts`. At request
  time, no `sm_context_ref` exists yet.
- The `201 Created` response provides the assigned resource reference via the `Location`
  header (and/or `SmContextCreatedData.smContextRef`).
- The correlation engine maps the newly created reference to the initiating transaction.

### PDU Session ID vs. SM Context Reference

- **`pdu_session_id`**: A UE-allocated integer (1..255) identifying the PDU session.
- **`sm_context_ref`**: An SMF-allocated URI or resource identifier string.
- They are completely different namespaces and must never be substituted for one another.
