# HTTP/2 Transport Model

## HTTP/2 in 3GPP Service Based Interfaces

Per 3GPP TS 29.500 clause 5.2 and RFC 9113, 3GPP SBA utilizes HTTP/2 as the underlying
application-layer transport protocol. HTTP/2 multiplexes multiple logical streams over
a single persistent transport connection (typically TCP or TCP with TLS).

## Connection Context and Stream Identity

### Fundamental Principle: Stream IDs are Connection-Local

An HTTP/2 `stream_id` (e.g., stream 1, stream 3) is assigned per connection:
- Client-initiated streams use odd numbers (1, 3, 5, ...).
- Server-initiated streams use even numbers.
- **A stream ID is never globally unique.** Multiple concurrent or sequential TCP
  connections between the same or different endpoints each maintain their own independent
  stream numbering starting from 1.

Therefore:
- A stream ID alone **MUST NOT** be used as a transaction key.
- All transaction and event models must scope stream identity by **connection context**:
  `capture_file` + `connection_context` (dissector `tcp.stream` or explicit `connection_id`) + `stream_id`.
- Stream 1 on Connection A and Stream 1 on Connection B are separate, independent transactions.

### Connection Context Definition

- When extracted from PCAP via TShark: `tcp.stream` provides capture-local TCP connection indexing.
  Note that `tcp.stream` is dissector metadata, not an on-the-wire protocol field.
- When ingested from structured input: an explicit `connection_id` or endpoint-pair context
  (`endpoints:{src_addr}:{src_port}-{dst_addr}:{dst_port}`) isolates connections.

## Bounded Frame Types and Fields

This Skill tracks the following HTTP/2 frame types and fields necessary for SBI:

| Frame Type | Scope | Fields Tracked |
| :--- | :--- | :--- |
| `HEADERS` (Request) | Request initiation | `stream_id`, `:method`, `:scheme`, `:authority`, `:path`, `content-type`, `content-length`, safe SBI headers |
| `HEADERS` (Response) | Response completion | `stream_id`, `:status`, `content-type`, `content-length`, `location`, safe SBI headers |
| `DATA` | Body payload | Length and presence evidence; raw payload bytes are NEVER persisted |
| `RST_STREAM` | Stream cancellation | `stream_id`, `error_code` |
| `GOAWAY` | Connection teardown | `last_stream_id`, `error_code`, debug-data presence only |
| `SETTINGS` / `PING` | Control signaling | Recognized as generic control evidence; deep semantics deferred |

## Transport Errors vs. Service Failures

- **RST_STREAM**: Indicates that a stream was abruptly terminated by an endpoint with an HTTP/2 error code (e.g., `CANCEL`, `INTERNAL_ERROR`, `PROTOCOL_ERROR`, `REFUSED_STREAM`). This is transport-layer evidence; it must not be reported as an SMF procedure failure without service-level corroboration.
- **GOAWAY**: Informs the peer that no new streams will be accepted on this connection (e.g., during graceful shutdown or fatal connection error). This is connection-level transport evidence; it does not indicate that a specific PDU session failed.

## Tooling Discipline

Per repository rules, no byte-level HTTP/2 frame parser, HPACK decompressor, Huffman
decoder, or TCP reassembly engine is implemented in Python. Extraction relies on
TShark dissector output or deterministic structured offline input.
