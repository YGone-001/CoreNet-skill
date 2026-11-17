# SIP failure cases and exit codes

The extractor separates legitimate absence of SIP evidence from extraction failure.
A TShark error is never reported as an empty capture.

## Exit codes

| Code | Meaning | Evidence |
| --- | --- | --- |
| 0 | Extraction succeeded; events were published. | complete run |
| 2 | Invalid input. | missing capture, unrecognised capture signature, malformed JSONL, unsupported field, missing frame number, TLS/unsupported transport in a plaintext SIP record |
| 3 | No plaintext SIP messages observed. | valid capture or PDML with no `sip` protocol instance |
| 4 | Required tool unavailable. | `tshark` executable absent or not startable |
| 5 | Decoder failure. | TShark version or dissection command returned nonzero |
| 6 | Output failure. | no destination, existing output without `--force`, source overwrite, absent output directory, write or readback failure |

## Message classifications

| Classification | Basis |
| --- | --- |
| `COMPLETE` | reviewed start line, CSeq and Call-ID evidence present, no malformed finding, capture not truncated |
| `INCOMPLETE` | valid message missing CSeq or Call-ID |
| `MALFORMED` | missing start line, invalid status code, invalid CSeq, invalid method token, invalid Content-Length, or decoder header-damage finding |
| `TRUNCATED` | capture `cap_len` is shorter than `frame.len` |
| `UNKNOWN` | decoder exposed a SIP instance without a usable start line |

`extraction_status` follows the classification: `OBSERVED`, `PARTIAL` or
`MALFORMED`. The Skill never emits `UNSUPPORTED` for a valid extension method;
extension methods are preserved with `method_scope: EXTENSION`.

## Decoder findings

The extractor recognises the following decoder-reported findings:

- `HEADER_NOT_TERMINATED`
- `HEADER_NO_COLON`
- `INVALID_STATUS_CODE`
- `MISSING_CALL_ID`
- `INVALID_CONTENT_LENGTH`
- `MALFORMED_SECURITY_MECHANISM`
- `UNRECOGNIZED_HEADER`

An unrecognised header is a finding on an otherwise complete message; it is not
silently discarded and it is not promoted to a failure.

## Transport failures

- A capture with SIP over TLS produces no SIP event because no plaintext SIP
  protocol instance is dissected. The extractor does not decrypt TLS.
- A UDP datagram or TCP segment without a complete decoded SIP message is not
  invented as a message boundary.
- A TCP observation is anchored on the frame where the decoder delivers the
  message; missing earlier segments are a capture limitation, not a fabricated
  event.

## Output safety

Output is written through a temporary file and atomically renamed. A successful
command that leaves no readable output is an output failure. An existing output is
never reused implicitly, and an output path equal to the input is refused.