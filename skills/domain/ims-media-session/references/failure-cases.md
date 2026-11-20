# Failure Cases

## Input and provenance failures

| Case | Required behavior |
|---|---|
| Wrong analysis name or version | Rejected, exit `2`, no output |
| Wrong SDP event schema version | Rejected, exit `2`, no output |
| IMS Session file SHA-256 differs from IMS Media Signaling provenance | Rejected |
| SDP file SHA-256 differs from IMS Media Signaling provenance | Rejected |
| SDP file SHA-256 differs from Transport Correlation provenance | Rejected |
| Capture basename mismatch | Rejected |
| Capture SHA-256 mismatch | Rejected |
| Endpoint context mismatch | Rejected |
| Endpoint context absent on both sides | Accepted; insufficient endpoint evidence preserved |
| Duplicate attempt, branch, Dialog, exchange or correlation reference | Rejected |
| Invalid media-section index, SDP reference or stream reference | Rejected |
| Correlation MID disagrees with the SDP media section | Rejected |
| Output collides with an input | Rejected, no output |

## Ownership failures

| Case | Required behavior |
|---|---|
| One accepted branch owns the answer | `BRANCH` / `ESTABLISHED` |
| All bindings are shared initial-offer messages | `ATTEMPT` / `ESTABLISHED` |
| Two forked branches share an initial offer | Offer published once at attempt level |
| Correlation spans multiple branches | `AMBIGUOUS` with candidate branches |
| Correlation spans multiple attempts | `AMBIGUOUS` with candidate attempts |
| Relationship spans attempts or branches | Record kept indivisible |
| Exchange branch identity not established | `UNBOUND` / `INSUFFICIENT_EVIDENCE` |
| Exchange does not reference an SDP message | `UNBOUND` / `NOT_ESTABLISHED`, `NO_SIGNALING_EXCHANGE_OWNER` |
| Exchange reference mismatch or Dialog mismatch | Rejected |
| Historical Dialog terminated after accepted confirmation | Historical association preserved with release context |
| Missing termination evidence | Branch remains confirmed or early; no invented release |
| Established exchange has no Correlation record | `TRANSPORT_CORRELATION_NOT_OBSERVED` |

## Transport association failures

| Case | Required behavior |
|---|---|
| Original `MATCHED_ENDPOINT` | Preserved exactly, never upgraded |
| Original `BUNDLE_TRANSPORT_MATCHED` | One shared observation, all media bindings preserved |
| Original `AMBIGUOUS` | Preserved; IMS binding may be branch/attempt or ambiguous |
| Original `INSUFFICIENT_EVIDENCE` | Preserved; no fabricated match |
| Original `UNMATCHED` | Preserved |
| Original `OUT_OF_SCOPE` | Preserved |
| Missing endpoint context | Insufficient endpoint evidence, no match |
| Same endpoint across unrelated media | Original ambiguity preserved |
| Correlation truncation | Explicit omission counter; ambiguity never silently discarded |
| Unmatched RTP stream | Preserved without Dialog or subscriber ownership |

## Provisional and unsupported signaling

| Case | Required behavior |
|---|---|
| Provisional SDP | `PROVISIONAL_SDP_UNINTERPRETED`, never early-media establishment |
| Unsupported in-dialog SDP | `UNSUPPORTED_SDP_OBSERVATION`, not interpreted |
| Unbound SIP SDP event | Preserved |
| Unmatched SDP message | Preserved |
| Unusable initial SDP | Upstream fail-closed exchange preserved |

## Privacy and temporal failures

| Case | Required behavior |
|---|---|
| Raw IP address, UDP port, endpoint tuple or key in output | Validation failure |
| Raw SIP/SDP body, Call-ID, tag or subscriber identity in output | Validation failure |
| Claimed temporal association | Validation failure |
| Claimed media delivery, two-way audio, QoS, MOS or codec verdict | Not published |
| Claimed RTP teardown after BYE | Not published |
| Claimed RTP MID demultiplexing | Not published |