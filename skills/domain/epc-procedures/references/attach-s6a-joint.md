# EPS Attach and S6a/S6d joint evidence

The joint companion consumes accepted EPS Attach and Diameter EPC analysis
artifacts. It is presentation and evidence composition only.

## Independent facts

- EPS Attach instances retain their existing procedure verdicts, stages,
  deviations and limitations.
- Diameter S6a/S6d observations retain their Core transaction reference,
  transaction status, result namespace, presence status and Core latency.
- A shared timeline is ordering evidence, not causation and not shared identity.

## Provenance

`input_provenance` records both artifact SHA-256 values, the supplied capture
digest when one is available, and producer identities. The captured distinction is
deliberate:

- A capture digest identifies the supplied capture file.
- An artifact digest identifies the supplied analysis artifact.
- Neither digest by itself proves that an artifact was generated from that capture.
- A matching filename proves none of those relationships.

The accepted statuses are:

| Status | Meaning |
| --- | --- |
| `VERIFIED_COORDINATED_CAPTURE_CONTEXT` | A coordinated-run manifest binds the capture and both artifacts by digest, and the run declares the required producer invocations. |
| `CAPTURE_HASH_OBSERVED_UNBOUND` | A capture was supplied, but no run-level evidence binds the artifacts to those capture bytes. |
| `DECLARED_PROVENANCE_UNVERIFIED` | A run manifest was declared but its capture or producer evidence could not be verified. |
| `FILENAME_MATCH_ONLY` | The artifacts merely agree on a filename. |
| `UNVERIFIED` | No source relationship could be established. |

The standalone CLI never promotes `--capture` alone to verified coordinated
provenance. The unified analyzers write a coordinated-run manifest recording the
run identifier, capture digest, Attach and Diameter EPC artifact digests, producer
identities and the producer invocations executed during that run. The joint model
verifies the manifest's capture and artifact digests before using it. A capture or
artifact digest contradiction fails closed as invalid input. A verified context
affects ordering only; it never creates a per-UE identity association.

## Collection publication

The joint artifact publishes counts separately from the retained records. Each of
`attach_inventory`, `diameter_inventory` and `timeline` records the number of
records omitted by this producer. A consumer that applies a stricter presentation
limit must add its projection omissions to that source omission count and must never
label the truncated list as the complete collection. The unified report publishes
`source_total = published + omitted_by_producer + omitted_by_projection` for each
collection.

## Identity association

No reviewed identity bridge currently exists between an S1AP UE context and a
privacy-safe S6a/S6d subscriber context. The companion therefore publishes:

```text
status = INSUFFICIENT_EVIDENCE
established_pair_count = 0
candidate_pairs = []
```

It never creates a Cartesian product of Attach attempts and Diameter
transactions, never uses timing/external endpoints/order as identity evidence,
and never asks for or publishes an IMSI, User-Name, Session-Id value or
authentication vector.

## Ordering and latency

With verified common-capture context, rows order by frame and message occurrence.
Otherwise ordering is source-local only. Diameter latency is copied only from
MATCHED Core transactions; it is never recomputed from frame numbers.

## Diagnostics

Counts describe observed evidence. They do not establish a root cause. Reported
Diameter failure counts, open/ambiguous counts and earliest abnormal frames are
diagnostic observations, not a first causal failure boundary.