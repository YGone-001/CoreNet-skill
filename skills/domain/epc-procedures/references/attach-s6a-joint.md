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

`input_provenance` records both artifact SHA-256 values and producer identities.
A capture SHA-256 and `VERIFIED_COORDINATED_CAPTURE_CONTEXT` are recorded only
when one capture is supplied by the coordinated workflow. A filename match alone
is reported as `FILENAME_MATCH_ONLY`; it never becomes verified same-capture
identity.

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