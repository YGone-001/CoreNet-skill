# IMS Media Session Evidence

## Purpose

Compose four accepted evidence sources into a bounded, branch-scoped IMS media
transport evidence analysis:

```text
IMS Session Attempt -> SIP Dialog Branch -> SDP Offer/Answer Exchange
-> SDP Media Section -> RTP UDP Transport Correlation
```

The Domain answers which observed RTP transport endpoint correspondences can be
associated with which accepted IMS media-signaling exchanges and Dialog Branches.
It does not establish media delivery or successful IMS media-session operation.

## Inputs

1. IMS Session Analysis (`ims-session` 0.1.0).
2. IMS Media Signaling Analysis (`ims-media-signaling` 0.3.0).
3. SDP Analysis (`sdp-rtp` 0.2.0, event schema 1.1.0).
4. SDP/RTP Transport Correlation (`sdp-rtp-transport` 0.1.0).

The Domain never requires raw SIP events, raw RTP/RTCP analysis, raw SDP bodies,
PCAP files, an HMAC key or TShark. It consumes only the accepted artifacts.

## Workflow

1. Validate analysis names, versions, schemas, capture identity and SHA-256
   provenance.
2. Verify that the IMS Media Signaling `ims_session_sha256` and
   `sdp_analysis_sha256` equal the actual supplied files, and that the Transport
   Correlation SDP SHA-256 equals the supplied SDP file.
3. Verify that SDP endpoint context and Transport Correlation endpoint context
   match; both absent is accepted as insufficient endpoint evidence.
4. Resolve every IMS Session attempt, branch and Dialog; reject duplicate or
   contradictory identity.
5. Resolve every SDP message and media-section reference; reject invalid indices,
   MID disagreement, duplicate binding and missing references.
6. Build one indivisible Domain transport observation per Transport Correlation
   record and resolve all of its SDP bindings against all exchanges.
7. Publish attempt-level shared initial-offer evidence once, branch-bound answer
   observations separately, and preserve multi-owner ambiguity without splitting
   the Correlation record.
8. Attach each Domain observation to its exchange references and branch records.
9. Publish unmatched RTP streams and unbound signaling observations unchanged in
   meaning.
10. Check count conservation and privacy, then write deterministic JSON and an
    optional text report.

## Evidence Rules

- `OBSERVED`: accepted lower-layer artifact evidence.
- `DERIVED`: the IMS ownership association itself.
- Binding scope is `ATTEMPT`, `BRANCH`, `AMBIGUOUS` or `UNBOUND`.
- Binding status is `ESTABLISHED`, `AMBIGUOUS`, `INSUFFICIENT_EVIDENCE` or
  `NOT_ESTABLISHED`; it is separate from the original transport-correlation
  status.
- The original correlation `association_status`, `correlation_strength`,
  `correlation_type`, match directions, endpoint references, UDP Stream
  references, RTP event references, missing evidence and conflicts are preserved
  exactly.
- An initial INVITE Offer shared by forked branches is published once at attempt
  level. Branch records refer to the shared observation; it is never duplicated
  as independent RTP evidence.
- A Correlation Record is indivisible. If it spans multiple branches or attempts,
  the Domain publishes `AMBIGUOUS` with candidate owners and never selects one.
- A resolved BUNDLE shared transport remains one observation with all media
  sections, MIDs and stream references. No RTP MID demultiplexing is performed.
- Every Transport Correlation reference appears exactly once in the Domain
  observation inventory.
- Every observation publishes
  `temporal_association_status = NOT_EVALUATED` and
  `association_scope = CAPTURE_WIDE_ENDPOINT_CORRESPONDENCE_ONLY`.
- A later BYE or 200 OK to BYE is lifecycle context only; it never proves RTP
  teardown, media resource release or media-session success.

## Failure Handling

Malformed, contradictory, cross-capture, wrong-hash, duplicate-reference or
unsupported-version inputs return a non-zero exit before output is written.
Missing endpoint context, missing correlation records, unbound SDP messages and
provisional SDP remain explicit insufficient, unmatched or out-of-scope evidence,
never fabricated associations.

## Validation

```bash
python3 -m unittest discover -s skills/domain/ims-media-session/tests -p 'test_*.py' -v
python3 scripts/validate-ims-media-session.py
```

Fixtures are synthetic and sanitized.