# Privacy

## In-memory only

The registration Domain reuses the accepted SIP private message records for
capture-local identity matching. The following values are never published:

- Call-ID;
- From tag and To tag;
- SIP URI, Request-URI or Contact URI;
- raw Contact values beyond safe numeric/boolean expiration metadata;
- IMSI, IMPI, IMPU or MSISDN;
- Authorization or Proxy-Authorization content;
- WWW-Authenticate or Proxy-Authenticate content;
- digest nonce, digest response or username;
- authentication vector, RES/XRES, RAND, AUTN, CK or IK;
- SIP message body or SDP;
- Diameter AVP values.

## Published references

References are derived from source-event positions, not subscriber values:

- `sip-registration:<capture>:<frame>.<occurrence>`
- `sip-event:<capture>:<frame>.<occurrence>`
- `sip-transaction:<capture>:request|response:<frame>.<occurrence>`
- `ims-timeline:<capture>:<frame>.<occurrence>:<kind>`

A reference is a capture-scoped analysis identifier. It is not a portable subscriber
identity and is not a hash of a raw identifier.

## Published facts

Numeric status codes, command codes, result codes, result names, presence counts,
frame numbers, booleans, evidence states and opaque references are publishable.
Expires, Min-Expires and Contact `expires` values are published only as reviewed
numeric facts; wildcard, non-wildcard and per-Contact expiration counts are published
as aggregate numeric or boolean metadata. Individual Contact URIs and raw Contact
values are never published. Reason phrases are published only through the accepted
SIP event contract.

## Diagnostics

CLI preflight and output failures do not print input paths, payloads or identity
values. They report only that a destination collides with an input artifact, that
output destinations are duplicated, that an output exists without `--force`, or that
an output directory is missing.

## Verification

Tests and the repository validator scan the produced JSON document, the report,
stdout, stderr and error paths for synthetic sensitive values. A failure to find a
value is recorded as a test result, not as a production privacy guarantee for
arbitrary real traffic.

## Prohibited patterns

- No unkeyed hash of IMSI, IMPI, IMPU or Call-ID.
- No persistent subscriber pseudonym.
- No raw SIP identity in a file name, error message or report.
- No weakening of the accepted SIP or Diameter privacy contracts for correlation.