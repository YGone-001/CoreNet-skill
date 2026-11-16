# Privacy

The Skill consumes already-redacted Diameter Core evidence and never weakens it.

Never published:

- IMSI, SUPI, MSISDN or any subscriber identity.
- User-Name value.
- Authentication vectors.
- RAND, AUTN, XRES, KASME or resynchronization material.
- Authentication-information group payloads or child vector contents.
- Subscription-Data contents.
- Session-Id value.

Published instead:

- AVP code and reviewed name.
- Vendor-ID.
- presence, structural status and redaction status.
- `value_kind` copied from Core.
- `children_omitted` copied from Core.
- explicit `NOT_OBSERVED_IN_PUBLISHED_SUBSET` when Core truncated the AVP
  publication.

## Grouped authentication information

A redacted parent proves presence only. The Skill does not reconstruct how many
vectors or which child AVPs were present. It never hashes a sensitive value into a
pseudo-identity.

## Verification

Both the synthetic fixture and the real capture output are scanned for
subscriber-like values, authentication payload fragments and `IMSI` markers in
the analysis JSON and timeline.