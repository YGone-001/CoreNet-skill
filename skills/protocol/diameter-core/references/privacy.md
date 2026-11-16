# Privacy and sensitive AVP handling

Diameter captures may contain subscriber and authentication data. Default
outputs never publish raw sensitive values.

## Redacted AVP classes

| AVP code | Name | Publication |
| --- | --- | --- |
| 1 | User-Name | presence, code, flags, length only |
| 2 | User-Password | presence, code, flags, length only |
| 3 | CHAP-Password | presence, code, flags, length only |
| 27 | Authorization-Info | presence, code, flags, length only |
| 28 | (authentication-related) | presence, code, flags, length only |
| 29 | (authentication-related) | presence, code, flags, length only |
| 79 | EAP-Payload | presence, code, flags, length only |
| 102 | EAP-Key-Name | presence, code, flags, length only |
| 443 | Subscription-Id | grouped structure is not recursed |
| 444 | Subscription-Id-Data | value withheld |
| 1408 | Requested-EUTRAN-Authentication-Info | grouped structure is not recursed |
| 1409 | Requested-UTRAN-GERAN-Authentication-Info | grouped structure is not recursed |
| 1413 | E-UTRAN-Authentication-Info | grouped structure is not recursed |
| 1414 | UTRAN-GERAN-Authentication-Info | grouped structure is not recursed |

RAND, AUTN, XRES, KASME and equivalent keying material are never published.

## Grouped sensitive AVPs

A sensitive grouped AVP is not recursed in either input path. PDML extraction and
JSONL replay both publish `grouping_status = REDACTED`, an empty child list and
an accurate `children_omitted` count. Nested Subscription-Id, authentication
information, RAND, AUTN, XRES, KASME or equivalent values are never published.

## Input bounds

Both input paths enforce the same publication budget and depth limit. A JSONL
input that exceeds the bounded structural limits is rejected before recursive
normalization; it is never partially published without an omission count.

## Session-Id

A Session-Id value can embed an IMSI or another subscription identifier. The
Skill publishes it as opaque presence and length metadata only, with an explicit
event limitation.

## Unknown and vendor-specific AVPs

An unknown or vendor-specific AVP publishes its numeric code, Vendor-ID, flags,
length and presence. It never publishes raw bytes, decoded payloads or a
guessed semantic name.

## Correlation and privacy

Protocol-local Request/Answer matching uses header identifiers and transport
identity. It does not need a subscriber identity, a raw User-Name or an
authentication vector. Sensitive values are not hashed to invent a cross-packet
identity.

## Verification

The sanitized privacy fixture and the committed expected outputs are scanned for
subscriber-like values, authentication payload fragments and `IMSI` markers.