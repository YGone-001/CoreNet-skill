# Result namespaces

## Base Result-Code

Base `Result-Code` is interpreted in the RFC 6733 namespace.

```text
2001, 2002  SUCCESS_REPORTED
>= 3000     FAILURE_REPORTED
1001        UNRESOLVED (multi-round challenge is not a success or failure verdict)
other       UNRESOLVED with the exact numeric code
```

Example: base `Result-Code = 5001` is `DIAMETER_AVP_UNSUPPORTED`. It is never
`DIAMETER_ERROR_USER_UNKNOWN`.

## 3GPP Experimental-Result

3GPP semantics require:

- a decoder-proven `Experimental-Result`;
- `Vendor-ID = 10415`;
- a reviewed 3GPP `Experimental-Result-Code`;
- the S6a/S6d application context.

Reviewed names:

```text
5001  DIAMETER_ERROR_USER_UNKNOWN
5420  DIAMETER_ERROR_UNKNOWN_EPS_SUBSCRIPTION
5421  DIAMETER_ERROR_RAT_NOT_ALLOWED
```

An unknown 3GPP code keeps its numeric value and gets no name. A different
Vendor-ID or a missing Vendor-ID receives neither a 3GPP name nor a base name.

## Conflicts and absence

- Both base and experimental results present: `CONFLICTING`, `UNRESOLVED`, both
  numeric values preserved.
- Experimental result present without a code: `UNRESOLVED`.
- No result AVP: `MISSING`, `UNRESOLVED`.
- A redacted or truncated result is never described as confirmed success.

## What a result does not prove

A successful Diameter result does not prove EPS Attach, UE authentication,
subscriber authorization, context installation or network access.