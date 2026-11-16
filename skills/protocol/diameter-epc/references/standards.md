# Standards and verification boundary

## Normative references

- 3GPP TS 29.272, Mobility Management Entity (MME) and Serving GPRS Support Node
  (SGSN) related interfaces based on Diameter protocol.
  - Identified release document: ETSI TS 129 272 V17.09.00 (2024-05).
  - ETSI path: `/deliver/etsi_ts/129200_129299/129272/17.09.00_60/ts_129272v170900p.pdf`.
  - ETSI index: `https://www.etsi.org/deliver/etsi_ts/129200_129299/129272/`.
- 3GPP TS 29.230, Diameter applications — 3GPP specific codes and identifiers.
- RFC 6733, Diameter Base Protocol.
- IANA Diameter Command Code, AVP Code, Application-ID and Result-Code registries.
- Wireshark/TShark 4.2.2 Diameter and 3GPP Diameter dissector definitions.

## What was verified

The ETSI directory index and the exact V17.09.00 document file were observed
concretely. The PDF content was not downloaded or clause-parsed in this
environment.

AVP Code/Vendor-ID pairs and result-code names used by the producer were checked
against the installed TShark 4.2.2 decoder tables and the real capture:

```text
diameter.3gpp.ulr_flags
diameter.3gpp.ula_flags
diameter.3gpp.air_flags
diameter.Experimental-Result-Code 5001  DIAMETER_ERROR_USER_UNKNOWN
diameter.Experimental-Result-Code 5420  DIAMETER_ERROR_UNKNOWN_EPS_SUBSCRIPTION
diameter.Experimental-Result-Code 5421  DIAMETER_ERROR_RAT_NOT_ALLOWED
diameter.Result-Code 5001              DIAMETER_AVP_UNSUPPORTED
```

The real capture independently shows AVP codes 1407, 1408, 1413, 1400, 1405,
1032, 628 and 268 in the expected S6a/S6d command context.

## Honest limitation

Clause text of TS 29.272 V17.09.00 was not independently inspected. The
implementation is limited to the command codes, Application-ID, result values and
presence-only AVP checks that are directly supported by the decoder tables, the
real capture and the task contract. No additional semantic name is invented for
an unverified code.

Classification: document identity VERIFIED; clause-level semantics
NOT_INDEPENDENTLY_VERIFIED.