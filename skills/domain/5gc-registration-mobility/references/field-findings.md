# Field-Level Findings

The project goal reaches below the procedure stage: the analysis must
identify the signaling field that supports each procedure-local
deviation. Field findings use only fields already supplied by the lower
Protocol Skills; no new decoding happens in this package.

## Finding contract

Each field finding preserves: protocol, message_type, field_name,
observed_value, normalized_value (where the lower layer already provides
one), frame_number, capture_file, evidence_level, interpretation, and
limitations. Interpretation stays procedure-local.

## Supported findings

- NAS 5GMM Cause code and reviewed name on Registration reject.
- NAS 5GMM Cause on Authentication failure.
- NAS 5GMM Cause on Security mode reject.
- NAS 5GMM Cause on Service reject.
- NGAP Cause category and value on InitialContextSetupFailure.
- NGAP Cause category and value on UE Context Release messages.
- 5GS registration type on Registration request.
- Identity type on Identity response.
- Selected NAS ciphering and integrity protection algorithms on
  Security mode command.
- Lower-layer UNKNOWN or UNSUPPORTED support status.
- NGAP unsuccessfulOutcome pdu_type.
- Correlation binding conflicts (DERIVED; confidence reduced).
- Security-protected NAS envelope with unavailable inner message.

## Example boundary

Allowed: "Registration Reject carries 5GMM Cause 22 (Congestion)."

Not allowed: "AMF overload caused the problem." A cause statement is
what the message said; attribution requires evidence this Skill does
not hold.

## No new decoding

The analyzer reads only the fields present in lower-layer event records.
If a needed field is absent from the input, the analysis states the gap
in limitations instead of extracting or interpreting anything new.
