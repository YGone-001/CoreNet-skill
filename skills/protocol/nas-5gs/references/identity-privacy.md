# Identity Privacy

Subscriber and mobile equipment identities in NAS signaling are
sensitive operational data. This Skill treats them accordingly.

## Sensitivity classes

- Permanent subscriber identities: SUPI in its IMSI or network-specific
  forms. Their encrypted form, SUCI, is privacy-protected but still
  subscriber-related.
- Temporary subscriber identities: 5G-GUTI, 5G-S-TMSI.
- Equipment identities: IMEI, IMEISV.
- Opaque temporary paging-related identity material surfaced in 5GMM
  messages (for example inside paging identities) is subscriber-related
  metadata.

## Default behavior (redaction)

Default output carries identity evidence as presence and reviewed type
only:

    identity: {present: true, type_code: 1, type_name: SUCI, value: null}

Raw identity values are dropped even when present in structured input.
Capture-based extraction never emits identity values through this
package: TShark 4.7.1 exposes IMEI/IMEISV values, which are reduced to
presence, and SUCI/5G-GUTI structures are not exported as values here.

## Explicit opt-in

`extract-nas5gs.py --include-sensitive-identifiers` carries the
structured-input `identity_value` field into the detailed event. This is
intended for authorized diagnostic workflows where the analyst already
holds the capture. Risks: identity values can identify subscribers,
correlate across captures, and leak through downstream tooling. Redacted
mode satisfies the same protocol questions (which identity type was
used, whether identity was provided) without carrying raw values.

## No identity conversion

The Skill never converts or equates identity forms:

- SUCI does not reveal SUPI; concealing the subscriber is its purpose.
- 5G-GUTI and 5G-S-TMSI are temporary; they are never mapped to a
  permanent identity.
- IMEI/IMEISV identify equipment, not subscribers.
- No identity value is used to infer authorization, subscription state,
  or subscriber identity beyond the reviewed type table.

Unknown identity type codes stay UNKNOWN with their numeric value.

## Trace projection

The shared trace-event schema has subscriber fields. This Skill leaves
them unpopulated in every mode, including opt-in; identity evidence
lives only in the detailed NAS event's `identity` object, so generic
projections stay safe to share.

Session fields are populated only from directly observed 5GSM evidence
and only when unambiguous: `pdu_session_id` from the observed PDU session
identity, `dnn` from an observed DNN, and `qfi` only when exactly one QFI
is represented. SEID and TEID are never derived from NAS, and APN is
never fabricated from DNN. Session identifiers such as PDU session
identity, procedure transaction identity, QFI, and DNN are protocol and
session evidence, not subscriber identities.

## Synthetic data only

Examples, fixtures, and documentation use unmistakably synthetic values
(documentation ranges only, for example 192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24, and 2001:db8::/32). Real IMSI, SUPI, SUCI, MSISDN, GUTI,
production PDU addresses, or authentication material must never be
committed to this repository.
