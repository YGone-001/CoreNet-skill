# S1AP UE-Context Correlation

## Rules

A context is formed only from evidence the protocol itself provides:

1. the capture file identity,
2. the scoped SCTP association,
3. the observed eNB-UE-S1AP-ID and MME-UE-S1AP-ID pair.

Timestamp proximity is never used. An E-RAB identifier is never treated as a UE
identity. A single numeric identifier shared across associations is never merged.

## Strength

| Strength | Meaning |
| --- | --- |
| `STRONG` | Both S1AP UE identifiers are present in the context. |
| `SUPPORTED` | Exactly one identifier is present; the association is stable. |
| `AMBIGUOUS` | An identifier pair conflicts with another observed pair in the same association. |
| `UNBOUND` | No S1AP UE identifier is present. |

## Ambiguity

Two conflict shapes are detected and reported with reasons:

- one eNB-UE-S1AP-ID observed with multiple MME-UE-S1AP-ID values in one association;
- one MME-UE-S1AP-ID observed with multiple eNB-UE-S1AP-ID values in one association.

An ambiguous context is never resolved by preference. Both contexts stay visible and
carry their ambiguity reasons.

## Pre-assignment phase

An InitialUEMessage is normally observed before the MME allocates an MME-UE-S1AP-ID.
That event forms its own `SUPPORTED` context with the eNB identifier only. It is
never merged into the later `STRONG` context, because the missing identifier is not
inferred.

## Output

```json
{
  "capture_file": "capture.pcap",
  "event_count": 10,
  "context_count": 2,
  "contexts": [
    {
      "context_key": "s1ap-context:capture.pcap:sctp-assoc-0:e24:m24",
      "enb_ue_s1ap_id": 24,
      "mme_ue_s1ap_id": 24,
      "message_count": 9,
      "first_frame": 35,
      "last_frame": 53,
      "messages": ["DownlinkNASTransport", "UplinkNASTransport", "UEContextReleaseCommand"],
      "strength": "STRONG",
      "ambiguity_reasons": []
    }
  ],
  "rules": ["..."]
}
```
