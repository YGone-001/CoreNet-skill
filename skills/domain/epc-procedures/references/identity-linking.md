# Safe cross-interface identity linking

This capability publishes identity links with four statuses:

```text
ESTABLISHED      an exact, reviewed identity basis proves the link
SUPPORTED        the reviewed basis holds but one supporting condition is unavailable
AMBIGUOUS        several candidates satisfy the basis, so none is selected
NOT_ESTABLISHED  the basis does not hold, or the required evidence is absent
```

Every link carries `link_type`, `status`, `source_subject_reference`,
`target_subject_reference`, `link_basis`, `supporting_identifiers`,
`evidence_refs`, `association_strength` and `limitations`.

## Permitted links

### NAS-EPS to S1AP UE context — `esm_to_s1ap_ue_context`

Basis: same capture, same frame number, and an S1AP message on that frame that
carries a NAS-PDU (either a message-level NAS-PDU or a NAS layer nested inside an
E-RAB item). This reuses the accepted EPS Attach association rule. Timestamp
proximity is never used, and a frame with more than one NAS-PDU carrier stays
`AMBIGUOUS`.

### ESM to EPS Attach — `esm_to_eps_attach`

Basis: the ESM message's enclosing NAS message is bound to exactly one S1AP UE
context, and exactly one EPS Attach instance publishes that same context
(`capture`, `sctp association`, `eNB-UE-S1AP-ID`, `MME-UE-S1AP-ID`). No subscriber
identity is compared. Different Attach attempts keep different contexts and are
never merged.

### S1AP E-RAB to GTPv2-C bearer — `s1ap_erab_to_gtpv2_bearer`

Basis: exact equality of the S1-U transport layer address **and** the S1-U
GTP-TEID, with a reviewed S1-U F-TEID interface type (1), inside one capture, with
a reviewed GTPv2-C procedure family, and exactly one candidate.

This link is `SUPPORTED`, never `ESTABLISHED`, because:

- the E-RAB identity and the EPS bearer identity are different identifiers and are
  never equated, so the bearer identity condition of the join is unavailable;
- endpoint equality is control-plane provisioning evidence, not proof that a
  GTP-U tunnel forwards packets.

When several GTPv2-C messages publish the same endpoint, the link is `AMBIGUOUS`
and no transaction is selected. When none does, it is `NOT_ESTABLISHED` and is
published in `unbound_evidence` so both sides stay visible.

## Forbidden links

| Link | Status | Reason |
| --- | --- | --- |
| S11 to S5/S8 session | `NOT_ESTABLISHED` | no reviewed identity bridge exists; a shared capture, a shared EBI, a shared Cause or close timestamps do not prove a relationship |
| Attach UE to GTPv2-C session subject | `NOT_ESTABLISHED` | no reviewed common identifier; an E-RAB ID numerically equal to an EBI is not a bridge |
| E-RAB ID to EPS bearer identity | never attempted | different identifiers in different scopes |
| ESM PTI to a UE identity | never attempted | a PTI identifies a procedure transaction inside one NAS context |

## Required output shape

An unlinked relationship must remain visible on both sides. The analysis therefore
publishes, for every instance, the ESM evidence it owns, the E-RAB items it owns,
the tunnel links it attempted, and the reason a link is not established. It never
invents an identity to make a relationship look complete.
