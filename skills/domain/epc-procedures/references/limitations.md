# Limitations

| Limitation | Consequence |
| --- | --- |
| Protected NAS envelope | Inner message identity is unavailable; the stage is not asserted as absent |
| Partial capture | A missing counterpart is reported as a limitation, never as a failure |
| No ESM decoding | Attach reject causes such as ESM failure are preserved as observed values only |
| No GTPv2-C or Diameter evidence | Session establishment and authentication backend behaviour are not assessed |
| No EPC Analysis Orchestration | No global first-abnormal boundary is selected; deviations stay procedure-local |
| Unbound NAS evidence | NAS messages without an enclosing S1AP UE context cannot form an instance |
| Ambiguous identifier pairs | Conflicting S1AP identifiers are never merged; both contexts remain visible |

## Not confirmed by this analysis

Default bearer activation, PDN connectivity success, S1-U readiness, end-to-end
service success, root cause and network-function blame, and HSS/MME/SIM behaviour are
explicitly outside what this evidence supports.
