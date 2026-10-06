# Confidence Model

Boundary confidence expresses confidence in the boundary selection and its
ordering. It is **selection confidence, never causal confidence**: a `HIGH`
boundary confidence makes no statement about why the abnormality happened.

| Confidence | Criteria |
| --- | --- |
| `HIGH` | Directly observed deviation with exact frame provenance. |
| `MEDIUM` | Derived missing-evidence boundary with a sufficient, unblocked source observation window, or ordering established through windows rather than exact frames. |
| `LOW` | The selection remains valid but rests on weaker ordering bases (for example stage order only) or meaningful evidence limitations remain. |

If the ordering itself is unsafe, no confidence is assigned: the group reports
`AMBIGUOUS_FIRST_BOUNDARY` or `INSUFFICIENT_COMPARABLE_EVIDENCE` instead of a
forced low-confidence answer. Subject-link strength (`STRONG`/`SUPPORTED`/
`AMBIGUOUS`/`UNBOUND`) is a separate concept from boundary confidence and the
two are never conflated.

## Mobility Confidence (v0.2.0)

For Mobility boundaries the same ladder applies. `HIGH` requires a safely
grouped diagnostic subject plus exact machine-readable observed EVENT
provenance and safe ordering. A Domain-supported source/target context bridge
justifies SUPPORTED subject linkage without reducing a directly observed
boundary to LOW: the bridge affects grouping, not selection confidence.
Derived missing-evidence boundaries stay MEDIUM, and window-based ordering
keeps the boundary at MEDIUM. Boundary confidence is never causal confidence.
