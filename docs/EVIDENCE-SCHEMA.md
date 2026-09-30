# Evidence Model

`shared/schemas/evidence.schema.json` freezes the evidence record and its vocabulary.

| Level | Meaning |
| --- | --- |
| `OBSERVED` | Directly visible in a packet capture, log, configuration, source code, command output, or another primary artifact. |
| `DERIVED` | Deterministically calculated or correlated from observed evidence. |
| `INFERRED` | Strongly suggested by protocol or system behavior but not directly proven. |
| `HYPOTHESIS` | A plausible root-cause candidate that needs additional evidence. |
| `CONFIRMED` | A behavior or root cause proven by sufficient independent evidence, reproduction, implementation verification, or controlled validation. |

Skills must keep evidence separate from interpretation and preserve sources. Evidence-safe language is mandatory. For example, when only a UE Context Release Command/Request is observed, do not say “the gNB caused the registration failure”; say that the gNB initiated or sent the observed release, and label any cause attribution as inference or hypothesis until proven.
