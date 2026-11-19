# Failure and edge cases

## SIP input

| Case | Result |
| --- | --- |
| Malformed SIP JSONL / PDML | Exit code 2; no output published |
| No plaintext SIP messages | Exit code 3 |
| TShark unavailable | Exit code 4 |
| TShark dissection failure | Exit code 5 |
| Output exists without `--force` | Exit code 6 |
| Output directory absent | Exit code 6 |
| Output path equals input | Exit code 6 |

## Registration attempt boundaries

| Case | Result |
| --- | --- |
| Missing Call-ID | Independent `UNDETERMINED` observation with `CALL_ID_NOT_OBSERVED` |
| Missing From tag | Independent observation with `FROM_TAG_NOT_OBSERVED` |
| Missing CSeq | Independent observation; CSeq progression `UNKNOWN` |
| Response-only REGISTER | `UNDETERMINED` / `INCOMPLETE_EVIDENCE` with `REQUEST_NOT_OBSERVED` |
| Incompatible CSeq sequence | Split observations with `CSEQ_INCOMPATIBLE` |
| Same identity, same CSeq, different Via branch | `multi_hop_candidate`; forwarding unproved |
| Different captures, identical SIP identifiers | Separate attempts; timeline `SOURCE_LOCAL_ONLY` |
| Duplicate retransmission | One accepted transaction; no duplicate attempt |

## Authentication edges

| Case | Result |
| --- | --- |
| 401/407 without retry | `CHALLENGE_WITHOUT_OBSERVED_RETRY`; SIP outcome `INCOMPLETE_EVIDENCE` |
| Authorization without challenge | `RETRY_WITHOUT_OBSERVED_CHALLENGE` |
| 401 followed by 403 | Negative SIP outcome for the attempt |
| Retry without final response | `OPEN_IN_CAPTURE` |
| Any challenge/retry | `authentication_cryptographically_verified: false` |

## Lifecycle edges

| Case | Result |
| --- | --- |
| `Contact: *` with `Expires: 0` | `DEREGISTRATION_REQUESTED`; scope `ALL_BINDINGS` |
| Contact `expires=0` | `DEREGISTRATION_REQUESTED`; scope `CONTACT_SCOPED` |
| Default `Expires: 0` with a supplied Contact | `DEREGISTRATION_REQUESTED`; scope `CONTACT_SCOPED` |
| `Expires: 0` without a Contact | Observation retained; scope `NONE`; `EXPIRES_WITHOUT_CONTACT` |
| Contact `expires=3600` with default `Expires: 0` | Contact parameter wins; no removal scope |
| Mixed Contacts (`0` and positive) | `CONTACT_SCOPED`; no all-bindings claim |
| Missing Expires | `EXPIRATION_NOT_OBSERVED`; not treated as zero |
| De-registration without response | `DEREGISTRATION_OUTCOME_UNPROVED` |
| De-registration with its own 200 | `DEREGISTRATION_ACCEPTED_BY_SIP` |
| Unrelated transaction 200 | Not attributed; removal outcome remains unproved |
| Challenge response observed after retry | No Challenge→Retry association |
| 423 with Min-Expires and retry | `min_expires_evidence` plus one supported attempt |
| No final response | `OPEN_IN_CAPTURE`; no timeout inference |

## Diameter input

| Case | Result |
| --- | --- |
| No Diameter input | `NOT_SUPPLIED`; SIP-only analysis succeeds |
| Invalid supplied artifact | Exit code 2; not treated as absence |
| Artifact without Cx/Dx commands | `NOT_OBSERVED_IN_SUPPLIED_ARTIFACT` |
| Open request / response-only / ambiguous | Retained with numeric status |
| Unassigned experimental code | Retained; application result unresolved |
| Wrong Vendor-ID | Retained; application result unresolved |

## Cross-protocol edges

| Case | Result |
| --- | --- |
| Same filename | Not proof; `NOT_ESTABLISHED` |
| Nearby timestamps or frames | Not proof; `NOT_ESTABLISHED` |
| SIP 200 near SAA success | Not proof; `NOT_ESTABLISHED` |
| SIP 401 near MAA success | Not proof; `NOT_ESTABLISHED` |
| Different captures | `NOT_ESTABLISHED` with `COMMON_CAPTURE_NOT_VERIFIED` |
| Any positive association | Rejected by semantic validation |

## Unsupported conclusions

- registration persistence after 200 OK;
- cryptographic authentication success;
- IMS session or media success;
- RTP delivery or two-way audio;
- P-CSCF/I-CSCF/S-CSCF role;
- timeouts from capture silence;
- root cause or IMS failure boundary.