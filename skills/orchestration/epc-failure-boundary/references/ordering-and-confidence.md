# Ordering and confidence

## Ordering

Candidates inside one diagnostic group are ordered by exact frame number. Nothing
else orders them:

| Never used | Why |
| --- | --- |
| Severity ranking | Would turn selection into a judgement about importance. |
| Cause-code magnitude | A numeric value is not a chronology. |
| Message label | "Reject" and "Failure" carry no order. |
| Stage-array index | A Domain list order is not a capture order. |
| Explanation text order | Prose is presentation, not evidence. |
| Transaction list order | The correlation list is not sorted by capture time. |
| Timestamp proximity | Timestamps never link subjects and never order candidates. |

The selected candidate is the eligible candidate with the smallest frame number
inside one subject.

## Ties

Two eligible candidates at the same frame are ambiguous when their provenance
differs — different deviation type, transaction, bearer item or message. Exact
duplicates, meaning identical type, frame, transaction, bearer item and message,
are deduplicated with the deduplication basis recorded as a limitation.

`AMBIGUOUS_FIRST_BOUNDARY` publishes no selected boundary. The candidates remain
visible so a reader can see the competing evidence.

## Ambiguity ahead of a candidate

An `AMBIGUOUS_TRANSACTION_OBSERVED` deviation means the response could not be
selected. If that ambiguity sits at or before the earliest eligible candidate,
the evidence cannot establish that candidate as first: the result is
`INSUFFICIENT_COMPARABLE_EVIDENCE`.

## Truncated candidate universe

The session-control Domain bounds its deviation lists and publishes the omitted
count. When the omitted count is non-zero, the visible list is not the complete
candidate universe, so no boundary is selected. The status is
`INSUFFICIENT_COMPARABLE_EVIDENCE` and the limitation names the omission.

## Confidence

| Level | Conditions |
| --- | --- |
| `HIGH` | Complete candidate list, `OBSERVED` evidence level, exact frame, subject link `STRONG` or `SUPPORTED`. |
| `MEDIUM` | Complete candidate list and `OBSERVED` evidence, but the subject link is `UNBOUND` or `AMBIGUOUS`. |
| `LOW` | Complete list but derived evidence, or a weak anchor. |

Confidence describes the selection: how complete the evidence is, how strong the
subject link is and how well the anchor is established. It never describes:

- the probability that a vendor, an MME, an SGW-C or a PGW-C is responsible;
- root-cause certainty;
- subscriber service quality.

A clean explicit rejection with an exact frame can support `HIGH` selection
confidence while saying nothing about why the rejection happened.

## Downstream observations

Every candidate and procedure stage observed after the selected frame is listed
with `relation = OBSERVED_AFTER_BOUNDARY`. The relation states ordering only.
Orchestration never publishes `CAUSED_BY_BOUNDARY`, `ROOT_CAUSE_CHAIN` or an
equivalent claim, and the text report repeats that ordering is not causation.
