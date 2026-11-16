# Failure and incomplete-evidence cases

## Malformed input

- Invalid JSONL syntax returns exit code 2.
- A record without `header` or `transport` returns exit code 2.
- A non-positive or non-integer `frame_number` returns exit code 2.
- A PDML document that is not valid XML returns exit code 2.

## No Diameter evidence

A capture or PDML document without Diameter messages returns exit code 3. This is
not a decoder failure and not a successful Diameter analysis.

## Incomplete messages

- A declared length greater than the observed dissection length is published as
  `MESSAGE_LENGTH_STATUS = MISMATCH` with an explicit limitation.
- A transport segment that does not contain a complete reassembled Diameter
  message is not published as a complete message.
- The Skill does not implement custom TCP or SCTP reassembly. The installed
  decoder's reassembly result is the only accepted basis.

## Incomplete correlation

- An unanswered request is `OPEN_REQUEST`, not a timeout.
- An answer without a request is `RESPONSE_ONLY`.
- Competing requests or answers are `AMBIGUOUS`; all candidates stay visible.
- A missing End-to-End Identifier prevents `STRONG` correlation but does not
  fabricate a pair.

## Unsupported scope

- Unknown commands and application-specific commands remain numeric.
- An unsupported Application-ID does not become S6a, Gx, Rx or IMS semantics.
- A vendor Experimental-Result-Code is not translated to a base result name.
- Grouped AVPs without decoder-proven children are `NOT_DECODED`, not inferred
  from list order.

## Output failures

Existing outputs require `--force`. Writing over the input artifact is refused.
A missing destination directory returns exit code 6.

## Privacy failure handling

If a sensitive AVP value cannot be classified safely, it is withheld. The
implementation never falls back to publishing raw bytes.