# Failure and fail-closed cases

## Input rejection

The analyzer rejects the following inputs with exit code 2 and publishes no
analysis:

- malformed JSON or a non-object JSONL record;
- an event missing a required identity, transport, AVP or result field;
- events from more than one capture;
- transaction `capture_files` that do not equal the event capture;
- duplicate event frame/occurrence identity;
- duplicate transaction references;
- a transaction reference that does not match the Diameter Core reference shape;
- a request or answer reference that does not resolve to a supplied event;
- a reference that disagrees with its event on direction, command code,
  Application-ID, Hop-by-Hop or End-to-End identifier;
- an invalid transaction status/latency invariant;
- a Cx/Dx event with no transaction representation.

No synthetic transaction reference or synthesized message is ever created.

## Message-level outcomes

- A reviewed Cx/Dx command under Application-ID 16777216 is `OBSERVED`.
- A reviewed Cx/Dx command under another Application-ID is `CONFLICTING`; no
  Cx/Dx AVP or result semantics are assigned.
- An unreviewed command code under Application-ID 16777216 is
  `KNOWN_UNSUPPORTED`; its numeric identity is preserved and it is not treated as
  malformed.
- A non-Cx/Dx application transaction is not interpreted.

## Result outcomes

- A single base result is classified by RFC 6733 value class.
- A single reviewed 3GPP experimental result uses the TS 29.229 name.
- A 3GPP experimental code outside the reviewed set remains numeric.
- A non-3GPP or missing Vendor-ID receives no 3GPP semantics.
- Simultaneous base and experimental results are `CONFLICTING` and
  `UNRESOLVED`.
- No result evidence is `UNRESOLVED`, never success.

## AVP outcomes

- A grouped AVP without decoder-proven children publishes
  `structure_proven: false`, no child array and a limitation.
- A reviewed AVP absent from a truncated published subset is
  `NOT_OBSERVED_IN_PUBLISHED_SUBSET`.
- Repeated occurrences are counted, not merged into one.
- A protected AVP never publishes a value.
- A reviewed enumeration outside its known value set publishes no reviewed value.
- AVP namespace mismatch (a base code with a vendor or a 3GPP code without
  Vendor-ID 10415) is not matched as the reviewed AVP.

## Transaction outcomes

- `OPEN_REQUEST` publishes no answer, no application result and no latency.
- `RESPONSE_ONLY` publishes no request and no latency.
- `AMBIGUOUS` publishes no selected request, retains every candidate reference
  and publishes no latency.
- An unanswered request is capture incompleteness, never a timeout.

## Empty input

When no reviewed or conflicting Cx/Dx command evidence exists, the CLI exits
with code 3 and writes no analysis. A Diameter capture with only S6a, Gx, base or
Sh/Rx traffic is not Cx/Dx evidence.

## Interface and procedure outcomes

- Cx versus Dx is never decided.
- HSS, I-CSCF and S-CSCF roles are never inferred from endpoints.
- No IMS registration, authentication, authorization, session or media verdict is
  produced from a Diameter result.