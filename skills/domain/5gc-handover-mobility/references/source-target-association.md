# Source / Target Association Model

Domain-level source/target association is explicit and evidence-bounded;
the NGAP Protocol-layer correlation model is deliberately not copied across
associations.

## AMF-UE-NGAP-ID scope

AMF-UE-NGAP-ID is an AMF-allocated NGAP UE-associated identifier. It is
not a SUPI, SUCI, IMSI, permanent UE identity, cross-AMF identity, or
cross-capture identity. Pairing is scoped to: capture file + AMF-UE-NGAP-ID
(at minimum), with observed AMF endpoint compatibility used when both
sides expose the AMF address. Endpoint addresses are context evidence and
never map to network-function roles.

## Association rule

A source half and a target half are compatible when all of the following
hold:

1. same capture file;
2. same scoped AMF-UE-NGAP-ID context (halves without an AMF-UE-NGAP-ID
   are not pairable);
3. compatible observed AMF endpoint context (missing endpoints never
   reject);
4. reviewed role compatibility (source-role messages from the Handover
   Preparation/Cancel procedures; target-role messages from Handover
   Resource Allocation/Notification);
5. temporal sanity: the target half starts after the source initiation
   and within the source's active window, which ends when the next source
   initiation for the same scoped context begins (one active N2 handover
   per UE context in the reviewed basis).

Timestamps may reject impossible candidates and bound windows — after
identity and context compatibility. Timestamp proximity alone never
associates source, target, Path Switch, PFCP, GTP-U, or SBI evidence.

## Strengths

- STRONG — unique pairing with an observed source initiation
  (HandoverRequired) and target allocation initiation (HandoverRequest).
- SUPPORTED — unique pairing where one side lacks its initiation evidence
  (for example a target half anchored on HandoverNotify).
- AMBIGUOUS — multiple candidates are simultaneously compatible; all
  candidates are preserved and no nearest-in-time selection is made
  (CORRELATION_AMBIGUITY deviation).
- UNBOUND — no compatible counterpart; the attempt stays single-side.

## Reuse and multi-UE safety

The same numeric AMF-UE-NGAP-ID in distinct context lifetimes never merges
automatically: a new initiation for the same scoped context bounds the
previous attempt's window, and any genuinely competing candidate keeps the
association AMBIGUOUS. Equal RAN-UE-NGAP-IDs across SCTP associations
never establish identity (source and target RAN IDs may legitimately
differ or coincide). Two interleaved UEs always form separate attempts.
