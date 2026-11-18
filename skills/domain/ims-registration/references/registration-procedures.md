# Registration procedure evidence

## Normative basis

| Specification | Relevant clause | Behavior supported | Direct review |
| --- | --- | --- | --- |
| RFC 3261 | Section 10 | REGISTER binding creation, refresh and removal; Expires, Contact expires and wildcard Contact | Reviewed through the repository's accepted SIP protocol contract; direct RFC retrieval not executed in this environment |
| RFC 3261 | Section 17 | REGISTER is a non-INVITE transaction; response matching is owned by the SIP Protocol Skill | Reviewed through the accepted transaction contract |
| RFC 3261 | Section 22 | 401/407 challenges and Authorization/Proxy-Authorization presence | Reviewed through the accepted SIP event contract |
| 3GPP TS 24.229 | IMS registration, re-registration and de-registration procedures | Challenge/retry sequence, initial registration, refresh, de-registration | `NOT_EXECUTED` for direct document retrieval; modeled conservatively |
| 3GPP TS 29.228 V19.2.0 | Cx/Dx signalling flows | UAR/MAR/SAR/RTR/PPR/LIR application context | `NOT_EXECUTED` for direct document retrieval; consumed through the accepted `diameter-ims` Skill |
| 3GPP TS 29.229 V19.1.0 | Cx/Dx protocol details | Command codes, AVP and result semantics | Consumed through the accepted `diameter-ims` Skill; direct retrieval `NOT_EXECUTED` |

The model does not assume that every IMS registration follows one universal fixed
sequence. UAR, MAR and SAR are not mandatory stages of every observed registration.

## SIP transaction inventory

Only transactions whose accepted request method is `REGISTER` enter the inventory.
Each entry preserves the accepted transaction reference, request/provisional/final
event references, matching status, observed evidence status, final status codes,
frame provenance, retransmission references and lower-layer missing/conflicting
evidence.

A REGISTER request without a response remains observable. A REGISTER response without
a captured request remains an independent observation and is never converted into a
successful registration attempt.

## Registration-attempt grouping

An attempt may contain multiple REGISTER transactions, for example:

```text
REGISTER CSeq 1
    -> 401 Unauthorized
REGISTER CSeq 2 + Authorization
    -> 200 OK
```

Grouping requires private capture-local evidence:

- same capture;
- same Call-ID;
- same Request-URI;
- same initiating From URI and tag;
- a compatible CSeq progression;
- for a retry, an observed preceding 401/407/423 and, for 401/407, observed
  Authorization or Proxy-Authorization presence.

Call-ID alone, CSeq alone, chronological adjacency, addresses or ports are never
sufficient. A missing mandatory value keeps the transaction as an independent
`UNDETERMINED` observation with explicit missing evidence.

A repeated REGISTER with the same CSeq and a different Via branch is retained as a
`multi_hop_candidate` within the same candidate attempt. No proxy role or forwarding
relationship is claimed. An incompatible CSeq progression splits observations and
publishes `CSEQ_INCOMPATIBLE`.

The attempt reference is derived from the first observed request event:

`sip-registration:<capture>:<frame>.<occurrence>`

## Registration type

| Type | Rule |
| --- | --- |
| `INITIAL_REGISTRATION_CANDIDATE` | An observed REGISTER for an identity without a prior successful observed attempt |
| `RE_REGISTRATION_CANDIDATE` | A prior successful observed attempt for the same identity, followed by a challenged or authenticated REGISTER |
| `REFRESH_OBSERVED` | A prior successful observed attempt, a subsequent REGISTER with positive Expires and no observed challenge |
| `DEREGISTRATION_REQUESTED` | Explicit all-bindings removal (`Contact: *` with `Expires: 0`, or `Expires: 0` with no wildcard) or a Contact-specific `expires=0` removal |
| `UNDETERMINED` | Missing mandatory identity or response-only observation |

`INITIAL_REGISTRATION_SUPPORTED` is reserved for a future rule with independent
evidence; it is not assigned from capture position alone.

The first REGISTER in a capture is never assumed to be the subscriber's first
registration. A capture that begins with an authorized REGISTER remains
`INITIAL_REGISTRATION_CANDIDATE` and publishes
`RETRY_WITHOUT_OBSERVED_CHALLENGE`.

## Expiration and de-registration

Expiration evidence is published only when observed:

- REGISTER `Expires` numeric value;
- Contact `expires` numeric value;
- wildcard Contact presence and whether non-wildcard Contact values coexist;
- accepted `Min-Expires` numeric value from a 423 response.

RFC 3261 Section 10.2.2 requires `Contact: *` together with `Expires: 0` for an
all-bindings removal request. Wildcard presence alone is not valid removal evidence;
a nonzero `Expires`, a wildcard combined with another Contact value, or a malformed
`Expires` value is retained as observed protocol evidence but never promoted to a
valid all-bindings request.

The model distinguishes:

- `ALL_BINDINGS`: valid wildcard removal or explicit `Expires: 0`;
- `CONTACT_SCOPED`: Contact-specific `expires=0`, which does not necessarily remove
  every binding;
- `NONE`: wildcard or expiration evidence was observed but is invalid or incomplete.

Invalid requests publish `scope: NONE`, `valid_all_bindings_request: false`, the
invalidity labels, and `DEREGISTRATION_OUTCOME_UNPROVED` even when a 200 OK was
observed. Missing Expires is never treated as zero. A 200 OK to a valid de-registration
REGISTER is `DEREGISTRATION_ACCEPTED_BY_SIP`; it does not prove that every binding was removed or
that the IMS subscription is permanently disabled.

## Negative outcomes

A final 3xx/4xx/5xx/6xx response other than 401/407 is a negative SIP observation for
the associated attempt. A 401/407 challenge is not a terminal failure when the
observed sequence continues. A REGISTER without a final response is
`OPEN_IN_CAPTURE`; no timeout is inferred from capture silence.

## Multi-hop observations

Each hop can produce distinct transaction evidence. Individual transaction references,
per-hop transport metadata, Via evidence and unverified network-function roles are
preserved. Per-hop REGISTER copies are not counted as independent subscriber attempts
when they share a registration identity and CSeq, but they are not merged into one
logical procedure without forwarding evidence. The result is
`MULTI_HOP_CANDIDATE` / `FORWARDING_RELATIONSHIP_UNPROVED`.