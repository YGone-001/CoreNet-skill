# Media Session Evidence

## Exchange types

`INITIAL_INVITE_SDP_OFFER`

- Attempt-level offer only; no branch answer is established.
- Its transport observation is attempt-level.

`INITIAL_INVITE_OFFER_ANSWER`

- The initial offer is attempt evidence.
- The answer is branch-scoped.
- A shared initial offer is published once and referenced by all branches.
- If a single Correlation record contains the shared offer and one or more
  branch answers, the record's multi-owner ambiguity is preserved rather than
  split.

`LATE_OFFER_ANSWER`

- Offer and ACK answer both belong to the same accepted branch.
- Exact offer and answer SDP references are preserved.
- The 2xx offer transport observation is branch-bound when the exchange is
  established.

`INITIAL_INVITE_WITHOUT_SDP`

- No SDP media transport association.
- Late-offer evaluation remains separate.

`INITIAL_INVITE_SDP_EVIDENCE_UNUSABLE`

- The upstream fail-closed decision is preserved.
- No transport association upgrades it.

Any non-established exchange stays non-established.

## Fork isolation

Every forked Dialog Branch is preserved independently. The Domain never:

- merges branches because they share an SDP offer;
- selects a preferred branch;
- assigns one branch's answer to another;
- collapses Dialog references into one media session;
- duplicates a shared transport observation into independent branch records.

The shared initial offer is attempt-level evidence; each branch references the
same observation.

## BUNDLE

A `BUNDLE_TRANSPORT_MATCHED` Correlation record remains one shared transport
observation. It retains all associated:

- SDP message references;
- media-section indices;
- MID values;
- bundle references;
- RTP UDP Stream references.

The Domain does not demultiplex a bundled transport into audio/video streams and
does not assign the stream to one specific MID. RTP header-extension MID
demultiplexing remains out of scope.

## Match direction

The Domain preserves exactly:

- `RTP_SOURCE_ENDPOINT_MATCH`
- `RTP_DESTINATION_ENDPOINT_MATCH`

It never converts them into UE uplink/downlink, access-side/core-side, or
caller-to-callee/callee-to-caller roles.

## Missing evidence

- No endpoint context on both sides is accepted as insufficient endpoint
  evidence, not as a match.
- A missing Correlation record leaves an established exchange with
  `TRANSPORT_CORRELATION_NOT_OBSERVED`.
- An unbound SDP message produces `UNBOUND` / `NOT_ESTABLISHED` with no
  fabricated attempt or branch.
- Provisional SDP remains `PROVISIONAL_SDP_UNINTERPRETED` and is never promoted
  to an early-media session.
- Unmatched RTP streams are preserved without Dialog or subscriber ownership.

## Not confirmed

The Domain does not establish:

- media delivery;
- two-way audio;
- IMS media-session success;
- temporal media association;
- RTP teardown after BYE;
- codec compatibility;
- media QoS or MOS;
- ICE connectivity or NAT mapping.