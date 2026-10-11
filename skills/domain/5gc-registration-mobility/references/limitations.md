# Limitations

Every analysis from this Skill is bounded by its evidence. These
limitations are structural, not defects.

## Observation window

- The analysis sees only the supplied events. First and last timestamps
  and frames are preserved on every instance so the window stays
  explicit.
- An expected counterpart that stays unobserved is not automatically an
  absence claim. When the observation window ends at the stage trigger,
  or when the counterpart could be inside a protected NAS envelope, the
  stage records that limitation and no missing-counterpart deviation is
  published; a deviation is published only when the branch was entered,
  the counterpart stayed observable, and the window continued past the
  trigger without it.
- A capture that begins mid-procedure is marked PARTIAL_CAPTURE: earlier
  stages may exist outside the capture, and entry/conditional decisions
  made before the window are unknowable from this evidence.

## Instance resolution

- Instances come from NGAP UE-context evidence and frame-provenance NAS
  joins. Evidence that cannot be resolved stays UNBOUND / INCONCLUSIVE
  rather than being assigned.
- Timestamp proximity never merges instances. When several UEs signal
  concurrently, only shared provenance separates them; weak evidence
  produces separate low-confidence records, never merged procedures.
- Conflicting identifier bindings are preserved and reduce confidence;
  the analyzer does not adjudicate which observation is correct.

## Lower-layer boundaries

- UNSUPPORTED or UNKNOWN lower-layer messages limit interpretation; no
  semantics are invented for them.
- Protected NAS envelopes without a decodable inner message leave the
  inner procedure step unobserved; contents are never guessed.
- Message-level timing skew, capture-loss, and dissector version
  differences propagate from the lower layers unchanged.

## Causal boundary

- Procedure-local deviation is not end-to-end root cause.
- Release initiator is not root cause.
- Protocol-defined causes are statements in messages, not attributions.
- Implementation, vendor, product, or element blame is never derivable
  from this Skill's output. Cross-procedure and end-to-end diagnosis
  belongs to Analysis Orchestration.
