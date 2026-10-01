# NGAP Failure Cases

Protocol-local abnormal or inconclusive patterns this Skill can report.
Each pattern names what is OBSERVED, what is DERIVED, and the hard boundary
against causal overreach.

## Abnormal protocol-local patterns

- Unknown procedure code — `ngap.procedureCode` outside the reviewed
  38.413 table. Reported as UNKNOWN; no message semantics are attached.
- Unsupported procedure — code inside the reviewed table but outside the
  bounded 0.1.0 subset (handover, NG setup, PDU session resource families,
  and similar). Reported as UNSUPPORTED with the reviewed procedure name
  and no message mapping.
- Malformed extracted metadata — required fields absent or not integers
  (frame number, timestamp, procedure code, UE NGAP IDs). The extractor
  fails loudly per record; it never guesses.
- Unsuccessful outcome where supported — InitialContextSetupFailure
  observed. The failure is OBSERVED with its Cause; the end-to-end reason
  is not established by this Skill.
- Cause stated in a failure or release message — the category/value pair
  is preserved (for example radioNetwork value 3, reviewed as
  release-due-to-ngran-generated-reason). This is protocol evidence, not a
  confirmed end-to-end root cause.
- Release initiation from the NG-RAN side — UEContextReleaseRequest
  observed with sender_role derived as ng-ran. INFERRED at most: the
  observed release path was initiated from the NG-RAN signaling side. It
  is NOT confirmed that the NG-RAN caused any user-visible failure; RRC,
  NAS, core, or transport evidence may be required.
- Conflicting UE-ID binding — a frame observes a RAN/AMF ID pair that
  contradicts an earlier derived binding in the same association. The
  conflict is reported with the first binding retained; the Skill does not
  adjudicate which observation is correct.
- Duplicate or ambiguous identity — the same UE NGAP ID pair reappearing
  with contradictory metadata, or a numeric ID collision across
  associations. Association scoping keeps contexts separate; the report
  shows both contexts instead of merging them.
- Expected outcome missing from the capture window — for example, a
  UEContextReleaseRequest with no UEContextReleaseCommand visible. This is
  reported as an unclosed protocol-local outcome under the observed
  capture boundary.

## Capture-boundary uncertainty

"Outcome not observed" must never be reported as "the network did not send
the outcome." Absence from one capture is not absence from the network.
Typical limits that preserve uncertainty:

- capture point (N2 observed at one side only),
- capture filters and truncation,
- SCTP reassembly or segmentation effects,
- timing skew and capture loss,
- encrypted or tunneled segments leaving the observed segment.

Reports built from this Skill's output must keep the capture window
explicit and phrase missing outcomes as unobserved-in-capture.

## Explicitly out of scope for causal claims

The Skill does not confirm: registration success or failure (NAS-5GS and
the future 5GC domain Skills own that), radio-layer diagnosis (RRC timers,
RLC/MAC/PHY measurements), AMF or gNB implementation defects (no product
or source mapping belongs here), or any end-to-end root cause. Its
evidence ceiling for cause attribution is INFERRED, and only for
protocol-local paths such as release initiation direction.
