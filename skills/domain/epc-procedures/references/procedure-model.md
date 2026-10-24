# EPS Attach Procedure Model

## Normative basis

- 3GPP TS 23.401 — EPS attach procedure context: where Attach sits relative to
  authentication, security mode control and S1 context setup.
- 3GPP TS 24.301 — EPS NAS message identities, security header type and EMM causes.
- 3GPP TS 36.413 — S1AP messages used as associated evidence.

Protocol message identity and cause names are not re-derived here: they arrive from
the accepted `s1ap` and `nas-eps` Protocol Skills, which verified them against the
TShark 4.7.1 dissector. This Domain owns procedure-stage composition only.

## Procedure instances

An instance is one Attach attempt for one UE context. A UE context is the tuple
(capture file, SCTP association, eNB-UE-S1AP-ID, MME-UE-S1AP-ID). A new attempt
starts when an `Attach request` is observed after a terminal decision (accept or
reject) on the same context. A repeated `Attach request` without an intervening
terminal decision stays in the same attempt and is reported as a repeated request.

The instance reference is a hash of the context and attempt index. It never exposes
raw identifiers through string concatenation.

## Stage semantics

Stages are observed checkpoints, not a mandatory sequence. `NOT_OBSERVED` on a
conditional stage is not a defect: an Identity exchange is not mandatory in every
valid Attach, and authentication may be skipped when a security context exists.

`OBSERVED` means at least one message of that stage was decoded in this attempt.
`INCOMPLETE` is reserved for a trigger without any counterpart while the attempt has
no terminal decision. `UNAVAILABLE_PROTECTED` marks a stage whose messages are inside
a protected envelope.

## What the Domain must never do

- Claim default bearer activation, PDN connectivity or user-plane readiness.
- Treat `Attach complete` or `InitialContextSetupResponse` as end-to-end success.
- Select a global first-abnormal boundary, rank deviations by severity, or attribute
  root cause to a network function.
- Read subscriber identity, authentication parameters or payload bytes.
