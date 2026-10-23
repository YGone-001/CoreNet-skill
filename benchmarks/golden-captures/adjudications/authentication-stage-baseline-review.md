# Authentication-Negative Procedure-Stage Independent Baseline Review

Record type: independent, review-only evidence adjudication. Documentation only.

Subject case: `public-5gc-auth-negative`.

Nothing is changed by this record. It does not amend `human-baseline.json`, `case.json`, any
`differential.json`, any `skill-result-summary.json`, `benchmark-summary.json`, any existing
adjudication JSON, any Skill runtime, any comparator, or any benchmark metric. It records what the
packets and the cited standards support, and it explicitly does not assert that its conclusion has
already been applied to the frozen benchmark.

## 1. Question and Scope

The committed differential for this case reports `PROCEDURE_MATCH_STAGE_DIFFERENCE` with layer
attribution `DOMAIN`. Both sides anchor the abnormal boundary at frame 11 of the pinned capture,
agree on protocol `NAS-5GS`, agree on abnormal-event identity `Authentication failure`, and agree on
procedure family `5gc-registration-mobility`. They disagree on one dimension only:

| Dimension | Frozen human baseline | Automated Skill |
| --- | --- | --- |
| `procedure_stage` | `security` | `authentication` |

This review answers one question: which of the two stage labels is independently justified by the
packet evidence, the applicable 3GPP procedure definitions, and the explicit CoreNet Skill stage
model. It deliberately separates five concepts that are not interchangeable:

- general 5G system security architecture;
- the NAS primary authentication procedure;
- the NAS security mode control procedure;
- the Registration Domain's bounded stage vocabulary;
- the independent baseline's intended meaning of `security`.

## 2. Subject Provenance

| Item | Value |
| --- | --- |
| Repository | CoreNet Skill |
| Branch | `main` |
| Reviewed source commit | `ccc7edd6fc99e0d1f152ff9a016ae243afbbc66a` |
| Working tree at review start | clean |
| Remote `refs/heads/main` | identical to the reviewed source commit |
| External corpus | `abdelrahman-fawaz18/5g-sa-core-protocol-lab` |
| Pinned external commit | `82934c2cc231540fa425e48177d4bed33210bfc1` |
| Capture path in corpus | `captures/fault-injection/authentication-key-mismatch/fault.pcap` |
| Capture size | 2300 bytes |
| Capture SHA-256 (recomputed) | `70cc13c537a745625fc59d974653f5b819874a8f1a74b14db416dc97a91801c7` |
| Frozen case-record digest | identical to the recomputed value |
| Frame count | 16, confirmed by the dissector |
| Dissector | TShark (Wireshark) 4.7.1 (v4.7.1-0-g667ab240e6de) |
| Decoder configuration | isolated, empty `WIRESHARK_CONFIG_DIR`; no user preferences existed, so decoder defaults applied |

The capture digest was recomputed from the pinned corpus commit rather than copied from the frozen
record, and it matches. The frame count matches. The corpus scenario directory name was never read
as packet truth; every claim below rests on dissector fields.

All extraction artifacts were kept outside the repository. No capture bytes, no protocol event
dumps, no subscriber identifier, no authentication parameter value, and no workstation path appear
in this record.

## 3. Method

Three evidence paths were used, and they are reported separately because they carry different
weight:

1. Direct dissector inspection of the pinned capture with structured field extraction, plus full
   decode trees for the frames that carry the disputed boundary.
2. Normative review of the cited 3GPP specifications, retrieved as the ETSI-published editions of
   the corresponding 3GPP releases, with clause identifiers taken from those documents rather than
   from memory.
3. Independent re-execution of the accepted Registration Domain analyzer, fed with event records
   derived only from the field extraction in path 1, plus a read-level audit of the comparator and
   the Orchestration stage mapping.

Path 3 is a partial re-execution: the lower-layer Protocol Skills were not re-run, so the event
records were constructed by hand from dissector output instead of being produced by the accepted
extraction pipeline. That difference does not affect the stage question, which depends on decoded
message identity and procedure context, both of which were read directly from the capture. The
limitation is stated again in section 12.

## 4. Packet Evidence Matrix

Complete structured inventory of all 16 frames. "Plain" means `nas-5gs.security_header_type` is 0.

| Frame | SCTP chunk | NGAP procedure | NGAP PDU type | NAS identity | Field-level note |
| --- | --- | --- | --- | --- | --- |
| 1 | INIT | — | — | — | SCTP association setup, loopback endpoints |
| 2 | INIT ACK | — | — | — | association setup |
| 3 | COOKIE ECHO | — | — | — | association setup |
| 4 | COOKIE ACK | — | — | — | association setup |
| 5 | DATA | `id-NGSetup` (21) | initiatingMessage | — | node-level setup, no UE context |
| 6 | SACK | — | — | — | — |
| 7 | DATA | `id-NGSetup` (21) | successfulOutcome | — | node-level setup, no UE context |
| 8 | SACK | — | — | — | — |
| 9 | DATA | `id-InitialUEMessage` (15) | initiatingMessage | Registration request (0x41), plain | RAN-UE-NGAP-ID 1; no AMF-UE-NGAP-ID yet |
| 10 | DATA | `id-DownlinkNASTransport` (4) | initiatingMessage | Authentication request (0x56), plain | RAN-UE-NGAP-ID 1, AMF-UE-NGAP-ID 2; ngKSI 0; challenge parameters present (presence only, values not reproduced) |
| 11 | DATA | `id-UplinkNASTransport` (46) | initiatingMessage | Authentication failure (0x59), plain | RAN-UE-NGAP-ID 1, AMF-UE-NGAP-ID 2; 5GMM cause 20 |
| 12 | DATA | `id-DownlinkNASTransport` (4) | initiatingMessage | Authentication reject (0x58), plain | RAN-UE-NGAP-ID 1, AMF-UE-NGAP-ID 2 |
| 13 | DATA | `id-UEContextRelease` (41) | initiatingMessage | — | `UEContextReleaseCommand`; Cause `nas` (2) / `normal-release` (0); UE-NGAP-ID pair 2 / 1 |
| 14 | SACK | — | — | — | — |
| 15 | DATA | `id-UEContextRelease` (41) | successfulOutcome | — | `UEContextReleaseComplete` |
| 16 | SACK | — | — | — | — |

Exhaustive negative results over the whole capture:

- Exactly four NAS messages exist: Registration request (0x41), Authentication request (0x56),
  Authentication failure (0x59), Authentication reject (0x58). Every one is a plain NAS message.
- No NAS security-protected envelope exists. No frame carries a message authentication code or a
  ciphered payload, so nothing in this capture is hidden behind NAS security.
- No Security mode command (0x5D), Security mode complete (0x5E), or Security mode reject (0x5F)
  exists.
- No NGAP InitialContextSetupRequest or InitialContextSetupResponse exists; the NGAP procedure
  inventory is exactly NGSetup, InitialUEMessage, DownlinkNASTransport, UplinkNASTransport, and
  UEContextRelease.
- No `ngap.pDUSessionID` value exists anywhere in the capture.

### 4.1 Frame 11 deep verification

| Property | Verified value | Source field |
| --- | --- | --- |
| Protocol identity | NAS-5GS carried in NGAP `UplinkNASTransport` | `ngap.procedureCode` 46, `nas-5gs.epd` 126 |
| 5GMM message identity | Authentication failure (0x59) | `nas-5gs.mm.message_type` |
| 5GMM cause | 20 | `nas-5gs.mm.5gmm_cause` |
| Cause name | MAC failure | dissector cause table |
| Security header type | 0, plain NAS message | `nas-5gs.security_header_type` |
| Protected payload | none; no MAC field, no ciphered region | decode tree |
| Direction | UE to AMF (uplink) | `ip.src` is the RAN-side endpoint |
| Correlation with the challenge | same UE-NGAP-ID pair as frame 10 | `ngap.RAN_UE_NGAP_ID` 1, `ngap.AMF_UE_NGAP_ID` 2 |
| Correlation with the reject | same UE-NGAP-ID pair as frame 12 | `ngap.RAN_UE_NGAP_ID` 1, `ngap.AMF_UE_NGAP_ID` 2 |

Cause 20 is therefore genuinely present, not inferred. The message is fully visible: the boundary is
not a protected-envelope limitation.

### 4.2 Timestamp provenance observation

The frozen `case.json` records `first_timestamp` and `last_timestamp` that do not correspond to the
pinned capture's frame epochs: the frozen window spans about 34 milliseconds, while the capture's
frame epochs span about 65 seconds, and the offset between the frozen values and the capture is not
constant across frames. The Skill-side boundary timestamp in the committed summary does match the
frame-11 capture epoch, while the frozen baseline's boundary timestamp does not. Frame numbers, frame
count, and capture digest all agree, so this does not disturb any frame-anchored conclusion in this
record; it is recorded because it limits any timestamp-derived reasoning about the baseline's
authoring basis, and because it is relevant to the provenance question in section 8.

## 5. Normative Review

All clause identifiers below were read in the retrieved documents.

| Specification | Edition used | Clauses consulted | What they establish |
| --- | --- | --- | --- |
| 3GPP TS 24.501 (ETSI TS 124 501 V19.8.0) | version 19.8.0, Release 19 | 5.4.1 and 5.4.1.3.2, 5.4.1.3.5, 5.4.1.3.6, 5.4.1.3.7 c), 8.2.4.1, 8.2.5.1, 9.11.3.2 with table 9.11.3.2.1, annex A.3 | the primary authentication and key agreement procedure, its failure and reject outcomes, and the encoding and meaning of 5GMM cause 20 |
| 3GPP TS 24.501 (same edition) | version 19.8.0, Release 19 | 5.4.2, 5.4.2.1, 5.4.2.2, 8.2.25 | the NAS security mode control procedure is a distinct procedure, initiated by SECURITY MODE COMMAND, whose stated purpose is to take a 5G NAS security context into use |
| 3GPP TS 33.501 (ETSI TS 133 501 V19.4.0) | version 19.4.0, Release 19 | 6.1.3, 6.1.3.3.1, 6.7, 6.7.2 | authentication procedures and the NAS security mode command procedure are separate; a failed AUTN verification yields an Authentication Failure carrying a cause value |
| 3GPP TS 38.413 (ETSI TS 138 413 V19.3.0) | version 19.3.0, Release 19 | 8.3.3.1, 8.3.3.2, `CauseNas` definition | the AMF initiates UE context release with UE CONTEXT RELEASE COMMAND; `CauseNas` enumerates `normal-release`, `authentication-failure`, `deregister`, `unspecified` |
| 3GPP TS 23.502 (ETSI TS 123 502 V19.9.0) | version 19.9.0, Release 19 | 4.2.2.2.2 general registration call flow | the registration flow carries one step labelled `Authentication/Security`, which groups primary authentication and NAS security establishment |

Three normative facts follow directly, and they are the load-bearing ones for this adjudication.

1. **Authentication failure with cause 20 is a message of the authentication procedure.** TS 24.501
   clause 5.4.1.3.6 states that if the UE finds the MAC code invalid it "shall send an AUTHENTICATION
   FAILURE message to the network, with the 5GMM cause #20 'MAC failure'", and clause 5.4.1.3.7 c)
   names that case "Authentication failure (5GMM cause #20 'MAC failure')" and has the UE start
   timer T3520. Clause 8.2.4.1 defines AUTHENTICATION FAILURE as sent by the UE to the AMF, with the
   5GMM cause mandatory, and annex A.3 defines cause 20 as "MAC failure". TS 33.501 clause 6.1.3.3.1
   states the same behaviour from the security-architecture side.
2. **The reject that follows belongs to the same procedure.** TS 24.501 clause 5.4.1.3.5 covers
   "Authentication not accepted by the network" and has the network send AUTHENTICATION REJECT after
   an unsuccessful 5G AKA procedure when it does not first run identification; clause 5.4.1.3.7 c)
   points at exactly that clause as the termination path. Frame 12 is therefore the closing message
   of the same authentication procedure, not the opening of a different one.
3. **Security mode control is a different procedure with a different trigger.** TS 24.501 clause
   5.4.2.2 states the AMF initiates it "by sending a SECURITY MODE COMMAND message to the UE", and
   clause 5.4.2.1 states its purpose is to take a 5G NAS security context into use. TS 33.501 clause
   6.7.2 describes the same procedure as establishing the NAS security context between UE and AMF
   through SECURITY MODE COMMAND and SECURITY MODE COMPLETE. Neither document treats a failed
   authentication as part of that procedure.

### 5.1 The one place where a broad reading of "security" has support

TS 23.502 clause 4.2.2.2.2 presents the general registration call flow with a single step labelled
`Authentication/Security`. That label groups primary authentication together with NAS security
establishment. It is the only authoritative text found in this review that places authentication
under a broader security heading at the procedure-flow level.

This is a real but bounded support: it justifies `security` as a coarse description of the enclosing
registration step. It does not create a stage identifier, it does not make authentication and
security mode control the same procedure, and it says nothing about the CoreNet stage vocabulary.
The relationship it describes is containment, and containment is asymmetric: the enclosing step
contains the authentication procedure, so the enclosing step's name cannot be substituted for the
contained procedure's name without losing information.

## 6. Authentication Versus Security Mode Analysis

| Question | Authentication procedure | NAS security mode control procedure |
| --- | --- | --- |
| Governing clause | TS 24.501 5.4.1; TS 33.501 6.1.3 | TS 24.501 5.4.2; TS 33.501 6.7.2 |
| Initiating message | Authentication request (0x56) | Security mode command (0x5D) |
| Defined outcomes | Authentication response, reject, failure, result | Security mode complete, Security mode reject |
| Observed in this capture | request at frame 10, failure at frame 11, reject at frame 12 | nothing |
| Purpose | authenticate the network and the UE, derive anchor keys | take a NAS security context into use and start NAS signalling security |

The capture contains a complete, self-contained authentication exchange that terminates in failure
and rejection, followed immediately by N2 UE context release. It contains no security mode exchange
of any kind.

## 7. Current Registration Domain Model Audit

### 7.1 Authoritative stage vocabulary

`skills/domain/5gc-registration-mobility/rules/registration-model.json` declares exactly ten stage
identifiers:

`registration-initiation`, `identity`, `authentication`, `security-mode`, `registration-decision`,
`registration-completion`, `n2-context-establishment`, `context-release`, `paging`, `service-access`.

There is no stage identifier named `security`. The nearest identifier is `security-mode`, which is
triggered only by an observed Security mode command.

### 7.2 Activation and evidence conditions

Each stage declares a trigger set and, where the reviewed procedure defines them, expected outcomes.
The authentication stage is conditional, is triggered by Authentication request, and lists
Authentication response, Authentication reject, Authentication failure, and Authentication result as
expected outcomes. The security-mode stage is conditional, is triggered by Security mode command, and
lists Security mode complete and Security mode reject as expected outcomes. Conditional stages record
their absence as a limitation rather than as a deviation, so the missing security-mode exchange is
not itself treated as a fault.

### 7.3 How event-derived deviations receive a stage identity

The Domain resolves a stage identity for an observed event through
`_unique_stage_id_for_event`, which requires all of the following before returning a value: the event
carries a protocol and a decoded message identity; exactly one stage in the rule table names that
protocol and message identity in its trigger or its expected outcomes; and that stage is present in
the evaluated instance's activated stage records. Otherwise it returns nothing.

This function was exercised directly against the committed rule table with the stage set that this
capture activates. Results:

| Observed NAS message | Resolved stage |
| --- | --- |
| Authentication request | `authentication` |
| Authentication failure | `authentication` |
| Authentication reject | `authentication` |
| Security mode command | none (that stage is not activated in this capture) |
| Security mode complete | none |
| Registration request | `registration-initiation` |

### 7.4 Independent re-execution

The analyzer was run on event records built only from the field extraction in section 4. It formed a
single registration instance and emitted exactly three stage records:

| Stage record | Confidence | Evidence basis | Observed frames |
| --- | --- | --- | --- |
| `registration-initiation` | MEDIUM | OBSERVED | 9, with a recorded limitation that no Registration accept or reject is observable |
| `authentication` | HIGH | OBSERVED | 10, 11, 12 |
| `context-release` | HIGH | OBSERVED | 13, 15 |

It emitted exactly two deviations, both carrying the stage identity `authentication`: an
unsuccessful-outcome deviation anchored at frame 11 and a protocol-reject deviation anchored at frame
12. No security-mode stage record was created, because no trigger for it was observed.

This reproduces the committed summary's boundary frame, boundary message, procedure family, selected
source domain, deviation count, and `selected_procedure_stage = authentication`. The reproduction is
independent of the human baseline and independent of the committed summary; the summary was compared
against it only after it was produced.

### 7.5 Does the Domain infer workflow completion?

No. Stage activation requires an observed trigger. The Domain did not create a security-mode stage,
did not create a registration-decision stage, and did not attribute frame 11 to security mode
control. The absence of a registration decision is recorded as a stage limitation rather than as an
asserted missing counterpart, which is consistent with the reviewed procedure model.

**Audit result: no Domain stage-modeling defect was found for this case.** The `authentication`
attribution is derived from observed message identity plus the accepted rule table, with no inference
about unobserved messages.

## 8. Independent Baseline Stage Label Review

### 8.1 What the accepted baseline contract says

`benchmarks/golden-captures/schemas/human-baseline.schema.json` types `procedure_stage` as a plain
string or null. It defines no enumeration, no controlled vocabulary, no mapping to any Domain stage
identifier, and no requirement that the value be drawn from the implemented stage catalog. No other
repository document defines the baseline's stage vocabulary; the generic procedure-evidence framework
states explicitly that it owns no telecom procedure catalog, so the only documented stage catalog in
the repository is the per-Domain one.

### 8.2 What the corpus actually uses

Surveying all 13 committed baselines, the stage labels in use are `ng-setup`, `registration`,
`security`, `release`, `establishment`, `deregistration`, `user_plane`, `authentication_resync`,
`uplink_transmission`, and `bidirectional_traffic`. Not one of these is identical, after the
comparator's normalization, to any of the ten Domain stage identifiers. The baseline therefore
maintains a parallel descriptive vocabulary across the whole corpus; `security` is not an isolated
slip.

This case is the only one in which the stage dimension is actually compared, because it is the only
case whose baseline carries a non-null boundary stage inside a procedure family that a Domain
implements. The disagreement is therefore the visible instance of a corpus-wide vocabulary
separation, not a local anomaly.

### 8.3 What `security` can and cannot mean here

Assessed against the five candidate readings listed in the review scope:

| Reading | Verdict | Basis |
| --- | --- | --- |
| A defensible high-level description | Supported, narrowly | TS 23.502 clause 4.2.2.2.2 groups authentication and security establishment under one step labelled `Authentication/Security` |
| A precisely defined stage identifier under the accepted benchmark contract | Not supported | The baseline schema defines no stage vocabulary, and no repository contract maps baseline labels to Domain stage identifiers |
| An ambiguous umbrella label | Supported | It covers two separately identifiable procedures and cannot distinguish them |
| A mistaken reference to NAS security mode control | Cannot be confirmed, and is contradicted if intended | No Security mode command, complete, or reject exists anywhere in the capture, and no protected envelope could conceal one |
| Impossible to interpret confidently from the current provenance | Partly applicable | The baseline documents no definition, no limitation, and no derivation for the label, and its boundary timestamp does not match the pinned capture epoch |

The baseline records `baseline_confidence` HIGH with an empty `limitations` array, so the frozen
record itself asserts no doubt about the label. That assertion is not supported by any documented
definition of the term.

**Conclusion for this dimension: `security` is defensible as a coarse umbrella description of the
enclosing registration step, and is not supported as a stage identifier under the only documented
stage taxonomy in the repository.**

## 9. Comparator Contract Audit

`compare_boundary_semantics` compares three dimensions — procedure stage, protocol identity, and
abnormal-event identity — by normalizing each side to upper-case alphanumerics and testing equality.
An absent or placeholder value is reported as unreported and is never treated as equal to anything.
There is no alias table, no equivalence class, and no hierarchy awareness anywhere in the comparator.

The benchmark README states the same rule in prose: a stage disagreement reports
`PROCEDURE_MATCH_STAGE_DIFFERENCE` even when the frame anchor is identical, and frame agreement never
repairs a semantic disagreement.

**The comparator therefore has no authority to treat `security` and `authentication` as equivalent,
and none is implied by any repository contract.** Its output for this case is a faithful report of a
genuine string-level disagreement, not a misinterpretation.

One wording observation, recorded for accuracy rather than as a defect: the README and the testing
policy describe the required stage values as "compatible", while the implementation tests strict
equality. The operative rule is equality, and the README's own worked example confirms that
intention, so this is documentation looseness, not a semantic contradiction.

## 10. Historical Versus Current Runtime Reconciliation

### 10.1 The historical finding

Adjudication revision 1 was produced against runtime `603075bc`. In it, every event-derived deviation
carries `stage_id: null`, including the frame-11 unsuccessful outcome and the frame-12 protocol
reject. The current-runtime reconciliation recorded that as open finding R-1, a
`DOMAIN_RECONSTRUCTION_DEFECT`: the emitter constructed event-derived deviations with a literal null
stage identity while absence-shaped deviations carried theirs. The same reconciliation recorded U-1,
the baseline `security` label being un-equatable with the packet-supported stage without either
inventing stage semantics or revising the frozen baseline.

### 10.2 The current runtime

Commit `7599cea` ("fix(domain): attribute procedure stage to registration deviations") introduced the
stage-resolution function audited in section 7.3. It is an ancestor of the reviewed source commit.
Commit `a7bf7cd` then refreshed the affected benchmark outputs, and the only change to this case's
sanitized summary in that refresh is exactly:

```
-    "selected_procedure_stage": null,
+    "selected_procedure_stage": "authentication",
```

The current committed summary reports `selected_procedure_stage = authentication`, and the
independent re-execution in section 7.4 reproduces it from the packets.

### 10.3 Reconciliation result

| Historical item | Status today |
| --- | --- |
| R-1, event-derived deviations carried null stage identities | **Superseded and closed.** Corrected by `7599cea` and reflected in the refreshed artifacts. It must not be reported as a currently open defect. |
| U-1, the baseline `security` label cannot be equated with the packet-supported stage | **Still open, and addressed by this review.** This record supplies the adjudication that U-1 deferred. |
| R-2, sanitized summaries lack per-type and candidate-eligibility deviation semantics | Still open and out of scope. It does not affect this case's comparison status, which turns on stage identity, not on deviation counting. |
| R-3, benchmark README drift on the registration-resynchronization case | Closed by the current head commit, whose README no longer describes that case as a false positive. |
| adj-01 and adj-02 (frames 11 and 12 supported by packet evidence) | Still valid; independently reconfirmed in section 4.1. |
| adj-03, adj-04, adj-05, adj-06 (absence and PDU-session findings) | Still valid as historical findings; the corresponding defective records are no longer emitted, exactly as the reconciliation recorded. |
| adj-07 and adj-08 (orchestration candidates at frames 12 and 11) | Still valid; the frame-11 candidate remains the selected boundary. |

**What remains disputed today is only the semantics of the baseline label.** The Domain-side
unreported-stage dimension is closed.

## 11. Answers to the Adjudication Questions

### Q1 — Boundary identity

**Yes, frame 11 is a supported first abnormal boundary, and both the recorded message identity and
the decoded cause are correct.**

Frames 1-8 are association and node-level setup. Frame 9 is a normal Registration request. Frame 10
is a normal Authentication request. Frame 11 is the first message in the capture that reports an
unsuccessful outcome: NAS-5GS Authentication failure (0x59) with `nas-5gs.security_header_type` 0 and
`nas-5gs.mm.5gmm_cause` 20. TS 24.501 annex A.3 and table 9.11.3.2.1 define cause 20 as MAC failure.

Confidence: CONFIRMED. Evidence that would change it: a preceding abnormal message in frames 1-10, or
a decoded cause other than 20 at frame 11.

### Q2 — Authentication procedure

**Yes. Frame 11 belongs to a NAS primary authentication procedure, and the surrounding messages
establish that context.**

The preceding observed message is the Authentication request at frame 10, which is the procedure's
trigger under TS 24.501 clause 5.4.1.3.2 and the Domain model. The following observed message is the
Authentication reject at frame 12, which TS 24.501 clause 5.4.1.3.5 defines as the network's
non-acceptance outcome of the same procedure, reached through the clause 5.4.1.3.7 c) path named for
cause 20. All three messages share the same UE-NGAP-ID pair (RAN 1 / AMF 2), so they are one
UE-associated signalling conversation.

Confidence: CONFIRMED. Evidence that would change it: a different UE-NGAP-ID binding, or a message
identity between frames 10 and 12 belonging to another procedure.

### Q3 — Security Mode Control

**No NAS security mode control procedure is observable in the capture.**

The exhaustive inventory in section 4 contains no Security mode command, complete, or reject, and no
security-protected envelope that could conceal one. This is a stronger form of non-observation than
the protected-envelope cases: in those captures an inner message could be hidden, whereas here every
NAS message is plain and there is no envelope at all.

Non-observation is not the same as proof about the wider network session, and this review does not
claim the latter. What the packets support is: no security mode exchange exists anywhere in this
16-frame capture. What the procedure state additionally supports is that none was expected, because
TS 24.501 clause 5.4.2.1 makes security mode control the procedure that takes a security context into
use, and the authentication that would have produced that context failed at frame 11.

Confidence: CONFIRMED for non-observation inside the capture; INFERRED for the wider session, which
is bounded by the N2 release at frames 13-15.

### Q4 — Human baseline meaning

**`security` is a coarse descriptive category, not a stage identifier, and its intended meaning is
not documented.**

There is no documented definition, no controlled vocabulary, no mapping to the Domain catalog, and no
recorded derivation or limitation for the label. The strongest available reading is the TS 23.502
clause 4.2.2.2.2 flow step labelled `Authentication/Security`, which makes `security` a defensible
high-level description of the enclosing step that contains both authentication and security
establishment. It does not make `security` a distinct stage identifier, and if it were intended to
mean NAS security mode control it would be contradicted by the absence of any such exchange.

Confidence: HIGH for "not a stage identifier under the accepted taxonomy"; HYPOTHESIS for the specific
authoring intent, because the provenance is undocumented and the baseline's boundary timestamp does
not match the pinned capture epoch.

### Q5 — Domain stage meaning

**`authentication` denotes the Domain's Authentication procedure stage, and frame 11 falls inside it
on evidence alone.**

The stage is conditional, is triggered by Authentication request, and lists Authentication failure
and Authentication reject among its expected outcomes. It was activated at frame 10, its stage record
carries HIGH confidence over frames 10-12, and the stage-resolution function uniquely maps both
frame-11 and frame-12 message identities to it. Independent re-execution reproduced exactly that,
with both deviations carrying `stage_id = authentication`.

Confidence: CONFIRMED. Evidence that would change it: a rule table in which another stage also claims
the Authentication failure message identity, or a capture in which the authentication stage was never
activated.

### Q6 — Semantic equivalence

**No. `security` and `authentication` cannot be treated as equivalent under the accepted comparator's
stage-identity contract.**

The comparator performs normalized identity equality with no alias mechanism. No repository contract
authorizes an alias, and the standards do not supply one: TS 24.501 clauses 5.4.1 and 5.4.2 and
TS 33.501 clauses 6.1.3 and 6.7.2 define authentication and security mode control as separate
procedures, and TS 23.502's `Authentication/Security` step is a call-flow grouping, not an identity
statement. A broad concept that contains authentication is not equivalent to authentication; the
relation is containment, and it is asymmetric.

Proposing equivalence here would require inventing an alias table that no document authorizes, and
its only practical effect would be to remove a discrepancy rather than to record a fact.

Confidence: CONFIRMED.

### Q7 — Responsible layer

**The label discrepancy originates in the independent human baseline's terminology. It is not a
Domain defect and not a comparator defect. Two further issues are independently established at the
governance level.**

- Independent human baseline terminology: the label departs from the only documented stage taxonomy,
  while the Skill's label conforms to it and is packet-supported.
- Domain stage modeling: no defect found. Attribution is rule-derived from observed identity, and the
  historical null-stage defect is closed.
- Comparator contract interpretation: no defect found. The comparator reports a real string
  disagreement exactly as documented.
- Governance issue: the baseline contract defines no stage vocabulary and no mapping to the Domain
  catalog, while the comparator requires exact identity, so stage agreement is undefined for any
  baseline label not drawn from the Domain catalog. This applies corpus-wide, not just here.
- Governance issue: the committed differential's `layer_attribution: DOMAIN` and
  `recommended_next_action: CORRECT_DOMAIN_MODEL` are produced by a fixed policy that assigns DOMAIN
  to any in-family boundary-semantics mismatch, without distinguishing which side departed. The
  adjudication vocabulary already offers `HUMAN_BASELINE` as a first-differing-layer value, but the
  differential cannot emit it. For this case the policy default does not survive adjudication.

Packet evidence cannot assign implementation blame, and this review does not.

### Q8 — Acceptance impact of a separately authorized correction

The effect was measured rather than assumed. The committed case inputs were copied outside the
repository, the comparator was re-run on the unmodified copy, and the output was confirmed
byte-identical to the committed `differential.json`. The copy's baseline stage label was then changed
to `authentication` and the comparator was re-run.

| Artifact | Effect of changing the frozen baseline stage to `authentication` |
| --- | --- |
| `human-baseline.json` | The boundary stage and the `security` procedure observation would change; canonical digest would change from `74b7a9596b4687c050715d4b012a6f637bfa34bd3bc4b5478d82880afe2b129d` to `2d2a85e4da8caa2e06ff61575e5b9b4ac589d762df6b67b597b88c4a13016ba0` for the exact edit tested |
| `differential.json` | `comparison_status` becomes `EXACT_MATCH`; `adjudication_required` becomes false; the note and recommended action change |
| `benchmark-summary.json` | `exact_match_count` 0 to 1, `stage_match_count` 0 to 1, `procedure_match_count` 1 to 0, `needs_adjudication_count` 1 to 0, with `exact_match_rate` 0.0 to 0.1667 and `procedure_match_rate` 0.1667 to 0.0 over the evaluated-in-scope denominator of 6 |
| Domain or comparator output | unchanged |
| Skill runtime | unchanged |

The measured `EXACT_MATCH` outcome is recorded strictly as a consequence, not as a justification. A
match-rate improvement is not evidence about which label is correct, and this review's conclusion
rests on the packet and normative analysis, not on this simulation.

## 12. Adjudication Outcome

**Outcome: `MULTIPLE_DISTINCT_FINDINGS`.** Three findings are established independently, and the
permitted outcome `HUMAN_BASELINE_STAGE_UNSUPPORTED` is established as the first of them. The
remaining outcome categories are addressed explicitly: `DOMAIN_STAGE_ATTRIBUTION_DEFECT` is rejected,
`TERMINOLOGY_EQUIVALENCE_SUPPORTED` is rejected, and `INSUFFICIENT_EVIDENCE` does not apply to the
stage question, which the packets decide.

### F-1 — The frozen baseline stage label is not supported as a stage identifier

- Claim: `procedure_stage = security` has no standing as a stage identifier under the accepted
  benchmark contract, and `authentication` is independently supported for frame 11.
- Packet evidence: frame 10 Authentication request, frame 11 Authentication failure with cause 20,
  frame 12 Authentication reject, all plain, one UE-NGAP-ID pair; no security mode exchange anywhere
  in the capture.
- Dissector fields: `nas-5gs.mm.message_type` 0x56 / 0x59 / 0x58, `nas-5gs.mm.5gmm_cause` 20,
  `nas-5gs.security_header_type` 0, `ngap.procedureCode` 4 / 46 / 4.
- Normative reference: TS 24.501 19.8.0 clauses 5.4.1, 5.4.1.3.5, 5.4.1.3.6, 5.4.1.3.7 c), 8.2.4.1,
  table 9.11.3.2.1, annex A.3; TS 24.501 5.4.2.1 and 5.4.2.2; TS 33.501 19.4.0 clauses 6.1.3.3.1 and
  6.7.2; TS 23.502 19.9.0 clause 4.2.2.2.2.
- Repository contract: `rules/registration-model.json` stage vocabulary; `human-baseline.schema.json`
  free-form `procedure_stage`; `compare_results.compare_boundary_semantics`.
- Limitations: the baseline's authoring intent is undocumented; `security` remains defensible as a
  coarse umbrella over the TS 23.502 step, so this finding is about stage-identifier standing, not
  about whether the baseline author was describing something real.
- Confidence: HIGH.
- What would change it: a documented baseline stage vocabulary that defines `security` as an
  identifier distinct from `security-mode` and justifies it for frames 10-12; or observed Security
  mode command traffic at or before frame 11.

### F-2 — No shared stage vocabulary contract exists between the baseline and the Domain catalog

- Claim: the baseline schema leaves `procedure_stage` free-form while the comparator requires exact
  normalized identity, and the corpus uses a vocabulary entirely disjoint from the Domain catalog, so
  stage agreement is undefined for every baseline label not drawn from that catalog.
- Evidence: schema typing; the ten Domain stage identifiers; the 13-baseline survey in section 8.2,
  in which zero labels match any Domain identifier; comparator normalization with no alias mechanism.
- Repository contract: `human-baseline.schema.json`; `rules/registration-model.json`;
  `compare_results.normalize_identity`; benchmark README stage-matching rules.
- Limitations: whether the intended design is a shared vocabulary or free-form description is a
  governance question this review cannot settle from the case evidence. The factual disjointness is
  established; the preferred remedy is not.
- Confidence: HIGH for the factual disjointness and the contract gap; the remedy is a governance
  decision.
- What would change it: a documented mapping or controlled vocabulary in the baseline contract, or
  evidence that the comparator is intended to consume free-form labels.

### F-3 — The differential's layer attribution is a policy default, not an evidence finding

- Claim: for this case the committed `layer_attribution: DOMAIN` and
  `recommended_next_action: CORRECT_DOMAIN_MODEL` do not identify where the departure actually is;
  they are the comparator's fixed response to any in-family boundary-semantics mismatch.
- Evidence: the comparator assigns DOMAIN and CORRECT_DOMAIN_MODEL in the branch that handles any
  mismatched boundary dimension after a family match, without evaluating which side departed; the
  adjudication area separately defines `HUMAN_BASELINE` as a valid first-differing-layer value.
- Repository contract: `compare_results` boundary branch; `adjudications/README.md` first-differing-
  layer vocabulary.
- Limitations: this is an expressiveness gap in attribution, not an error in comparison correctness;
  the comparator still reports the disagreement itself faithfully.
- Confidence: CONFIRMED for the code behaviour; HIGH for the conclusion that the default does not
  survive adjudication here.
- What would change it: a comparator contract that resolves side-specific attribution, or a
  documented rule that DOMAIN is intentionally a routing label rather than a finding.

### What this outcome is not

It is not a Domain defect, not a comparator defect, and not an authorization to change anything. It
does not assert that the benchmark accuracy has improved or changed. The frozen baseline still
records `security`, the committed differential still records `PROCEDURE_MATCH_STAGE_DIFFERENCE`, and
the aggregate metrics are untouched.

## 13. Remaining Limitations

1. The lower-layer Protocol Skills were not re-executed. Event records for the Domain re-execution
   were constructed from dissector output, so the reproduction in section 7.4 verifies the Domain
   stage logic against the packets, not the full extraction chain.
2. The baseline's authoring provenance is not documented, and its boundary timestamp does not match
   the pinned capture epoch, so the specific reason the label `security` was chosen cannot be
   reconstructed with confidence. The finding about its stage-identifier standing does not depend on
   that reconstruction.
3. Non-observation of security mode control is proven only inside this 16-frame capture. Statements
   about the wider session are marked INFERRED and are bounded by the N2 release at frames 13-15.
4. The TS 23.502 flow-step label `Authentication/Security` is a call-flow grouping. This review treats
   it as support for a coarse description only, and does not treat it as a normative stage taxonomy.
5. Whether a shared stage vocabulary should exist, and what it should contain, is a governance
   decision outside this review's authority.

## 14. Baseline Integrity

| Check | Result |
| --- | --- |
| Canonical digest of the committed baseline, recomputed with the repository's accepted canonical JSON hashing | `74b7a9596b4687c050715d4b012a6f637bfa34bd3bc4b5478d82880afe2b129d`, identical to the value recorded in the committed differential |
| Legacy `baseline_hash` field | Informational only; it matches neither the canonical digest nor the digest of the file's raw bytes, is referenced by no script, and is not used as an authenticated digest |
| Frozen baseline content | unchanged by this review |
| Frozen case record, differentials, summaries, aggregate metrics | unchanged by this review |
| Capture digest | recomputed and matching |

No baseline revision is authorized or performed here.

## 15. Scope of a Possible Future Authorized Correction

If a later, separately authorized task decides to act on F-1, the following describes the exact
boundary of that work. None of it is performed here.

- In scope for such a task: the boundary `procedure_stage` value and the corresponding
  `procedure_observations` entry for this one case; a refreshed `differential.json` for this one
  case; a refreshed aggregate summary; and an adjudication-record update that preserves the
  superseded canonical digest `74b7a9596b4687c050715d4b012a6f637bfa34bd3bc4b5478d82880afe2b129d`.
- Required governance: an explicit statement that the revision was decided on packet and normative
  evidence and not on the match-rate effect measured in section 11 Q8; preservation of the superseded
  digest and the superseded label; and re-adjudication of the affected differential rather than a
  silent metric change.
- Explicitly out of scope even then: any Domain stage-model change, any comparator change, any alias
  mechanism, any other case's baseline, and any benchmark score change beyond the mechanical
  consequence of the single baseline revision.
- F-2 and F-3 are not remedied by a baseline revision and would each require their own authorization.

If instead the governance decision is that the baseline vocabulary is intentionally descriptive, the
correct response is a documented vocabulary or mapping contract, not an edit to this case. Both
directions remain open; this review records the evidence, not the policy.

## 16. Status

This is an independent, review-only adjudication record. Its conclusion has not been applied to the
frozen benchmark, and it does not assert that the benchmark's accuracy or any metric has changed. The
frozen human baseline remains the authoritative baseline until a separately authorized revision
exists.
