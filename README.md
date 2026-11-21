# CoreNet Skill

`CoreNet-skill` is a modular, evidence-first repository for future AI-agent Skills that investigate mobile core-network signaling. Its intended technology scope includes EPC, IMS, 5GC, NGAP, NAS, S1AP, GTPv2-C, GTP-U, PFCP, SIP, SDP, RTP, Diameter, SBI/HTTP2, and Core network service function development.

## Current status

**Implemented:** accepted repository foundation, agent governance, audited
upstream snapshots, six CoreNet Foundation Skills, telecom core-network
Foundation extensions, GitHub Actions validation, the `core-network-pcap`
capture normalization layer, the bounded `ngap` Protocol Skill
(bounded UE-context signaling, PDU Session Resource
setup/modify/release subset over N2, including resources embedded in
Initial Context Setup, and the bounded N2 handover/path-switch mobility
subset: HandoverRequired/HandoverCommand/HandoverPreparationFailure,
HandoverRequest/HandoverRequestAcknowledge/HandoverFailure, HandoverNotify,
HandoverCancel/HandoverCancelAcknowledge, and
PathSwitchRequest/PathSwitchRequestAcknowledge/PathSwitchRequestFailure
with bounded mobility metadata and item-scoped resource-list roles), the bounded `nas-5gs` Protocol
Skill (bounded 5GMM
registration/identity/authentication/security-mode/service/status and
bounded 5GSM PDU session establishment/modification/release/status
subsets over N1 with security-envelope classification, bounded
session-management normalization, privacy defaults, and 5GSM cause
preservation), the bounded `pfcp` Protocol Skill
(bounded N4 session-control subset: Heartbeat, Association Setup, Session
Establishment/Modification/Deletion, header SEID and CP/UP F-SEID evidence,
bounded PDR/FAR/QER/URR rule groups, PFCP Cause, and endpoint-scoped
transaction correlation), the bounded `gtpu` Protocol Skill
(bounded N3 user-plane observation: G-PDU, Echo, Error Indication, End
Marker and Supported Extension Headers Notification, with TEID evidence
scoped by directed outer endpoints, bounded PDU Session Container / QFI
evidence, bounded inner packet metadata, and observed packet/byte stream
summaries), the bounded `sbi-http2` Protocol Skill
(bounded N11 Nsmf_PDUSession and Namf_Communication N1/N2 delivery observation:
Create SM Context, Update SM Context, Release SM Context, Namf N1N2MessageTransfer,
and N1N2Transfer Failure Notification, with HTTP/2 stream isolation scoped by
connection context, transfer reference tracking, URI path privacy sanitization,
Content-ID multipart binding, subscriber privacy redaction, bounded ProblemDetails,
HTTP/2 transport errors, and deterministic callback correlation), and the `cross-protocol-evidence` Correlation
Skill (provenance-key joins of extracted protocol events into a unified
observed-evidence timeline; no protocol ownership, no verdicts), and the
`procedure-evidence` Domain framework (generic stage and evidence model
with missing-evidence visibility), the bounded `5gc-registration-mobility`
Domain Skill (N1/N2 registration and access procedure-stage evidence, conditional
branches, missing-evidence visibility, and lower-layer field findings; no end-to-end
diagnosis), and the bounded `5gc-pdu-session` Domain Skill (v0.4.0, bounded
5GC PDU Session Establishment, repeated Modification, and Release lifecycle
analysis across N1/N2/N3/N4/N11 composing already-extracted NAS, NGAP, PFCP,
GTP-U, and SBI evidence, with lifecycle generation handling so the same UE
context re-using the same numeric PDU Session ID after an evidence-supported
release boundary forms a distinct lifecycle generation; no root-cause verdicts,
no implementation mapping), and the bounded `5gc-handover-mobility` Domain Skill
(v0.1.0, bounded 5GC N2 handover and Path Switch procedure analysis from
already-extracted NGAP/PFCP/GTP-U/SBI evidence: separate `handover_attempts` and
`path_switch_attempts` families with evidence-bounded source/target association,
branch-aware conditional stages, item-scoped PDU Session resource outcomes,
bounded N11/N4/N3 supporting evidence, and procedure-local deviations with
structured evidence_refs; no success/failure verdicts, no root-cause output),
and the bounded `5gc-failure-boundary` Analysis Orchestration
Skill (v0.2.0, evidence-safe first abnormal boundary localization across the
supported 5GC Domain analyses: diagnostic groups linked by exact common context,
separately addressable handover and Path Switch attempts with Domain-authorized
source/target context bridges, candidates drawn only from Domain-emitted deviations
and their machine-readable evidence_refs (Domain contracts 5gc-registration-mobility
>=0.2.0, 5gc-pdu-session >=0.4.0, and 5gc-handover-mobility >=0.1.0), provenance-based
ordering with no severity ranking, and no root-cause or blame output). The unified
`scripts/corenet-analyze.py` analysis workflow executes that accepted 5GC chain from
a single command-line entry point. The bounded `diameter-core` Protocol Skill
extracts Diameter base-protocol header, AVP, base result and vendor
experimental-result evidence from TCP/SCTP captures, with decoder-proven grouped
AVP structure, privacy-safe sensitive-AVP redaction and protocol-local
Request/Answer correlation; it does not implement S6a, Gx, Rx, Cx, IMS or any
application procedure verdict. The bounded `sdp-rtp` Protocol Skill parses explicitly
supplied RFC 8866 SDP bodies into structural session/media evidence with privacy-safe
address and sensitive-attribute classification, and extracts bounded RFC 3550 RTP
version 2 and RTCP SR/RR/SDES/BYE packet evidence from structured JSONL or an explicitly
authorized TShark capture; a separate bounded `rtp-stream` Protocol Skill reconstructs
capture-scoped RTP source streams and RFC 3550 Appendix A.1 sequence-integrity evidence
from that accepted output, reporting probation, wrap, duplicate, reorder, unobserved
sequence-number slot and restart-pattern evidence without a packet-loss, jitter, MOS,
QoS or media-delivery verdict; the `sdp-rtp` producer itself does not implement local
loss/jitter, MOS/QoS, Offer/Answer, SIP-to-SDP association or IMS media verdicts. The bounded `sip` Protocol Skill extracts SIP
requests and responses over UDP and TCP, including IPv4/IPv6 and
decoder-delivered TCP reassembly metadata, correlates requests and responses at the
RFC 3261 transaction layer, classifies retransmissions and publishes transaction
state with explicit matching ambiguity; it preserves privacy-safe redaction of
identities, URIs, tags, credentials and bodies, does not correlate SIP dialogs and
assigns no IMS procedure verdict. The bounded `s1ap` S1-MME Protocol Skill, the bounded
`nas-eps` EPS NAS Protocol Skill and the bounded `gtpv2` GTPv2-C session-control
Protocol Skill extract EPC access-signaling, NAS message and session-control
evidence from LTE captures, and the bounded `epc-procedures` Domain Skill analyzes
observed EPS Attach procedure stages, bounded GTPv2-C session-control transactions
and bounded EPS default-bearer signalling with procedure-local deviations,
item-scoped E-RAB and bearer evidence, evidence-safe cross-interface identity
links, and bounded S1-U GTP-U stream observation, with no bearer, PDN, delivery or
service verdict. The bounded `epc-failure-boundary` Orchestration
Skill selects, per diagnostic subject, the earliest supported abnormal observation
with exact frame evidence and explicit ambiguity, and never merges independent
Attach, S11 and S5/S8 subjects into one EPC failure point. The extensions provide investigation context only.
**Not yet implemented:** deep NGAP transfer-container decoding, the remaining
NGAP mobility-adjacent procedures (RAN Status Transfer and similar), broader
5GC mobility beyond the bounded handover/path-switch Domain analysis (UPF
relocation, inter-system and 5GS-EPS mobility, RAN Status Transfer Domain
semantics), remaining
5GC SBI services, GTP-U on N9/S1-U/S5-S8-U, remaining protocol work (RTP media QoS and Diameter IMS Sh/Rx/charging), IMS session modification and media-domain analysis,
broader EPC procedures (bearer and session lifecycle, Diameter EPC, cross-interface session association, end-to-end EPC diagnosis),
implementation-specific mappings, or root-cause hypothesis reasoning and deeper
diagnosis orchestration.

## Why modular Skills

Each future Skill is designed to be downloaded and used independently. It must document its bounded responsibility, inputs, outputs, dependencies, evidence behavior, test coverage, and upstream provenance. This keeps reusable protocol expertise separate from domain procedures and implementation-specific knowledge.

```text
Foundation → Protocol → Correlation → Domain / Procedure → Analysis Orchestration
```

| Layer | Purpose |
| --- | --- |
| Foundation | Teach an agent how to investigate and grade evidence: Wireshark use, reverse engineering, systematic debugging, Linux, and C-oriented methods. |
| Protocol | Teach protocol-local encoding and correlation: NAS, NGAP, S1AP, GTP, PFCP, SIP, SDP/RTP, Diameter, and SBI. |
| Correlation | Join already-extracted protocol evidence into deterministic groups and a unified observed-evidence timeline by shared capture provenance. |
| Domain / procedure | Compose protocol evidence and correlation output into procedure-stage analysis for EPC, IMS, and 5GC procedures. Domain Skills consume protocol evidence and correlation output; they do not replace protocol decoding or correlation. |
| Analysis Orchestration | Combine protocol evidence into investigation reports that localize the first abnormal evidence boundary with confidence-aware diagnosis. |

Dependencies only point left, and a Skill may depend on the same layer when ownership remains acyclic and semantically correct. Lower layers never own higher-layer capabilities, which prevents circular architecture and preserves reuse. Correlation is optional infrastructure for Domain Skills, not a mandatory wrapper around every Protocol Skill.

CoreNet Skill focuses on network signaling evidence analysis rather than implementation-specific source ownership. Implementation is not a Skill layer: when users provide implementation-specific logs, source code, or configuration, agents may analyze them as external evidence, but the repository never owns Skills for implementation-specific telecom software, third-party implementations, or vendor-specific network functions.

## EPC, IMS, 5GC, and Diameter

EPC procedures reuse NAS-EPS, S1AP, the implemented GTPv2-C session-control Skill, GTP-U, and Diameter EPC. IMS registration and session evidence reuse the implemented SIP Protocol Skill (including its bounded Dialog evidence), the implemented Diameter IMS Cx/Dx Protocol Skill, the implemented IMS Registration Domain Skill and the implemented IMS Session Domain Skill; bounded SDP and RTP/RTCP packet evidence exists as standalone Protocol Skills; the standalone `sdp-rtp-transport` Correlation Skill matches accepted SDP media transport endpoints with observed RTP UDP streams by capture-scoped HMAC endpoint equality, the standalone `ims-media-signaling` Domain Skill associates accepted SIP session attempts and independent dialog branches with accepted SDP messages, and the standalone `ims-media-session` Domain Skill composes IMS Session, IMS Media Signaling, SDP Analysis and transport-correlation evidence into branch-scoped media transport observations without a temporal or media-delivery verdict; these Skills are not yet integrated into that path. RTP stream reconstruction is implemented as the standalone `rtp-stream` Protocol Skill; RTP media QoS, Diameter Charging, session modification and media-domain analysis remain future work. 5GC procedures reuse NAS-5GS, NGAP, PFCP, GTP-U, and SBI/HTTP2.

Diameter is explicitly cross-domain—not an IMS-owned protocol. `diameter-core` owns base-protocol behavior; `diameter-epc` owns bounded S6a/S6d AIR/AIA and ULR/ULA application-message evidence; `diameter-ims` owns bounded Cx/Dx UAR/UAA, SAR/SAA, LIR/LIA, MAR/MAA, RTR/RTA and PPR/PPA application-message evidence; and `diameter-charging` will own shared credit-control semantics and remains planned, together with the Diameter IMS Sh and Rx applications. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Evidence first

All future troubleshooting output must separate observations, deterministic derivations, inferences, hypotheses, and confirmed results. A visible network action is not proof of a cause. The formal evidence levels and safe-language rule are in [docs/EVIDENCE-SCHEMA.md](docs/EVIDENCE-SCHEMA.md); normalized events and diagnostic results are schema-defined in `shared/schemas/`.

## Analyze a capture

`scripts/corenet-analyze.py` is the unified analysis entry point. It executes the
accepted Protocol, Correlation, Domain and Orchestration Skills for 5GC, EPC and IMS
captures and writes `analysis.json` plus `report.txt`.

```bash
python3 scripts/corenet-analyze.py \
  --capture /data/captures/registration.pcap \
  --domains auto \
  --work-dir /tmp/corenet-work \
  --output-dir /tmp/corenet-output
```

### Offline IMS media analysis

Add `--with-media --offline` to compose the accepted SIP, SDP, RTP/RTCP, RTP
source-stream, SDP/RTP transport-correlation and IMS media-session Skills in one
local run:

```bash
python3 scripts/corenet-analyze.py \
  --capture /private/local/ims/volte.pcapng \
  --domains ims \
  --with-media \
  --offline \
  --expected-capture-sha256 <64-lowercase-hex> \
  --work-dir /private/local/ims-work \
  --output-dir /private/local/ims-results
```

The media run creates a capture-scoped, owner-only 32-byte HMAC key under
`~/.local/share/corenet-skill/endpoint-keys/` (or uses `--endpoint-key-file`) and
uses the same key for SDP and RTP so endpoint references are comparable. Raw SIP and
SDP bodies are retained only in memory by the private adapter and are never written
to reports or tracked artifacts. `--offline` asserts that the analysis path needs no
external network service; TShark remains the only local dissector.

Media status is reported separately as `SUCCESS`, `PARTIAL`, `INSUFFICIENT_EVIDENCE`,
`UNSUPPORTED` or `FAILED`. A missing SDP answer, missing RTP, unmatched endpoint
correlation or encrypted media downgrades the media result instead of fabricating a
positive conclusion. `report.txt` includes SIP/SDP/RTP counts, RTP sequence-integrity
evidence, SDP/RTP match status, IMS media associations, diagnostics and the last
supported evidence point. No call success, RTP delivery, two-way audio, packet-loss,
QoS or MOS verdict is produced.

The workflow also publishes per-call and per-branch diagnostics. A capture-wide media
result is never substituted for an individual call's evidence coverage: each attempt
and branch receives its own `EVIDENCE_CHAIN_SUPPORTED`, `SIGNALING_ONLY`,
`MEDIA_TRANSPORT_OBSERVED`, `PARTIAL_EVIDENCE`, `AMBIGUOUS_OWNERSHIP`,
`INSUFFICIENT_EVIDENCE` or `UNSUPPORTED_PROCEDURE` status. The report includes RTP
duplicate-observation classification (multi-vantage, duplicate packet, sequence-only,
retransmission-not-established, unresolved), bounded SIP/RTP temporal evidence,
RTCP-to-RTP association boundaries, and receiver-reported fraction lost, cumulative
loss and jitter in RTP units. RTCP millisecond jitter is published only when a unique
RTP clock rate and source association are proven.

The workflow also publishes logical IMS call groups. Multi-hop INVITE transactions
are grouped only when capture-scoped HMAC Call-ID, From-tag, To-tag and CSeq identity
agree and the Via-hop stack is nested; a Call-ID match alone never merges attempts.
Each logical call lists its member attempts, transactions, Dialog branches, SDP
exchanges, candidate transports, source streams, temporal constraint, RTCP evidence
and an explicit `LOGICAL_CALL_MEDIA_OWNED`, `AMBIGUOUS_OWNERSHIP` or
`INSUFFICIENT_EVIDENCE` status. RTP duplicate identity is derived from complete RTP
packet bytes through a capture-scoped keyed HMAC; a header-tuple match is published
only as a header-signature observation.

The public IMS/VoLTE capture corpus and its pinned provenance are recorded in the
local acceptance record. Raw captures remain local-only and are never committed or
uploaded to CI.

`--domains` accepts `auto`, `5gc`, `epc`, `ims`, or a comma-separated list. 5GC, EPC
and IMS execute bounded analysis paths. IMS auto-selection runs when plaintext SIP is
observed while technology attribution remains `SUSPECTED`; an explicit `--domains ims`
executes the available IMS components even when evidence is incomplete. EPC covers
EPS Attach and session-control evidence, and when the accepted GTPv2-C transactions
contain Create/Update/Delete
Bearer signaling the unified path also runs the dedicated-bearer control-plane
outcome producer and records its bounded summary in `analysis.json` and `report.txt`.
A capture without those transactions reports `NOT_OBSERVED_IN_CAPTURE` instead of a
failure or a fabricated success; dedicated-bearer lifecycle remains out of scope.
Both the unified path and the optional Review Pack validate the complete Dedicated
Bearer artifact contract before publishing success, preserve the producer's declared
totals separately from published and displayed subsets, and reject a malformed
supplied optional source rather than treating it as usable evidence. The Review
Pack navigation index registers real narrative-subject, narrative-group and nested
bearer-endpoint objects and resolves Audit Subject references only by capture-scoped
source ownership and explicit identity; unresolved relationship mentions, missing
objects and cross-capture references remain explicitly classified. The unified path
also emits a frame-anchored Dedicated Bearer cross-layer timeline over the accepted
control artifact and optional NAS-EPS/S1AP events; it lists observed dedicated ESM
and standalone E-RAB references and marks cross-layer links as established only
with matching item identity, a complete procedure pair and shared capture-scoped UE
context evidence; the three-plane overall status requires both NAS and S1AP layers.
Upstream source completeness is preserved and mixed-capture inputs are rejected.
A separate optional attribution artifact exposes receiver-scoped control-to-session
links, NAS-to-S1AP ownership from an observed embedded NAS-PDU, and endpoint-only
correspondence with the exact missing identity bridge; endpoint equality is never
promoted to UE identity. IMS executes accepted SIP extraction, optional Diameter
Cx/Dx evidence, IMS Registration and IMS Session analysis; with `--with-media` it
also composes the accepted SDP, RTP/RTCP, RTP source-stream, transport-correlation and
IMS media-session Skills. A missing component or failed extraction is reported
explicitly and never converted into an IMS call, media or network verdict. Every
diagnostic subject in a capture is reported with its own boundary status, a failed
component makes the run `PARTIAL` instead of `COMPLETED`, and the workflow never asserts
network health.
See [docs/ANALYSIS-WORKFLOW.md](docs/ANALYSIS-WORKFLOW.md) for prerequisites, exit
codes, the report contract, privacy rules and the EPC/IMS implementation boundary.

## Review EPC evidence

`scripts/epc-evidence-review.py` builds a bounded, reference-oriented Review Pack
from already-published EPC analysis artifacts, or from an explicit local capture
replay through the accepted unified EPC pipeline.

```bash
python3 scripts/epc-evidence-review.py \
  --artifacts-dir /data/epc-artifacts \
  --output-dir /tmp/epc-review-pack
```

It writes `manifest.json`, `evidence-review.json`, `evidence-review.md`,
`evidence-index.json` and `replay-verification.json`. Unresolved references stay
explicit, duplicate ownership stays scoped to actual claimants, and no producer
count is rewritten. `--capture` enables local replay, while `--compare-a` and
`--compare-b` compare two independently produced Review Packs without treating
different evidence as equal.

Local replay binds artifacts to a fresh, invocation-specific work directory with
sibling `scratch/` and `cli-output/` paths, so work and output never overlap, and
never selects a stale run. Comparison mode returns `0` only for `IDENTICAL`, `1` for
`DIFFERENT`, and `5` for missing, schema-incompatible, capture-mismatched or
unsupported comparisons; output-write failures return `7`. Audit Ledger omission,
source-collection completeness and Review Pack display truncation are reported as
separate dimensions.

## Repository structure

```text
├── docs/                 # frozen architecture, contracts, rules, roadmap
├── shared/               # schemas and documented future shared assets
├── skills/               # Foundation wrappers; later-layer Skills remain planned
├── templates/skill-template/  # reusable contract-complete Skill skeleton
├── scripts/              # validation and original generic helper scripts
└── tests/                # schema, structure, and fixture checks
```

The original generic workflow is retained: `scripts/new-skill.sh` creates a simple standalone Skill skeleton and `scripts/link-skills.sh` links Skills into a local discovery directory. A repository-compliant Skill must additionally follow [docs/SKILL-SPEC.md](docs/SKILL-SPEC.md) and use `templates/skill-template/`.

## Validate

```bash
python scripts/validate-repository.py
python -m unittest discover -s tests -p "test_*.py"
```

Python's standard library is sufficient for the repository foundation. The checks parse JSON schemas and fixture documents, but do not claim full runtime JSON Schema validation; [docs/TESTING.md](docs/TESTING.md) explains the deliberate limitation.

Ubuntu 24.04 developers can use `./scripts/dev.sh` (`doctor`, `bootstrap`, `validate`, `golden-preflight`); see [docs/DEVELOPMENT-UBUNTU.md](docs/DEVELOPMENT-UBUNTU.md).

## Contribution expectations

Keep Scope and Non-Goals explicit, use lowercase kebab-case names, preserve artifact provenance, attach evidence levels to claims, and add focused fixtures/tests for executable or rule-driven work. Do not add protocol expertise until its planned milestone is authorized. Review [docs/NAMING.md](docs/NAMING.md), [docs/UPSTREAM.md](docs/UPSTREAM.md), and [docs/ROADMAP.md](docs/ROADMAP.md) before proposing a Skill.

## Roadmap

The repository foundation and six accepted Foundation Skills establish the
stable investigation-method baseline; GitHub Actions reproduces repository
validation remotely.
Future milestones are Packet and Protocol Core (continuing), remaining Diameter IMS
Sh/Rx and charging, IMS media/QoS, Advanced 5GC Interfaces, and End-to-End Root Cause
Analysis; the implemented 5GC, EPC, IMS registration, IMS session and standalone
IMS SDP media-signaling paths remain bounded evidence capabilities. IMS media QoS, RTP endpoint
correlation and unified media execution remain planned; RTP source-stream
reconstruction and sequence-integrity evidence are implemented as a standalone
Protocol Skill. Implementation-specific Skills are not planned: external
implementation analysis is performed only when users provide implementation
evidence. Each milestone's gates and dependencies are frozen in
[docs/ROADMAP.md](docs/ROADMAP.md).
