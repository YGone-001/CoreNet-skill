# EPC Procedures Domain Skill

Bounded EPS Attach procedure analysis over accepted S1AP and NAS-EPS events.

```text
skills/domain/epc-procedures/
├── SKILL.md        Skill contract
├── README.md       This file
├── manifest.yaml   Machine-readable manifest
├── references/     Procedure model, stage map, evidence rules, limitations
├── rules/          Stage vocabulary and deviation catalogue
├── schemas/        Analysis JSON Schema
├── scripts/        analyze_epc_attach.py, epc_attach_timeline.py, epc_attach_model.py
├── examples/       Event fixtures and expected analysis
└── tests/          Standalone unit tests
```

## Quick start

```bash
# 1. Extract protocol events (from the Protocol Skills)
python3 ../../protocol/s1ap/scripts/extract-s1ap.py capture.pcap --output s1ap-events.jsonl
python3 ../../protocol/nas-eps/scripts/extract-nas-eps.py capture.pcap --output nas-eps-events.jsonl

# 2. Analyze the EPS Attach procedure
python3 scripts/analyze_epc_attach.py \
  --s1ap s1ap-events.jsonl \
  --nas nas-eps-events.jsonl \
  --output epc-attach-analysis.json \
  --stage-output epc-attach-stages.jsonl

# 3. Read the procedure timeline
python3 scripts/epc_attach_timeline.py epc-attach-analysis.json --format text
```

Or run everything through the unified workflow:

```bash
python3 scripts/corenet-analyze.py --capture capture.pcap --domains epc \
  --work-dir /tmp/corenet-work --output-dir /tmp/corenet-report
```

## Session control

```bash
python3 scripts/analyze_epc_session.py \
  --gtpv2 gtpv2-events.jsonl \
  --transactions gtpv2-transactions.json \
  --output epc-session-analysis.json
python3 scripts/epc_session_timeline.py epc-session-analysis.json --format text
```

The session-control path consumes the accepted `gtpv2` Protocol Skill output. It
reports protocol outcomes (`RESPONSE_ACCEPTED_OBSERVED`, `RESPONSE_REJECTED_OBSERVED`,
`RESPONSE_OUTCOME_UNKNOWN`, `OPEN_REQUEST`, `RESPONSE_ONLY`,
`AMBIGUOUS_TRANSACTION`) separately from the correlation status, keeps message and
bearer Cause apart, and groups transactions only on a resolved interface plus a
directed endpoint pair plus a shared control-plane TEID.

It never links S11 to S5/S8, never links an Attach UE to a GTPv2-C session, and
never claims PDN, bearer or user-plane success. See
`references/session-control.md`.

## Default bearer

```bash
python3 scripts/analyze_epc_default_bearer.py \
  --nas nas-eps-events.jsonl \
  --s1ap s1ap-events.jsonl \
  --attach epc-attach-analysis.json \
  --session epc-session-analysis.json \
  --gtpv2 gtpv2-events.jsonl \
  --output epc-default-bearer-analysis.json
python3 scripts/epc_default_bearer_timeline.py epc-default-bearer-analysis.json
```

The default-bearer path consumes already-extracted ESM, E-RAB and GTPv2-C
tunnel-endpoint evidence. It reports staged PDN connectivity and default bearer
activation with explicit `UNAVAILABLE_PROTECTED` handling, typed ESM negative
deviations, and identity links classified `ESTABLISHED` / `SUPPORTED` /
`AMBIGUOUS` / `NOT_ESTABLISHED`. It never claims that a bearer carries user
traffic and never equates an E-RAB identity with an EPS bearer identity.

## S1-U observation

```bash
python3 scripts/analyze_epc_s1u.py \
  --gtpu gtpu-events.jsonl \
  --streams gtpu-streams.json \
  --default-bearer epc-default-bearer-analysis.json \
  --gtpv2 gtpv2-events.jsonl \
  --output epc-s1u-observation.json
python3 scripts/epc_s1u_timeline.py epc-s1u-observation.json
```

The S1-U path consumes already-extracted GTP-U evidence. It reports directed
streams with observed G-PDU and payload-octet counts and relates a stream to a
bearer only on receiving-endpoint equality (outer destination address plus header
TEID against an advertised S1-U F-TEID). It never claims UE delivery, service
success or application reachability, and it never republishes inner packet
content. See `references/s1u-observation.md`.

```bash
python3 scripts/analyze_epc_bearer_lifecycle.py \
  --gtpv2 gtpv2-events.jsonl \
  --transactions gtpv2-transactions.json \
  --s1u epc-s1u-observation.json \
  --gtpu gtpu-events.jsonl \
  --output epc-bearer-lifecycle-analysis.json \
  --timeline-output epc-bearer-lifecycle-timeline.jsonl
```

The lifecycle path consumes already-extracted GTPv2-C evidence and its accepted
transaction correlation. It classifies repeated S1-U F-TEID advertisements into
advertisement families, publishes bounded generation observations with scoped
pseudonymous references, and attributes observed G-PDUs to a generation from
frame-level events with conserved packet and octet accounting. A generation closes
only when one matched, corroborated release transaction in the same capture names
both the released endpoint and the same control-plane context, with the outcome
read from the contract field `message_cause` of its correlated response; evidence
is keyed by capture, frame and message occurrence, so a same-numbered frame in
another capture never supplies a Cause or a context; initiation and
confirmation frames are published separately and the exact release-effective frame
is never claimed. Packets inside a pending release interval stay unresolved, and an
unresolved attribution is neither packet loss nor a tunnel failure. See
`references/bearer-lifecycle.md` and `references/advertisement-family.md`.

## What it reports

| Evidence | Detail |
| --- | --- |
| Procedure instances | One per UE context and Attach attempt, with a pseudonymous reference |
| Stages | attach-initiation, identity, authentication, security-mode, attach-decision, attach-completion, s1-context-setup, context-release |
| Observations | Attach request/accept/complete, authentication response, security mode complete, S1 context response, context release, identity exchange |
| Deviations | Attach reject (with EMM cause), authentication failure/reject, security mode reject, S1 context setup failure, protected inner message, insufficient terminal evidence |
| Limitations | Protected envelopes, partial captures, unbound and ambiguous NAS evidence |

## What it does not do

No ESM decoding, no bearer or PDN state, no user-plane validation, no root cause, no
global failure boundary, no subscriber identity. See `SKILL.md`.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Analysis written with at least one procedure instance |
| 5 | Malformed input or missing provenance |
| 6 | Analysis written but no Attach procedure instance formed |
| 7 | Output failure, including a refused overwrite |

## Version

0.6.1
