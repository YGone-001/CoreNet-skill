# cross-protocol-evidence

## Purpose

Combine independent protocol observations into a unified evidence
timeline. This Correlation-layer capability joins already-extracted NGAP
and NAS-5GS detailed events by shared capture provenance and answers one
question: what protocol observations belong together? It does not
answer what happened in the network.

## Scope

- Join protocol events on the primary provenance key
  (capture_file + frame_number) with deterministic STRONG grouping.
- Chain events within one capture whose adjacent timestamps stay inside
  a documented bounded window into MEDIUM groups.
- Keep capture-only events as WEAK single-event groups; weak evidence
  is never merged automatically.
- Preserve embedded protocol events verbatim as foreign evidence,
  including NGAP UE-context identifiers; never parse, rename, or
  interpret them.
- Surface missing protocol sources per group (NGAP present but NAS-5GS
  missing, and the reverse) as missing evidence, not failure.
- Emit deterministic correlation-event JSONL and a unified
  observed-evidence timeline in text or JSON.

## Non-Goals

- No PCAP, NAS, or NGAP parsing; protocol Skills remain authoritative.
- No subscriber, session, or registration correlation; no
  subscriber_id/imsi/supi fields exist here.
- No registration success or failure determination, no PDU session
  state, no state machine.
- No AMF/gNB diagnosis, no implementation mapping, no root cause; the
  output carries no root_cause/status/success/failure fields.
- No cryptographic or sensitive-data handling: sensitive input fields
  are rejected, never redacted-and-passed.

## Inputs

- NGAP detailed event JSONL produced by the ngap Protocol Skill
  (--ngap-events, repeatable).
- NAS-5GS detailed event JSONL produced by the nas-5gs Protocol Skill
  (--nas-events, repeatable).
- Each event must carry timestamp, frame_number, and capture_file;
  events containing sensitive identity or authentication-secret fields
  are rejected. NGAP event JSONL alone is not sufficient for NAS
  semantics and NAS JSONL alone is not sufficient for NGAP semantics;
  this layer joins them without decoding either.

## Outputs

- scripts/correlate-events.py --ngap-events FILE [--nas-events FILE ...]
  --output groups.jsonl [--window-seconds 1.0] — correlation-event JSONL
  per schemas/correlation-event.schema.json.
- scripts/evidence-timeline.py groups.jsonl [--format text|json] —
  unified observed-evidence timeline listing what was observed together
  and which protocol source is missing per group.

## Dependencies

None required. Optional: ngap >=0.1.0, nas-5gs >=0.1.0,
core-network-pcap >=0.1.0 as upstream event producers. Standalone: the
package needs nothing outside its own directory at runtime.

## Workflow

1. Obtain detailed protocol events from the authoritative Protocol
   Skills for the same capture.
2. Run correlate-events.py on the event files; verify every input event
   carries provenance fields and no sensitive material.
3. Read groups by strength: STRONG (same capture and frame), MEDIUM
   (same capture, adjacent timestamps within the bounded window), WEAK
   (single event, capture context only).
4. Render the timeline; treat missing protocol sources as missing
   evidence under the capture boundary.
5. Hand combined evidence to future Domain Skills for procedure
   interpretation; this layer stops at what belongs together.

## Evidence Rules

- OBSERVED: the protocol events present in the input, verbatim.
- DERIVED: grouping, ordering, correlation strength, missing-source
  notes, timestamps ordering.
- INFERRED: not produced by this layer.
- HYPOTHESIS: not produced by this layer.
- CONFIRMED: not produced by this layer; no root cause is ever
  confirmed here.

## Failure Handling

Missing provenance fields, non-integer frame numbers, invalid
timestamps, sensitive fields, and empty inputs fail loudly with
non-zero exits (malformed input 5, no events 6, output failure 7).
Out-of-order timestamps are preserved as-is; ordering is derived, never
corrected. Duplicate events are kept as separate observations with
stable ordering. Capture-boundary uncertainty is preserved: absence
from the input is reported as missing evidence, not network behavior.

## Validation

Run python tests/test_cross_protocol_evidence.py from this package.
Repository checkouts also run scripts/validate-cross-protocol-evidence.py.

## References

references/correlation-model.md, references/provenance.md,
references/timeline-model.md, references/failure-boundaries.md.
