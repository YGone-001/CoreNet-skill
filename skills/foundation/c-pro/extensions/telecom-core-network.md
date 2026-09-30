# Telecom Core-Network C Engineering Context

## Defensive Systems Practice

For signaling software, apply general C safeguards: network byte order, integer
width, signed/unsigned boundaries, unaligned access, packed-structure hazards,
buffer-length validation, TLV-style and nested parsing safety, decoded-message
ownership, reference counting, callback lifetime, state-machine events, timers,
retransmission state, and defensive handling of malformed network input.

Use concise, allowlisted logging fields for reproducible diagnosis without
exposing sensitive payloads. Apply compiler warnings, ASan/UBSan, GDB, Valgrind,
and optional future fuzzing as evidence sources. These are generic implementation
practices; they do not map any protocol decoder, source tree, or product code.

## Evidence-Safe Examples

- OBSERVED: A sanitizer reports an out-of-bounds access for a malformed input.
- DERIVED: The reported offset exceeds the validated buffer length.
- HYPOTHESIS: A missing bounds check may be involved.
- NEXT EVIDENCE: Reproduce with a minimized authorized test input and validation trace.

## Handoff to Higher Layers

This Skill cannot identify what a telecom field means or which product function
owns a procedure. Future Protocol Skills provide field semantics; future
Implementation Skills provide source-specific mappings.
