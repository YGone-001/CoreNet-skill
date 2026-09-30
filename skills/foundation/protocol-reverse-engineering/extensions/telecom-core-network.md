# Telecom Core-Network Structural Investigation Context

## Method

Treat unknown signaling content as an evidence problem. Compare software or
specification versions, working and failing captures, and repeated messages at
equivalent observation points. Separate known fields from unknown regions;
record length/value boundaries, position, repetition, nesting, flags, and byte
order without assigning unsupported meaning.

TLV-style elements, grouped elements, bit fields, ASN.1-based encodings, and
AVP-style structures are useful structural categories. An unknown AVP-like
element can be characterized by code, flags, vendor identity if present, length,
position, and surrounding structure; that characterization is not a definition.
Consider dissector limitations, malformed input, unsupported versions, and
vendor extensions as hypotheses until evidence distinguishes them.

## Evidence-Safe Examples

- OBSERVED: A repeated unknown region has the same length in working samples.
- DERIVED: Its position follows a stable enclosing boundary.
- HYPOTHESIS: A version or vendor extension may explain the difference.
- NEXT EVIDENCE: Compare a capture with confirmed software and specification context.

## Handoff to Higher Layers

This method cannot define a protocol code, information element, AVP, or message
procedure. Future Protocol Skills provide authoritative protocol interpretation;
future Domain Skills evaluate the resulting procedure context.
