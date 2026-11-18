# Diameter IMS Cx/Dx context

## Role of this Domain Skill

The registration Domain consumes the accepted `diameter-ims` analysis document. It
does not decode Diameter packets, rematch Requests and Answers, or reinterpret AVPs.
The Diameter observations retain independent protocol semantics.

## Supported registration-related commands

| Command | Code | Procedure context |
| --- | --- | --- |
| UAR/UAA | 300 | User authorization and registration-state query |
| SAR/SAA | 301 | Server assignment and related registration data |
| LIR/LIA | 302 | Location information, not a mandatory registration stage |
| MAR/MAA | 303 | Multimedia authentication |
| RTR/RTA | 304 | Registration termination |
| PPR/PPA | 305 | Profile push where registration context is relevant |

The model does not require UAR, MAR and SAR to appear in every registration attempt.
Initial registration, re-registration, de-registration and recovery cases have
different legitimate sequences.

## Retained evidence

For each relevant observation:

- source Diameter observation reference;
- Diameter transaction reference;
- command code and name;
- application ID from the accepted capability block;
- procedure family;
- `MATCHED`, `OPEN_REQUEST`, `RESPONSE_ONLY` or `AMBIGUOUS`;
- application result;
- Base or Experimental-Result namespace and reviewed numeric/name evidence;
- source event references;
- capture identity;
- observation limitations and `not_confirmed`.

AVP values are not republished. The inventory is an observation inventory, not a
registration verdict.

## Result semantics

A UAA, MAA or SAA success is an observed Diameter application result. None proves the
final SIP REGISTER outcome independently. A negative Diameter result does not identify
the affected SIP attempt unless a valid association exists.

Result names follow the accepted `diameter-ims` Release 19 registry. Unassigned
experimental codes and wrong Vendor-ID cases remain unresolved; they are not mapped to
invented names.

## Optional input behavior

- Diameter input is optional and a SIP-only analysis is complete.
- Missing Diameter input is recorded as `NOT_SUPPLIED`, not as a protocol failure.
- A supplied invalid artifact is an input error and is not silently converted into
  absence.
- An artifact with no registration-related commands is
  `NOT_OBSERVED_IN_SUPPLIED_ARTIFACT`.

## Cross-protocol boundary

Same capture filename, timestamp range, frame proximity, address, request count,
protocol success status or a SIP 401 near a MAA does not prove a SIP-to-Diameter
association. The registration Domain publishes `NOT_ESTABLISHED` and
`SUBSCRIBER_IDENTITY_BRIDGE_UNAVAILABLE` unless a future accepted identity bridge
exists. No bridge is introduced here.