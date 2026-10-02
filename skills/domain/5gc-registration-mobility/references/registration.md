# Registration Stage Reference

Bounded registration-stage behavior for version 0.1.0, grounded in the
reviewed TS 23.502 registration procedure and the TS 24.501 semantics
supplied by the nas-5gs Skill.

## Initiation

NGAP InitialUEMessage and/or the NAS Registration request start a
procedure instance. The InitialUEMessage frame carries the RAN-UE-NGAP-ID
(NGAP Skill extraction); the same-frame NAS record joins through shared
packet provenance. The 5GS registration type supplied by nas-5gs
(initial, mobility updating, periodic updating, emergency) is recorded
as a field finding and never treated as an outcome.

## Identity branch (conditional)

Identity request triggers the branch; Identity response completes it.
The response's identity type (SUCI, 5G-GUTI, and similar) is preserved
as an opaque type finding; no identity value is carried and SUCI is
never treated as SUPI.

## Authentication branch (conditional)

Authentication request triggers the branch. Its defined outcomes are
Authentication response (successful path), Authentication reject,
Authentication failure, and Authentication result where supplied.
Reject and failure are protocol-defined terminal observations for the
branch: the 5GMM Cause supplied by nas-5gs is preserved as a field
finding. The analyzer never concludes SIM, UDM, AUSF, or AMF defects
from these observations alone.

## Security mode branch (conditional)

Security mode command triggers the branch; Security mode complete or
Security mode reject are the observed outcomes. Selected NAS ciphering
and integrity protection algorithms, when supplied by nas-5gs, are
recorded as protocol-level field findings; no cryptographic assessment
is performed. A command with neither outcome visible in the observation
window is a missing-expected-counterpart deviation, never an
implementation failure.

## Decision

Registration accept and Registration reject are the decision
observations. Reject carries the 5GMM Cause (code and reviewed name
from nas-5gs) as a field finding; it is a protocol-defined terminal
observation for the procedure, never implementation blame. Accept
activates the completion expectation.

## Completion

Registration complete after accept closes the registration procedure.
Completion evidence is tracked separately from everything that happens
later on the N2 interface.

## What this reference does not cover

Handover, path switch, N2 context modification, PDU session
establishment (5GSM), and emergency-registration specifics are outside
version 0.1.0. Unsupported or unknown lower-layer messages are reported
with the UNKNOWN_OR_RESERVED deviation and limit interpretation.
