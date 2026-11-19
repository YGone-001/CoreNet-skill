# IMS session privacy

The Domain publishes only accepted, bounded evidence references and classifications.
It never publishes:

- raw Call-ID;
- From/To URI or Request-URI;
- From/To tags;
- Via branch or sent-by;
- Contact URI;
- subscriber identity, IMSI, IMPI, IMPU or MSISDN;
- Authorization, Proxy-Authorization, nonce or digest response;
- SIP body, SDP content or media parameters.

## Permitted evidence

- capture file name and SHA-256 of the accepted input artifacts;
- SIP Event, Transaction and Dialog references;
- method names, status codes, frame numbers and message occurrences;
- boolean and enum evidence classifications;
- bounded count and conservation metadata;
- attempt, branch, unbound and in-dialog observation references.

## Reference privacy

`ims-session:<capture>:<frame>.<occurrence>` is deterministic and capture-scoped. It is
not a subscriber identity and is not portable across captures. No persistent hash is
derived from a raw identity.

## Cross-protocol boundary

No registration-to-session association is derived from timestamps, addresses, frame
proximity, matching Call-ID-shaped values or similar protocol outcomes. Diameter Rx,
Sh and charging evidence is not integrated in this phase.

## Reporting

The text report publishes only references, statuses and bounded counts. Input raw SIP
identity remains in the accepted SIP Protocol artifacts and is never copied into the
Domain output.