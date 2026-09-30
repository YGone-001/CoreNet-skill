# Foundation Skills

Six CoreNet Foundation wrappers are implemented: `wireshark-analysis`,
`protocol-reverse-engineering`, `network-engineer`, `systematic-debugging`,
`linux-troubleshooting`, and `c-pro`. Each preserves its audited upstream source
under `upstream/` and remains independently usable.

All six wrappers include telecom-core-network extensions for investigation
methodology only. Protocol Skills retain responsibility for semantics, and the
audited upstream snapshots remain immutable.

The Foundation layer is the accepted investigation-method baseline. Future
Protocol and Domain work should depend on it rather than expanding Foundation
ownership; focused bug fixes remain permitted.
