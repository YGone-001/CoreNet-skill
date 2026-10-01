# Foundation Acceptance Record

## Accepted baseline

The accepted Foundation Skill set is `wireshark-analysis`,
`protocol-reverse-engineering`, `network-engineer`, `systematic-debugging`,
`linux-troubleshooting`, and `c-pro`. Each package is version `0.2.0`, remains
independently usable, and has no required CoreNet Skill dependency.

The acceptance baseline before this record is
`73a91d6dbcc95a9b8e1eb107181100813fcabecb`.

## Provenance and integrity

The embedded source snapshot is from
[`sickn33/agentic-awesome-skills`](https://github.com/sickn33/agentic-awesome-skills)
at commit `465ad05638fbe1d9e7f98671393396b6d9246393` under the MIT License.
The staged snapshot and every package-local `upstream/` copy are verified by
their committed SHA-256 integrity records. The upstream commit and raw source
bytes are frozen for this accepted Foundation baseline.

## Frozen architecture boundary

Foundation answers: **How should we investigate?**

Protocol answers: **What does the protocol message mean?**

Domain answers: **How does the telecom procedure work?**

Implementation answers: **How is it implemented in concrete software?**

Orchestration answers: **Where did the end-to-end procedure first become abnormal?**

Foundation therefore owns reusable investigation methods only. It does not own
protocol message semantics, EPC/IMS/5GC procedure state, or product-specific
source mappings. The telecom core-network extensions provide bounded
investigation context and hand off those questions to future higher-layer
Skills.

## Evidence and standalone contract

Foundation output preserves `OBSERVED`, `DERIVED`, `INFERRED`, `HYPOTHESIS`,
and `CONFIRMED` distinctions. It reports defensible evidence boundaries rather
than unsupported causal conclusions.

Each accepted package contains its contract, local upstream snapshot,
provenance record, integrity manifest, and telecom extension. It has no runtime
dependency on the repository root, `third_party/`, `docs/`, or `shared/`.

## Acceptance validation

Acceptance uses the repository, upstream snapshot, and Foundation validators;
the unit-test suite; Python compile checks; whitespace checks; and standalone
package simulation. GitHub Actions runs the same committed-state validation in
`.github/workflows/validate.yml` on pushes to `main` and pull requests targeting
`main`.

## Deferred layers

Packet normalization, protocol semantics, Diameter, EPC/IMS/5GC procedures,
implementation mappings, and end-to-end orchestration remain future work. The
Foundation freeze permits focused bug fixes, but later layers must depend on the
accepted Foundation boundary instead of expanding its ownership.

## Architecture evolution note

A later repository architecture correction introduced the Correlation layer
between Protocol and Domain/Procedure, formalizing the six-layer dependency
direction Foundation → Protocol → Correlation → Domain/Procedure →
Implementation → Orchestration. This changes nothing about the accepted
Foundation contract recorded here: the Foundation packages remain unchanged at
version 0.2.0 with their original acceptance baseline
(`73a91d6dbcc95a9b8e1eb107181100813fcabecb`), and Foundation responsibility
remains "How should we investigate?" The note is additive so the Foundation
acceptance history stays traceable as it was accepted.
