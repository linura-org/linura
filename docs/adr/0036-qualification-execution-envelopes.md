# ADR 0036 — Bind qualification execution to versioned immutable envelopes

- **Status:** Accepted
- **Date:** 2026-10-05
- **Refines:** ADR 0022 repository-owned development and system-proof pipeline

## Context

Hosted runner labels, mutable package repositories, cache keys, and source SHA
alone do not identify the environment that executed a qualification lane.
Release builds already have stronger isolated reproduction guarantees, but
ordinary development and specialized qualification need a common identity model
without making false reproducibility claims.

Security freshness and physical observations are intentionally variable and
must not be frozen simply to obtain deterministic-looking results.

## Decision

Linura uses schema-versioned qualification execution envelopes. Schema v2 separates the orchestrating runner from the execution subject. A subject is exactly one of: the runner itself, a typed VM guest, or an aggregate that binds an exact component-envelope set.

Each appropriate lane declares a reviewed profile in
`contracts/qualification-execution-envelopes.toml`. Contract validation fails
if a declared hosted workflow is not wired to the repo-owned envelope action or
if the physical finalization entrypoint does not create and verify its envelope.
The envelope binds exact
source commit/tree with a fully clean tracked checkout whose declared tree,
stage-0 index entries, raw worktree bytes, and non-generated untracked/ignored paths are checked independently of Git clean filters and EOL conversion. Qualification identity commands resolve only reviewed absolute, root-owned, non-writable system executables under a minimal subprocess environment rather than inheriting caller `PATH` resolution. Repository-controlled
input digests verified against the declared Git commit, runner identity, OS
release and installed-package manifest,
toolchain/lockfile digests, required external image/config digests, verified
cache content, and explicitly separated variable observations. Observation
fields named with a `_sha256` suffix are schema-typed SHA-256 digests rather
than arbitrary strings.

Cache keys do not establish identity. A cache may contribute only after its
bytes are independently verified against the digest recorded in the envelope.
Old-source pass results, qualification evidence, and Linura build outputs are
not reusable merely because a cache matched.

RustSec advisory identity and retrieval time remain freshness observations.
VM-backed qualification records the GitHub runner as orchestrator and independently captures the guest machine identity from inside the guest. Its execution subject additionally binds the reviewed virtualization acceleration and every lane dynamic image digest, so derived/prepared images cannot be hidden behind an original base-image identity. Aggregate jobs bind component-envelope digests rather than claiming their own runner executed the underlying tests. Component collections are canonicalized by semantic identity before hashing, so their digest is set-stable rather than incidental-order-dependent. The v0.9 adversarial matrix therefore emits one envelope per executing shard from a reviewed eight-shard schema inventory, writes the canonical component list as a separate execution-context manifest, and emits a separately bound aggregate. Downstream qualification independently recomputes that shard-set digest before using the aggregate as an execution subject. This layer never mutates qualification evidence or release receipts to accept an envelope; evidence acceptance is a separate authority boundary.

Physical workstation envelopes require physical machine/fixture identity,
reject hosted image identity and virtualization, and do not allow a cloud VM to
claim Q11 execution context.

An envelope is context, not success. Its SHA-256 is a content identifier, not a
signature or independent authenticity proof. Evidence acceptance and release
authority remain separate boundaries and must bind the envelope digest through
their own trusted provenance.

## Consequences

- Environment drift becomes explicit and machine-checkable.
- Cache substitution cannot silently change a qualified environment.
- Fresh security data remains fresh rather than pinned for reproducibility.
- Graphical and hardware evidence can bind environment identity without claiming
  byte-identical observations.
- Lane profile changes are contract changes and require review and new exact-head
  qualification.
