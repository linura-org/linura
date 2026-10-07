# ADR 0037: Envelope-bound qualification evidence

**Status:** Accepted

## Context

Execution envelopes prove what ran, not whether retained qualification evidence
may be accepted. A second deterministic authority boundary is required to stop
stale-source, cross-lane, cross-envelope and post-verification artifact
substitution.

## Decision

Use a versioned evidence-binding contract with a reviewed per-lane artifact
inventory. A repository-owned verifier rechecks the primary result and hashes
the complete required artifact set. Its result binds the exact source/tree,
execution-envelope digest, artifact-set digest, verification class, and verifier
implementation/contract digests. Evidence binding succeeds only when that
verifier result still matches the current bytes.

The evidence layer consumes but never mutates execution envelopes. It grants
neither publication nor release authority.

Trusted release proof and maintained-hardware Q11 are explicitly non-evidence
at this layer: release proof remains its own authority, and Q11 cannot be
fabricated before its real physical evidence path is complete.

## Consequences

A green workflow conclusion cannot promote itself into evidence. A verifier
result for one byte set cannot be replayed over another byte set. Missing
profile-required artifacts fail closed, and changes to evidence admission
trigger every evidence-bearing workflow through static integration checks.
