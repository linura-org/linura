# ADR 0015 — Isolated and independently reproducible release builds

- **Status:** Accepted
- **Date:** 2026-08-30

## Context

Linura already follows a proof-first, tag-last release model and promotes the exact bytes produced by Trusted Release Proof. As Linura moves toward externally consumable system artifacts, the build itself becomes a security and trust boundary: a correct source SHA is insufficient if build instructions, runner assumptions, environment drift, or publication-time rebuilding can change the resulting bytes.

The previous proof workflow performed validation, construction, attestation and orchestration in one workflow. That was functional but made the trusted builder harder to reason about as a distinct least-privilege capability and provided no independent byte-for-byte reproduction requirement.

## Decision

Linura adopts a repository-owned reusable trusted-build boundary:

1. `.github/workflows/reusable-release-build.yml` is the canonical release builder and is invoked only by an already-authorized Trusted Release Proof;
2. the builder receives only the exact source SHA, canonical release tag and version needed to construct the candidate;
3. the trusted build runs on the pinned `ubuntu-24.04` runner family with Rust `1.98.0` and target `x86_64-unknown-linux-gnu`;
4. dependencies remain locked and incremental compilation is disabled;
5. `SOURCE_DATE_EPOCH`, locale, timezone and source-path remapping form the deterministic build envelope;
6. the builder records its effective environment in `BUILD-ENVIRONMENT.json` and seals that record into release evidence;
7. the builder constructs the promotable payload once and creates build-provenance attestations for that exact payload;
8. a separate fresh runner rebuilds the same source and must reproduce every distributable binary byte-for-byte before Trusted Release Proof may succeed;
9. the reusable builder has no repository-content write, tag, or GitHub Release publication authority;
10. release-stage handoffs use explicit authenticated `workflow_dispatch` messages. The normal Release Authorization → Trusted Release Proof edge explicitly dispatches and binds exact-SHA permanent gates before directly dispatching proof. `workflow_run` remains only as a compatibility observer boundary (`CI`/`Security`/`CodeQL` → Release Proof Dispatch) for independently emitted native push gates; it is not required for token-authored automation handoffs and never chains release authority implicitly.

This decision intentionally makes **no SLSA Build Level 3 claim**. The reusable builder definition is stored in and loaded from the same reviewed source revision as the release candidate. It therefore improves capability separation, provenance, determinism and reproducibility, but it is not an independently governed immutable builder definition. A future SLSA Level 3-oriented design would require that stronger governance boundary to be specified and reviewed separately.

## Trust boundary

Authorization and construction are deliberately separate capabilities:

```text
protected release intent
  -> exact-SHA permanent gates
  -> proof authorization
  -> repository-owned reusable trusted builder
  -> independent binary reproduction
  -> proof completion
  -> promotion
  -> publication
```

The builder can read the selected source and emit evidence/artifacts. It cannot select another source, mutate repository contents, create a version tag, or publish a GitHub Release. Promotion and publication must independently verify the exact proof/source identity before receiving their own narrow authority.

Because the build workflow comes from the same source revision, review of a release-control change must evaluate both product source and build instructions together. Independent byte reproduction reduces nondeterminism risk but does not turn same-revision build instructions into a separately administered trust root.

## Failure behavior

The release fails closed if any of the following occurs:

- the selected source is no longer exact current `main` before proof authorization completes;
- the build modifies tracked source;
- the deterministic build envelope cannot be established;
- the independent runner produces a different distributable binary;
- the proof artifact, receipt, evidence, checksum set or provenance does not match the selected source;
- a later stage receives a stale or mismatched proof identity.

No failure in this path is repaired by retargeting an existing version tag. If source or build-control changes are required, merge the correction and create a fresh release intent.

## Alternatives considered

### Keep the build inline in Trusted Release Proof

Rejected because it conflates authorization and construction and makes the builder harder to reason about as a least-privilege capability.

### Rebuild during publication

Rejected because the released bytes could differ from the bytes that were tested, sealed and attested.

### Trust one successful deterministic-looking build

Rejected because deterministic settings alone do not prove reproducibility. A second isolated rebuild provides direct evidence that the distributable binaries are stable under the declared envelope.

### Move the builder immediately to an independently governed immutable workflow

Deferred rather than rejected. That is the direction required for a stronger SLSA-style builder trust root, but it introduces another governed artifact/repository boundary and lifecycle. Linura remains standalone for now and will not claim that stronger level until the independent governance model itself is designed, reviewed and operationally justified.

## Consequences

- Release proof is more expensive than ordinary CI because it intentionally performs two release builds.
- Normal development remains unaffected; the extra cost occurs only for deliberate public-release candidates.
- Build-environment drift becomes visible in sealed evidence.
- A reproducibility regression blocks promotion before any immutable version identity is consumed.
- Release reviewers must treat changes to the reusable builder as release trust-boundary changes, not ordinary CI refactoring.
- The release architecture has a durable decision record for future changes to runner isolation, provenance, reproducibility, or builder authority.

## Rollback / replacement

If this design becomes operationally unsuitable, replace this ADR with a new reviewed ADR that preserves the core invariant: **the exact bytes published to users must be independently attributable to an authorized exact source and must not gain trust from an unreviewed publication-time rebuild**.
