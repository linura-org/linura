# vX.Y.Z — implementation theme

**Status:** immutable release contract; live publication state is external to this frozen document.
**Claim class:** Experimental
**Supported platform profiles:** none

## Outcome

Summarize the bounded result of this version.

## User-visible capability

Describe what a user/operator can actually do that this release claims.

## Implemented scope

Describe the implementation that supports the claim.

## Authority and security boundary

State privilege, identity, policy, secret, fail-closed and trust-boundary effects.

## Platform and hardware scope

Declare exactly which platform profiles/hardware tiers are supported by this claim, or explicitly say none.

## Persistence, migration and upgrade

State schema/migration impact, upgrade source versions, backup requirements and downgrade compatibility.

## Recovery and rollback

State recovery, compensation, snapshot/rollback and break-glass behavior. Explicitly call out unavailable recovery mechanisms.

## Compatibility boundary

State API/protocol/profile compatibility and any breaking changes.

## Required acceptance evidence

List the permanent exact-source evidence required before publication. Phrase requirements as timeless contract conditions rather than temporary live-state assertions.

## Known limitations and unsupported states

List meaningful unsupported environments, capabilities and failure modes.

## Explicit non-goals

State what this release deliberately does not claim.

## Traceability

Use PR references by default. Add full-SHA commit URLs when exact immutable provenance materially improves a security, migration, recovery, release-control or trust-boundary claim.

- Change summary. [PR #123](https://github.com/linura-org/linura/pull/123)
- Security-sensitive example.
  [PR #124](https://github.com/linura-org/linura/pull/124) ·
  [`0123456`](https://github.com/linura-org/linura/commit/0123456789abcdef0123456789abcdef01234567)

## Artifacts and supply-chain evidence

State required binaries, SBOM, checksums, attestations and any version-specific artifacts.

## Publication evidence

Publication state is intentionally external to this immutable contract. The protected release lifecycle must bind the exact source and sealed bytes to the version tag, publish the immutable GitHub Release, independently verify the published release, and only then record terminal evidence in the version's publication dossier and advance roadmap state.

Do not write temporary live-state phrases such as “release candidate”, “publication pending”, “publication evidence remains pending”, or “not yet released” into this frozen contract. The same bytes may become the immutable GitHub Release body.

## Next-version handoff

State what the next milestone can build on and what gaps remain intentionally open.
