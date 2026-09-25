# crates.io publishing

Linura publishes the canonical top-level Rust package `linura` from
`crates/linura`.

The first release, `0.0.1`, was intentionally published manually to establish
the crate and its initial named owner. It is the one-time bootstrap version. The canonical crate now inherits `workspace.package.version`, so every subsequent crates.io version is advanced by Linura's deterministic release-preparation step and matches the product release version before irreversible publication. Subsequent publication is part of
Linura's existing proof-first release lifecycle. There is no standalone
version-bump-to-registry authority path and no long-lived crates.io token.

## Authority path

The normal path is:

`release: ready`
→ protected release preparation and authorization
→ Trusted Release Proof
→ immutable GitHub Release
→ exact-tag independent Release Verification
→ crates.io candidate qualification without OIDC authority
→ OIDC-backed crates.io publication or checksum-equivalent idempotent reuse
→ independent crates.io checksum verification
→ Release Closure Handoff.

The `crates-io-publish.yml` workflow has no manual dispatch path. It starts only
from GitHub's persisted `workflow_run: completed` event for `Verify published
release`, downloads the verifier's bound evidence artifact, authenticates the
exact tag/source/event/ref identity (including the supported marker-only recovery
ref), requires the source to still be the current protected `main` tip, and
fails closed on drift.

## Trusted Publisher identity

Configure the `linura` crate on crates.io with exactly this GitHub Actions
publisher identity:

| Field | Value |
| --- | --- |
| Repository owner | `linura-org` |
| Repository name | `linura` |
| Workflow filename | `crates-io-publish.yml` |
| Environment | `crates-io` |

The filename is relative to `.github/workflows/`; enter only
`crates-io-publish.yml` in crates.io.

## GitHub environment

Create a GitHub Actions environment named `crates-io`.

For Linura's automatic-after-readiness release contract:

- restrict deployment to protected `main`;
- do not add a required human reviewer;
- do not store a crates.io API token or other registry credential.

The environment is an isolation boundary, not a second approval gate. The OIDC
job is reached only after independent release verification and a separate
no-OIDC qualification job have succeeded.

## Credential boundary

The qualification job has no `id-token: write` permission. It tests and
packages the exact verified source, hashes the resulting `.crate`, and uploads
that package plus bound evidence as a short-lived GitHub artifact.

Only the dependent publication job receives `id-token: write`. Before invoking
the crates.io authentication action it consumes and verifies the qualification
artifact, reproduces the package without executing crate code, and re-checks
that both protected `main` and the immutable release tag still identify the
same source. The official crates.io auth action is pinned to an immutable
commit and its short-lived credential is passed only to `cargo publish`.

Publication uses `cargo publish --no-verify` because build/test verification
already occurred in the no-OIDC qualification job. This prevents repository
build scripts or tests from running while publication authority is present.

## Idempotency and independent verification

Before authentication, the workflow queries crates.io for the manifest version.

- If the version does not exist, the exact qualified package is published.
- If the version already exists, its crates.io checksum must exactly match the
  qualified package checksum; otherwise the workflow fails.
- After either path, the registry checksum is fetched again and must match
  before release closure may proceed.

This makes retries safe without treating an already-published but different
immutable crate as success. It also forces a version bump when package bytes
change. The short-lived GitHub artifact is not the durable provenance record:
post-release closure commits the exact crates.io workflow run ID, crate version,
and package SHA-256 into both the publication dossier and terminal release record.

## Trusted Publishing Only

After the first successful OIDC-backed release, enable crates.io's
**Trusted Publishing Only** mode for `linura`. Traditional API-token
publication is then disabled while the configured Trusted Publisher remains
authorized.

Keep the original named owner on crates.io for ownership administration. A
GitHub team may also be added as a restricted team owner for organizational
continuity; team ownership does not replace the OIDC Trusted Publisher identity.

## Recovery

If the crates.io handoff fails, do not create a fallback registry token and do
not dispatch release closure manually as a substitute.

Check, in order:

1. the triggering release-verification run completed successfully and emitted its bound evidence artifact;
2. its source SHA still equals protected `main`;
3. the immutable release tag still resolves to the same source;
4. the Trusted Publisher owner/repository are `linura-org/linura`;
5. the Trusted Publisher workflow is `crates-io-publish.yml`;
6. the Trusted Publisher environment is `crates-io`;
7. the GitHub job uses the `crates-io` environment;
8. the package checksum agrees with any existing crates.io version;
9. the crates.io version is not yanked;
10. the exact successful crates.io workflow run and publication-evidence artifact are propagated into closure.

A changed source, evidence mismatch, registry mismatch or OIDC configuration
error stops the release rather than degrading to a weaker publication path.
