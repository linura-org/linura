# Linura v0.6.0 — terminal release record

**Status:** released; immutable GitHub Release published and independently verified.
**Claim class:** Experimental
**Published:** 2026-09-06T15:36:34Z
**Release ID:** `383633879`
**Release source:** `c4343fbd30cb67efb1ef0164ee84b8ba9e95c695`

## Release outcome

Linura v0.6.0 is the first released milestone that integrates the complete eleven-stage managed-mutation lifecycle for one deliberately narrow Experimental external effect: active/inactive convergence for canonical `linura-managed-*.service` systemd units.

The release does not widen that bounded claim into generic system management, arbitrary shell/command execution, package/file/network mutation, unattended agent authority, a supported Linux distribution, or production readiness.

## Publication and verification

The repository-defined proof-first/tag-last lifecycle completed successfully:

- Trusted Release Proof: run `34041955809` — success;
- Release Promotion: run `34042733913` — success;
- Release publication: run `34042741803` — success;
- immutable GitHub Release: `v0.6.0`, release id `383633879`;
- independent Release Verification: run `34052040327` — success;
- post-release closure advanced the machine roadmap to `current_release = "v0.6.0"` and `next_release = "v0.7.0"`.

The immutable `v0.6.0` tag and GitHub Release remain bound to source commit `c4343fbd30cb67efb1ef0164ee84b8ba9e95c695`.

## Frozen-contract distinction

[`v0.6.0.md`](v0.6.0.md) is the exact **frozen pre-publication release contract** that was sealed into the release payload. It intentionally remains byte-for-byte unchanged after publication.

Because the GitHub Release is immutable and its body was copied from that frozen contract, the published body permanently contains historical pre-publication wording including “release candidate” and “publication evidence remains pending.” Those phrases describe the release contract at authorization time; they are not the current release state.

This terminal release record, [`../qualification/v0.6.0-publication.md`](../qualification/v0.6.0-publication.md), and `contracts/roadmap.toml` are the authoritative current-state surfaces.

## Claim boundary retained

v0.6.0 remains **Experimental**. Its released boundary is unchanged:

- `executor_state = "integrated-narrow"`;
- `complete_lifecycle = true`;
- `managed_mutation_support = "narrow-experimental"`;
- `platform_support = "none"`;
- `agent_role = "none"`.

Publication and post-release closure do not convert the release into a Stable or production-ready product claim.

## Next milestone

The canonical roadmap is ready for `v0.7.0`: persistent intent lifecycle and the local Linura Library. v0.7 must preserve v0.6's exact authority binding, fail-closed ambiguity handling, independent verification, narrow executor boundary, and proposal-only agent/model authority.
