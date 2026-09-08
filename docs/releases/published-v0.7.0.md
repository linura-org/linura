# Linura v0.7.0 — terminal release record

**Status:** released; immutable GitHub Release published and independently verified.
**Claim class:** Experimental
**Published:** 2026-09-07T06:12:10Z
**Release ID:** `383863574`
**Release source:** `73cd734319a212c4205b73d1626affae362a0a02`

## Release outcome

Linura v0.7.0 released **persistent intent lifecycle and local Linura Library** within its frozen Experimental claim. The release adds durable declarative intent, revisioned local Library objects, portable definitions, adoption dry-run, backup/recovery and failure-qualified persistence without widening the already-released privileged executor boundary.

## Publication and verification

The repository-defined proof-first/tag-last lifecycle completed successfully:

- Trusted Release Proof: run `34088636453` — success;
- Release Promotion: run `34089622924` — success;
- Release publication: run `34089656870` — success;
- immutable GitHub Release: `v0.7.0`, release id `383863574`;
- independent Release Verification: run `34161735811` — success;
- protected post-release closure advanced the machine roadmap to `current_release = "v0.7.0"` and `next_release = "v0.8.0"`.

The immutable `v0.7.0` tag and GitHub Release remain bound to source commit https://github.com/linura-org/linura/commit/73cd734319a212c4205b73d1626affae362a0a02.

## Frozen-contract distinction

[`v0.7.0.md`](v0.7.0.md) is the exact frozen release contract. It remains unchanged after publication. This terminal record, [`../qualification/v0.7.0-publication.md`](../qualification/v0.7.0-publication.md), and `contracts/roadmap.toml` are the authoritative current-state surfaces.

## Claim boundary retained

v0.7.0 remains **Experimental**. Its released boundary is unchanged:

- `executor_state = "integrated-narrow"`;
- `complete_lifecycle = true`;
- `managed_mutation_support = "narrow-experimental"`;
- `platform_support = "none"`;
- `agent_role = "none"`.

Publication and post-release closure do not convert the release into a Stable or production-ready product claim.

## Next milestone

The canonical roadmap is ready for `v0.8.0`: agent interpretation through typed `IntentProposal` generation. v0.8 agents remain proposal-only and must preserve the v0.7 durable intent/Library boundary plus the v0.6 policy, authorization, executor and independent-verification lifecycle.
