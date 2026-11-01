# S18-2 — establish native NetworkManager observation

**Status:** Reserved development scope; implementation not yet delivered or qualified.
**Milestone:** v0.10.0 / S18-2.
**Profile:** `arch-hyprland-v1` (development).
**Authoritative source and current PR review base:** `wip/v010-s18-network`.

## Ownership and dependencies

This boundary follows `S18-1` and is independently reviewable. All actual development continues in WIP. This draft PR adds only the present non-executable scope document relative to WIP; its ancestry includes WIP source, which is **not** implemented by this PR diff.

Source of truth:
- [S18 ten-boundary plan](../workstreams/v010-s18-pr-decomposition.md) and [machine-checked decomposition](../../contracts/v010-s18-pr-decomposition.toml).
- [Proposed ADR 0048](../adr/0048-s18-networkmanager-authority.md).
- [Inactive NetworkManager operations design](../../contracts/v010-s18-design.toml).
- [S18 native acceptance](../qualification/v0.10.0-s18.md) and [adversarial security qualification](../qualification/v0.10.0-s18-security.md).

## Source ownership and anticipated file changes

- `crates/linura-linux-observation/src/` — source-owned implementation, related native fixtures and negative/regression tests as applicable.
- `crates/linura-observation-control/` — source-owned implementation, related native fixtures and negative/regression tests as applicable.
- `apps/linurad/src/` — source-owned implementation, related native fixtures and negative/regression tests as applicable.
- `apps/linura-firstboot/src/` — source-owned implementation, related native fixtures and negative/regression tests as applicable.

Affected requirements: `R18-OBS-01`, `R18-OBS-02`, `R18-OBS-03`.
Threat/failure fixtures: `T01`, `T02`, `T03`, `T04`, `T05`, `T06`, `T07`, `T08`, `T09`, `T10`, `T22`, `T27`, `T28`.

## Required implementation (not yet completed)

- [ ] Extend the existing canonical observer and coordinator, preserving manager/device resource aliases, daemon/CLI and First Boot behavior.
- [ ] Implement bounded typed manager, device, passive AP, saved/active profile, radio/rfkill, IPv4/IPv6, DNS and default-route observations with distinct unknown/stale states.
- [ ] Bind actual unique NetworkManager D-Bus owner, boot and stable device/profile epochs before accepting related snapshots; detect churn and duplicate identity.
- [ ] Enforce transport receive/decode byte and nesting budgets, list bounds and real query deadlines, not only post-decoding elapsed time.
- [ ] Keep all reads passive: no RequestScan, secret read, profile mutation, connection activation or new effect authority.

## Required evidence, acceptance and blockers

- [ ] unit-fuzz-device-ap-profile-ip
- [ ] level-a-real-networkmanager-system-bus
- [ ] existing-observation-control-and-firstboot
- [ ] Complete native boundedness, owner swap, dual-stack and malformed-provider evidence before calling S18-2 complete

## Architecture and explicit non-claims

- No new external-effect operation is authorized by this boundary.
- Reuse Linura Control's authenticated principal, canonical `ReconciliationPlan`, trusted risk floors, durable prepare/revalidation, narrow native mechanisms, independent verification and no-blind-replay recovery where applicable.
- Preserve S17 lock/protected input, S21 display/power/storage, existing manager/device query aliases, First Boot, and offline/no-model recovery. Do not grant provider, client, model or shell a parallel authority.
- This document is a **draft reservation only**. It changes no runtime, public API, executor, operation registration, test assertion, release status, evidence or support level. The absence of physical C/Q11 hardware remains a qualification blocker where relevant.

## Extraction and release boundary

Before leaving draft, extract the reviewed S18-2 implementation from the WIP reference without unrelated slice changes, internally review architecture/security/regressions, consolidate a cohesive commit, run canonical exact-head CI, Security, CodeQL and applicable native A/B/physical C qualification, resolve findings and complete final review. Final integration targets accepted `main` only after explicit retarget/extraction; do not merge WIP wholesale or mistake WIP-ancestor tests for this PR's independently accepted evidence.

The GitHub head branch name may still contain its historical pre-rebuild slice, which does not define this PR's scope. The previous head is preserved at `archive/pre-s18-rebuild-20261101-pr-268`.
