# S18-1 — model exact native network identities

**Status:** S18-1 identity-only code and adversarial tests implemented as a candidate; exact-head qualification and review pending.
**Milestone:** v0.10.0 / S18-1.
**Profile:** `arch-hyprland-v1` (development).
**Authoritative source and current PR review base:** `wip/v010-s18-network`.

## Ownership and dependencies

This boundary follows the v0.10 S16 prerequisite and is independently reviewable. All actual development continues in WIP. This draft PR now adds the core canonical identity implementation and adversarial unit tests plus this scope document relative to WIP. It does not claim or modify the existing WIP NetworkManager provider implementation.

Source of truth:
- [S18 ten-boundary plan](../workstreams/v010-s18-pr-decomposition.md) and [machine-checked decomposition](../../contracts/v010-s18-pr-decomposition.toml).
- [Proposed ADR 0048](../adr/0048-s18-networkmanager-authority.md).
- [Inactive NetworkManager operations design](../../contracts/v010-s18-design.toml).
- [S18 native acceptance](../qualification/v0.10.0-s18.md) and [adversarial security qualification](../qualification/v0.10.0-s18-security.md).

## Implemented candidate and architecture boundary

- `crates/linura-core/src/network_identity.rs`: strict canonical D-Bus system bus/unique owner identities bound to `BootId`; typed and bounded native object identity families.
- Exact device identity includes kernel namespace, ifindex, current owner epoch, canonical interface, nonzero native generation; checked inventory detects duplicate/recycled aliases and oversize inventories.
- AP identities bind the observed device and scan generation; profile revisions bind settings object, strict UUID, nonzero revision generation and non-secret fingerprint (including ABA protection); active connections bind exact device/activation instance and optionally a matching profile epoch.
- Fresh observation correlation checks refuse owner/bus/boot changes, future timestamps and expired evidence, without claiming atomic multi-object proof.
- No new provider mutation or active scan, no authority grant, secrets, policy, approval, registry, executor, D-Bus API or released capability. Native source attestation and all effect authorization stay in later S18 boundaries.
- Regression coverage is directly inside the core module, with explicit malformed, cross-epoch, collision, replacement and clock/age cases.

## Source ownership and anticipated file changes

- `crates/linura-core/src/` — source-owned implementation, related native fixtures and negative/regression tests as applicable.
- `crates/linura-linux-observation/src/` — source-owned implementation, related native fixtures and negative/regression tests as applicable.
- `contracts/stability.toml` — source-owned implementation, related native fixtures and negative/regression tests as applicable.

Affected requirements: `R18-OBS-02`, `R18-AUTH-01`.
Threat/failure fixtures: `T01`, `T03`, `T04`, `T05`, `T08`, `T11`, `T15`, `T24`, `T28`.

## S18-1 implementation acceptance (source candidate; CI still required)

- [x] Introduce exact typed boot, NM unique owner, interface/device, access point, active connection, saved profile revision and non-authorizing observed generation identities.
- [x] Reject interface-name, ifindex, SSID/BSSID, UUID and path aliases as standalone authority across replacement, restart, or namespace changes.
- [x] Define canonical bounded encodings, comparison and anti-replay equality, including ambiguous/unknown identities that cannot be used for effects.
- [x] Preserve existing read-only query names and avoid granting any runtime operation, Polkit approval or native D-Bus mutation.
- [x] Unit-test malformed, mixed-epoch, conflicting path, reused device and profile revision identities.

## Required evidence, acceptance and blockers

- [ ] typed-identity-adversarial-tests
- [ ] existing-core-compatibility
- [ ] No merge until exact-generation invariants and backward-compatible identity tests pass

## Architecture and explicit non-claims

- No new external-effect operation is authorized by this boundary.
- Reuse Linura Control's authenticated principal, canonical `ReconciliationPlan`, trusted risk floors, durable prepare/revalidation, narrow native mechanisms, independent verification and no-blind-replay recovery where applicable.
- Preserve S17 lock/protected input, S21 display/power/storage, existing manager/device query aliases, First Boot, and offline/no-model recovery. Do not grant provider, client, model or shell a parallel authority.
- This PR is **an implementation candidate**, not a reservation-only change. It adds the core Rust identity API and unit tests but changes no runtime observer, D-Bus protocol, privileged executor, operation registration, credential flow, release status or support level. The absence of physical C/Q11 hardware remains a qualification blocker where relevant.

## Extraction and release boundary

Before leaving draft, extract the reviewed S18-1 implementation from the WIP reference without unrelated slice changes, internally review architecture/security/regressions, consolidate a cohesive commit, run canonical exact-head CI, Security, CodeQL and applicable native A/B/physical C qualification, resolve findings and complete final review. Final integration targets accepted `main` only after explicit retarget/extraction; do not merge WIP wholesale or mistake WIP-ancestor tests for this PR's independently accepted evidence.

The GitHub head branch name may still contain its historical pre-rebuild slice, which does not define this PR's scope. The previous head is preserved at `archive/pre-s18-rebuild-20261101-pr-267`.
