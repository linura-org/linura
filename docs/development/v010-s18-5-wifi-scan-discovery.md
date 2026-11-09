# S18-5 — add bounded Wi-Fi discovery and scan authority

**Status:** Reserved development scope; feature not implemented or qualified by this PR.
**Milestone:** v0.10.0 / S18-5.
**Profile:** `arch-hyprland-v1` (development).
**Authoritative reference / draft PR base:** `wip/v010-s18-network` at `63265739f8a62f2e7a7d3c665d7c9af7f8946537`.

## Ownership and dependencies

This S18 feature is independently reviewable after S18-2, S18-3, S18-4. Actual source development happens only on WIP; this draft PR contains **one scope document** as its own diff against WIP. Neither an ancestor implementation nor green WIP development checks qualify a new effect.

Normative WIP sources:
- [Phase-1 S18 architecture](../workstreams/v010-s18-network-phase1.md), [ten-part implementation plan](../workstreams/v010-s18-pr-decomposition.md), [machine-checked breakdown](../../contracts/v010-s18-pr-decomposition.toml).
- [NetworkManager authority ADR 0048](../adr/0048-s18-networkmanager-authority.md), [inactive candidate operations](../../contracts/v010-s18-design.toml).
- [Native qualification](../qualification/v0.10.0-s18.md), [adversarial qualification](../qualification/v0.10.0-s18-security.md).

## Source ownership, requirements and negative cases

- `crates/linura-linux-observation/src/` — feature-specific source, typed API and associated positive/adversarial native tests as applicable.
- `crates/linura-control/` — feature-specific source, typed API and associated positive/adversarial native tests as applicable.
- `crates/linura-policy/` — feature-specific source, typed API and associated positive/adversarial native tests as applicable.

Requirements: R18-OBS-03, R18-AUTH-01, R18-AUTH-02, R18-SEC-01.
Required negative cases: T02, T03, T05, T06, T07, T11, T12, T13, T14, T15, T16, T19, T20, T22, T23, T28, T29.

## Required implementation (not yet completed)

- [ ] Keep passive AP result observation separate from active RequestScan radio emission and permission-sensitive action.
- [ ] Bind scan authorization to exact adapter/owner/session and a reviewed non-downgradable operation floor.
- [ ] Limit native scan attempts, frequency, payloads, power/airplane mode interaction and privacy leakage.
- [ ] Verify fresh scoped scan completion without treating cached AP list, methods or signals as proof.
- [ ] Deny when rfkill, stale owner, missing authorization, foreign caller, timeout or uncertain effect makes scan unverifiable.

## Acceptance evidence (not yet established)

- [ ] real-nm-wifi-scan-negative-tests
- [ ] rate-and-payload-budget
- [ ] rfkill-owner-swap-no-replay
- [ ] Native authenticated RequestScan and exact-freshness oracle still unqualified

## Security, recovery and explicit non-claims

- Candidate operations: `operation:network.wifi.scan`; none are enabled, registered or qualified.
- Preserve the real user/session/Polkit subject, canonical Control plan, trusted risk floor, bounded native effects, independent verification, durable indeterminate/no-replay recovery, S17 protected session, S21 device safety, and offline local recoverability.
- No generic D-Bus/nmcli/shell or model/GUI command execution; reject unknown/stale/incomplete identity, owner replacement, last viable link loss and replay.
- This Markdown reservation contributes no runtime authority, client UI, feature flag, operation registry, privilege, physical Q11 proof or released support. The prior PR branch name does not define this feature.

## Implementation extraction and eventual release

Implement the full capability in the WIP source. After internal architecture, regression, security and adverse-case review, extract only this feature into an independently reviewable commit, test canonical exact-head CI, fresh Security and CodeQL, native real-NM A/B/physical C and required inherited gates, and resolve final Codex findings. For eventual integration, rebase/retarget to accepted `main` only once extraction and evidence are complete; never merge the WIP branch wholesale.

Original reserved head: `archive/pre-s18-rebuild-20261101-pr-271`; retained GitHub PR head name: `feat/v010-s26-1-library-queries`.
