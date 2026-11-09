# S18-5 — add bounded Wi-Fi discovery and scan authority

**Status:** Partial S18-5 implementation under exact-head testing; still Draft and not qualified. No `RequestScan` effect is enabled or dispatched.
**Milestone:** v0.10.0 / S18-5.
**Profile:** `arch-hyprland-v1` (development).
**Review base:** S18-4 / PR #270 (`feat/v010-s25-1-preference-authority`). **Historical integrated development reference:** `wip/v010-s18-network`. Work in this PR branch, not duplicate WIP implementation.

## Ownership and dependencies

This S18 feature is independently reviewable after S18-2, S18-3, S18-4. S18-5 source development occurs on its isolated PR branch; WIP is frozen as a comparison snapshot. Its new pure Control preflight cannot grant or dispatch anything. Until real original-subject Polkit, native NetworkManager and independent verification evidence are established, the effect remains unsupported.

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

## Implementation and remaining gates

- [ ] Keep passive AP result observation separate from active RequestScan radio emission and permission-sensitive action.
- [ ] Bind scan authorization to exact adapter/owner/session and a reviewed non-downgradable operation floor.
- [x] Add a pure, non-authorizing scan preflight (`crates/linura-control/src/wifi_scan.rs`) rejecting unsafe radio/rfkill/session conditions, directed probes, premature repeat scans, ambiguous prior attempts and malformed clock evidence. Only empty `RequestScan` options are represented; no secret/SSID probe options or arbitrary settings map can reach an executor.
- [ ] Bind the above to the *durably authenticated* Control subject and managed attempt ledger, exact live native device and session/seat; the current preflight accepts caller-supplied facts solely for adversarial unit testing and is NOT authority.
- [ ] Implement independently authorized, owner-pinned native `RequestScan`, including pre-allocation D-Bus receive budgets, actual rate limiting, transport deadlines, cancellation and zeroization where applicable.
- [x] Add a pure post-observation correlation check: owner/device epochs, increasing observation generation, and strictly newer bounded `LastScan` boot-time; this cannot be used as proof of effect completion.
- [ ] Verify real fresh scoped native scan postconditions and durable attempt/receipt binding; cached AP lists, method replies, and signals are never sufficient.
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

Implement S18-5 on this independent PR branch, preserving one consolidated review commit. Qualify its exact-head canonical CI, Security, CodeQL, real-NM A/B native behavior, adversarial rfkill/owner-swap/no-replay, and physical C/Q11 when applicable. WIP is a frozen development reference, not a second implementation source. No feature or release promotion before requirements and evidence are accepted. For eventual integration, rebase/retarget to accepted `main` only once extraction and evidence are complete; never merge the WIP branch wholesale.

Original reserved head: `archive/pre-s18-rebuild-20261101-pr-271`; retained GitHub PR head name: `feat/v010-s26-1-library-queries`.
