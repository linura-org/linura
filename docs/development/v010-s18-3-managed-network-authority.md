# S18-3 — add managed network authority semantics

**Status:** Reserved development scope; source implementation and qualification not delivered by this PR.
**Milestone:** v0.10.0 / S18-3.
**Profile:** `arch-hyprland-v1` (development).
**Reference branch and draft PR base:** `wip/v010-s18-network` at `63265739f8a62f2e7a7d3c665d7c9af7f8946537`.

## Ownership and dependencies

Depends on S18-1, S18-2. All development remains on WIP until each capability is independently extracted. This draft PR contributes only this non-executable planning document relative to WIP; inherited files are not claimed as this PR's implementation.

Authoritative WIP sources:
- [S18 Phase 1](../workstreams/v010-s18-network-phase1.md), [ten-part implementation decomposition](../workstreams/v010-s18-pr-decomposition.md), [machine-checked plan](../../contracts/v010-s18-pr-decomposition.toml).
- [NetworkManager ADR 0048](../adr/0048-s18-networkmanager-authority.md), [inactive design](../../contracts/v010-s18-design.toml).
- [S18 qualification](../qualification/v0.10.0-s18.md), [security dossier](../qualification/v0.10.0-s18-security.md).

## Intended source files and regression impact

- `crates/linura-control/` — owned implementation, relevant native fixtures, and positive/denial/adversarial regression tests.
- `crates/linura-policy/` — owned implementation, relevant native fixtures, and positive/denial/adversarial regression tests.
- `crates/linura-transaction/` — owned implementation, relevant native fixtures, and positive/denial/adversarial regression tests.
- `crates/linura-persistence-sqlite/` — owned implementation, relevant native fixtures, and positive/denial/adversarial regression tests.
- `contracts/operation-semantics.toml` — owned implementation, relevant native fixtures, and positive/denial/adversarial regression tests.

Relevant requirements: R18-AUTH-01, R18-AUTH-02, R18-REC-01.
Adversarial cases: T03, T05, T08, T09, T10, T12, T13, T14, T15, T18, T19, T20, T21, T24, T25, T26, T29.

## Required implementation (not yet completed)

- [ ] Define trusted typed operation classification and risk floors for all nine candidate effects; keep them inactive until feature-specific native qualification.
- [ ] Extend canonical reconciliation plans, exact principal/resource/epoch preconditions and bounded protected review of default-route/DNS impact.
- [ ] Persist prepare/attempt and indeterminate recovery through existing Control authority and SQLite; never mint grants from receipts or UI selections.
- [ ] Specify independently corroborated postconditions, no-change semantics and loss-of-control-path refusal with offline fallback.
- [ ] Test denial, replay, changed risk, ambiguous reply, crash recovery and route-impact conflicts without enabling unqualified effects.

## Required qualification and remaining blockers

- [ ] canonical-policy-negative-tests
- [ ] durable-attempt-recovery-and-enospc
- [ ] v06-managed-lifecycle-regressions
- [ ] All durable authorizations and recovery paths independently reviewed before native registration

## Explicit safety and support boundaries

- No native effect or operation is registered.
- Linura Control retains canonical risk classification, authenticated principal, `ReconciliationPlan`, durable prepare/verification and recovery authority. Native mechanisms must be narrow and fail closed.
- No arbitrary privileged D-Bus or shell passthrough, leaked secrets, session/seat alias grant, blind effect replay, or replacement of S17 lock/security and S21 device protections.
- This single Markdown file changes **no runtime, contract, policy, credential, test or release support behavior**. WIP's existing development checks are not evidence that a future effect passed exact-head native qualification.

## Acceptance and eventual release

Before review: implement the correct scoped code in WIP, internally verify consumers/security/negative cases, extract to an independently reviewable PR, consolidate a coherent commit, pass canonical CI, fresh Security/cargo-audit, CodeQL, applicable native A/B/C and inherited gates, resolve findings and complete final Codex review. Only then retarget/rebase toward accepted `main`; **never merge WIP wholesale**. Physical Q11 remains unsupported until actual maintained hardware evidence.

Historical PR head `feat/v010-s19-1-bluez-observation` is retained for GitHub continuity; its old version is archived as `archive/pre-s18-rebuild-20261101-pr-269`.
