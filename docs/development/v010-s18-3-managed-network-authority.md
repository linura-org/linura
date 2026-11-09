# S18-3 — add managed network authority semantics

**Status:** Typed non-authorizing Control semantics implemented; exact-source qualification and final review pending.
**Milestone:** v0.10.0 / S18-3.
**Profile:** `arch-hyprland-v1` (development).
**Stacked review base:** S18-2 / PR #268, source `8314ed6e11e90c5c795da041617e460270297778` (until S18-2 is integrated).

## Ownership and dependencies

Depends on S18-1 and the exact typed NetworkManager identities from S18-2. The review diff is stacked on PR #268 to prevent copying or reintroducing its core identity implementation. The authoritative WIP remains the development reference, not a direct merge target.

Authoritative WIP sources:
- [S18 Phase 1](../workstreams/v010-s18-network-phase1.md), [ten-part implementation decomposition](../workstreams/v010-s18-pr-decomposition.md), [machine-checked plan](../../contracts/v010-s18-pr-decomposition.toml).
- [NetworkManager ADR 0048](../adr/0048-s18-networkmanager-authority.md), [inactive design](../../contracts/v010-s18-design.toml).
- [S18 qualification](../qualification/v0.10.0-s18.md), [security dossier](../qualification/v0.10.0-s18-security.md).

## Delivered implementation and regression impact

- `crates/linura-control/src/network_authority.rs` — nine typed, candidate-only managed operation descriptions, exact risk floors and source capabilities; immutable typed owner/device/profile/activation target correlation; authenticated Linux principal and interactive actor checks; original observed epoch and monotonic freshness; exact resource and single postcondition matching; bounded IPv4/IPv6 default-route and DNS impact plus offline-local recovery denial. All outcomes are **non-authorizing**.
- `crates/linura-control/src/lib.rs` — explicitly exports the read-only assessment API and no permit/dispatch capability.
- `crates/linura-control/src/managed_lifecycle.rs` — a second fail-closed S18 boundary before durable candidate/approval/prepare/executor entry, so a mistaken future registry or provider input cannot activate an unqualified network effect.
- `crates/linura-control/src/transient_effect.rs` — deny all `networkmanager` providers and `operation:network.*` IDs before transient planning, audit reservation or executor work. Adversarial tests demonstrate that an unrelated provider label cannot launder RequestScan or any network operation into transient dispatch.
- `contracts/operation-semantics.toml` — inert proposed network-operation authority contract (not runtime registration).
- This document and unit tests in the Control source verify the nine operation IDs match the S18 design and remain **absent from the trusted executable registry**, with exact type/epoch/owner/resource and route, risk and replay negative cases.

The new S18-3 API explicitly does **not** accept arbitrary JSON/connection settings, expose an approval object, create durable transaction authority, carry a native dispatch permit, or claim external changes. Existing v0.6 `DurableAuthorityControl` and `TransactionStore`/SQLite remain the only authoritative durable lifecycle. No second journal or replay channel is created.

Relevant requirements: R18-AUTH-01, R18-AUTH-02, R18-REC-01.
Adversarial cases: T03, T05, T08, T09, T10, T12, T13, T14, T15, T18, T19, T20, T21, T24, T25, T26, T29.

## S18-3 implementation acceptance

- [x] Define all nine strictly typed managed candidate operations with conservative risk floors and fixed observation/one-change binding. Assert candidates are not registered for execution.
- [x] Enforce human/transport-principal, typed owner/boot/bus epoch, observed freshness, exact target identity and plan status/postcondition review; deny unknown/stale/changed/cross-provider input.
- [x] Bound route/DNS/default-link impact, reject unknown impact, remote control loss, missing independently reviewable offline local recovery and plan-risk downgrades.
- [x] Refuse opaque persistent profile material until S18-8 has a protected typed input path. Do not forward secrets, settings maps, arbitrary D-Bus calls or a shell executor.
- [x] Distinguish no-change, indeterminate observe-only, recovery-blocked and terminal/no-replay states; no receipt/GUI state is an approval or dispatch authority.
- [x] Invalidate unqualified S18 provider effects in the existing canonical managed **and transient** lifecycles **before** planning, transient audit or managed persistent prepare/approval/handoff; preserve ordinary systemd, audio, S17 and S21 effects and recovery.
- [ ] Complete full native authenticated subject, protected credentials and independently verified postcondition execution in later **S18-4 through S18-8**. This is not an S18-3 permission to send NM effects.

## Required qualification and remaining blockers

- [ ] Canonical Rust/Clippy/format, policy regression and all matching exact-head GitHub checks green
- [ ] Inherited durable-attempt, ENOSPC, managed lifecycle and no-blind-replay regressions green
- [ ] Final source, security and internal review of this exact commit complete
- [ ] S18-2 actual NetworkManager Level A qualification and strict transport receive ceiling accepted as an upstream merge prerequisite

No new live S18 prepare or attempt may be persisted **until** a separately implemented and accepted executor/verification integration exists. The existing authoritative SQLite-backed `DurableAuthorityControl` already owns the durable prepare, indeterminate and replay rules; S18-3 adds no second storage route or new permit.

## Explicit safety and support boundaries

- No native effect or operation is registered.
- Linura Control retains canonical risk classification, authenticated principal, `ReconciliationPlan`, durable prepare/verification and recovery authority. Native mechanisms must be narrow and fail closed.
- No arbitrary privileged D-Bus or shell passthrough, leaked secrets, session/seat alias grant, blind effect replay, or replacement of S17 lock/security and S21 device protections.
- This review changes only an inert typed authority assessment and a deny-before-prepare runtime guard. It does **not** change execution, credentials, native effects, SQLite schema, or release support. A green non-dispatching S18-3 test cannot be cited as qualification of future S18-4+ native effects.

## Acceptance and eventual release

S18-3 may enter final **code review** when the exact-source canonical CI, Security, CodeQL, managed lifecycle and durable persistence/ENOSPC checks pass. A reviewer must still confirm that every candidate is inert and the new guard cannot be bypassed. S18-2 must be independently accepted before final integration, and downstream native effect/Polkit/physical Q11 qualification remains separate. Do not merge the WIP branch wholesale or promote unqualified network features.

Historical PR head `feat/v010-s19-1-bluez-observation` is retained for GitHub continuity; its old version is archived as `archive/pre-s18-rebuild-20261101-pr-269`.
