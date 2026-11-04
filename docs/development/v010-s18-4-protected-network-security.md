# S18-4 — add protected network credentials and native authorization

**Status:** Reserved development scope; source implementation and qualification not delivered by this PR.
**Milestone:** v0.10.0 / S18-4.
**Profile:** `arch-hyprland-v1` (development).
**Reference branch and draft PR base:** `wip/v010-s18-network` at `63265739f8a62f2e7a7d3c665d7c9af7f8946537`.

## Ownership and dependencies

Depends on S18-1, S18-3. All development remains on WIP until each capability is independently extracted. This draft PR contributes only this non-executable planning document relative to WIP; inherited files are not claimed as this PR's implementation.

Authoritative WIP sources:
- [S18 Phase 1](../workstreams/v010-s18-network-phase1.md), [ten-part implementation decomposition](../workstreams/v010-s18-pr-decomposition.md), [machine-checked plan](../../contracts/v010-s18-pr-decomposition.toml).
- [NetworkManager ADR 0048](../adr/0048-s18-networkmanager-authority.md), [inactive design](../../contracts/v010-s18-design.toml).
- [S18 qualification](../qualification/v0.10.0-s18.md), [security dossier](../qualification/v0.10.0-s18-security.md).

## Intended source files and regression impact

- `crates/linura-linux-session/` — owned implementation, relevant native fixtures, and positive/denial/adversarial regression tests.
- `apps/linura-shell/security-owner/` — owned implementation, relevant native fixtures, and positive/denial/adversarial regression tests.
- `crates/linura-control/` — owned implementation, relevant native fixtures, and positive/denial/adversarial regression tests.
- `packaging/dbus-1/` — owned implementation, relevant native fixtures, and positive/denial/adversarial regression tests.

Relevant requirements: R18-AUTH-02, R18-SEC-01.
Adversarial cases: T03, T05, T11, T13, T14, T15, T16, T17, T19, T23, T24, T26, T28.

## Required implementation (not yet completed)

- [ ] Bind actual authenticated transport sender, logind session and Polkit subject to the exact operation, device/profile epoch and owner generation.
- [ ] Establish purpose-bound native Wi-Fi secret-agent and protected credential input without exposing passwords, EAP material or BSSID-sensitive data to model, QML, audit or logs.
- [ ] Separate one-time connection credentials from durable profile secret persistence and require explicit authenticated user consent.
- [ ] Cancel and zeroize on lock/session/seat/owner changes, timeout, focus loss and connection cancellation; no reusable proof or arbitrary GetSecrets/Update2 relay.
- [ ] Adversarially test confused deputy, root versus real user, foreign sessions, locked input, replay and redaction across native IPC.

## Required qualification and remaining blockers

- [ ] real-polkit-subject-adversarial
- [ ] native-protected-input-credential-tests
- [ ] secret-redaction-and-ownership-audit
- [ ] No native credential use until genuine protected-input and secret-agent subject are qualified

## Explicit safety and support boundaries

- No native effect or operation is registered.
- Linura Control retains canonical risk classification, authenticated principal, `ReconciliationPlan`, durable prepare/verification and recovery authority. Native mechanisms must be narrow and fail closed.
- No arbitrary privileged D-Bus or shell passthrough, leaked secrets, session/seat alias grant, blind effect replay, or replacement of S17 lock/security and S21 device protections.
- This single Markdown file changes **no runtime, contract, policy, credential, test or release support behavior**. WIP's existing development checks are not evidence that a future effect passed exact-head native qualification.

## Acceptance and eventual release

Before review: implement the correct scoped code in WIP, internally verify consumers/security/negative cases, extract to an independently reviewable PR, consolidate a coherent commit, pass canonical CI, fresh Security/cargo-audit, CodeQL, applicable native A/B/C and inherited gates, resolve findings and complete final Codex review. Only then retarget/rebase toward accepted `main`; **never merge WIP wholesale**. Physical Q11 remains unsupported until actual maintained hardware evidence.

Historical PR head `feat/v010-s25-1-preference-authority` is retained for GitHub continuity; its old version is archived as `archive/pre-s18-rebuild-20261101-pr-270`.
