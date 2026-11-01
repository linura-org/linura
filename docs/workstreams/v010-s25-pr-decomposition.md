# S25 implementation decomposition — five proposed, independently qualified PRs

**Status:** Proposed Phase-2 extraction plan. This file is not an implementation PR, an accepted ADR, an activated operation, production support, or native qualification evidence.

**Source:** [Phase-1 audit](v010-s25-personalization-phase1.md), [ADR 0053](../adr/0053-s25-personalization-authority-and-safe-rendering.md), [inactive S25 design](../../contracts/v010-s25-design.toml), [domain qualification](../qualification/v0.10.0-s25.md) and [adversarial qualification](../qualification/v0.10.0-s25-security.md). The machine-checked planning record is [S25 PR plan](v010-s25-pr-decomposition.toml).

## Baseline and immovable boundaries

The existing S10 compiled org.linura.UI 1.0 component SDK, semantic tokens, S16 shared Shell and S17 protected security owner are authoritative existing work. The user-local preference store, preview state and native compositor/provider state are three distinct trust and evidence domains. The native wallpaper backend also depends on exact S21 output/session topology. The current roadmap identifies S16 as S25's completed predecessor; S17 and S21 are *integration constraints*, not fabricated completed dependencies.

The Phase-1 WIP branch is a source of proposed architecture only. Reconcile provisional ADR numbering, accepted operation semantics, and branch drift against current main before extracting code. **Do not merge this WIP branch wholesale** or treat its tests as a slice completion. Five proposed PR boundaries may be combined or subdivided following security review, but no artificial PR quota or documentation-only completion is permitted.

## PR boundaries, implementation and review contracts

| Planning ID | Independent code responsibility | Depends on | Activation boundary |
| --- | --- | --- | --- |
| **S25-1** | Typed v1 preference schema, owner-authenticated provider/readback, atomic CAS, revision migrations and durable recovery | S16 | Linura-owned state only; external operations remain disabled |
| **S25-2** | Bounded per-session/window preview, Apply/Cancel, conflict and explicit revision restore | S25-1 | No preview persistence, native dispatch, or security-owner changes |
| **S25-3** | Safe semantic theme roles, density, motion, installed typography and icon families over S10 SDK | S25-1 and S25-2 | No executable themes, package installation or S17 fontconfig override |
| **S25-4** | Owner-scoped safe wallpaper assets, exact S21 output selection, narrow native provider, verification and recovery | S25-1 and S25-2; S17/S21 integration constraints | Managed candidates stay disabled until independent authorization, native verification and integrated S25-5 acceptance |
| **S25-5** | Control Center, Shell/Quick Settings/OSD, CLI/SDK, per-surface effective state and Q10/Q11 qualification | S25-1 through S25-4 | No release/evidence promotion without reviewed actual native and physical proof |

### S25-1 — preference authority

Provide canonical typed fields, strict deny-unknown parsing and schema version checks, authenticated owner/UID identity, owner-only file persistence, secure file-descriptor access, bounded canonical serialized representation, monotonic revision plus digest, atomic compare-and-swap, fsync/restart recovery, and explicit migration and prior-valid-state recovery. Test concurrent editors, stale base revisions, crash before/after atomic replacement, full disk, corrupted content, foreign owner and newer formats. This PR cannot claim saved state equals renderer application. It must include production API, verified negative tests and migration rules; no placeholders or unowned global settings files.

### S25-2 — appearance transactions

Bind preview to actual user, seat, session, window, source revision, generation and expiry. Explicit Apply checks the current revision and owner again; Cancel, timeout, lock/logout, renderer restart or destroyed window invalidates preview without native dispatch. Restore of a past revision is a *new authenticated CAS commit*, not a silent rollback. Add tests for conflicting windows, generation substitution, crash, stale Apply, race against concurrent preferences and readback. Implement a narrow safe baseline appearance preview before broader theme assets.

### S25-3 — theme, fonts and icons

Extend the shared token projection instead of replacing S10. Validate color semantics, readable status/focus/error/denial states, contrast under opacity/disabled states, bounded font scaling and hit targets, reduced motion, multilingual/RTL glyph fallback, installed allowlisted icon/font references and safe decoder formats. No QML/JS/CSS/shader content, external URL, arbitrary SVG script or unapproved font/icon install. Prove compiled SDK compatibility and protected S17 lock fonts/focus remain unmodified, including on adversarial malformed preferences.

### S25-4 — wallpaper and native effect

Treat wallpaper bytes as untrusted data. Require owner-checked safe-open regular file descriptors, controlled file roots, hash/provenance, MIME and encoded/decoded size, pixel/frame budget and immutable asset reference. Per-output apply/clear binds authenticated user session, compositor generation, exact S21 output identity/geometry/scale/transform, trusted plan and risk, policy authorization, durable preparation where managed, narrow native adapter, independent re-observation, audit and recovery. No generic shell/D-Bus proxy or optimistic provider receipts. Lost responses and compositor death are indeterminate: do not replay past approval or retarget an output. Saved preference and partially applied renderer state remain distinct. If true desktop color-scheme provider semantics differ from wallpaper, split that effect into another reviewable PR instead of broadening authority.

**S25-4 can merge an inert adapter only when its own executable code and negative tests are complete.** Its candidate external effects must not become active until the provider has passed the full authorization/evidence boundary and S25-5's integrated effective-state qualification. Native Q11 release proof is separate from VM evidence.

### S25-5 — full product and acceptance

Present stored, pending, applied, degraded, unsupported and rejected states consistently through Control Center, Shell, Quick Settings, OSD and manual CLI/SDK. Enforce no-model/offline operation, keyboard/pointer parity, screen reader semantics, focus, reduced motion, RTL and HiDPI. Qualify real QML rendering with reviewed Q10 baselines, executed diffs *and* interaction traces, source/renderer and revision provenance. Exercise compositor restart, missing provider, unsafe asset, lock/session change, multi-monitor hotplug and failed/partial application. Physical Q11 maintained real Arch/Hyprland hardware remains a separate mandatory release gate.

## Security and qualification traceability

The TOML planning record assigns all Phase-1 requirement identifiers and adversarial cases T25-01 through T25-26 to their intended implementation PRs. Tests for every changed behavior and negative path accompany the code in that PR. Do not postpone a necessary denial or failure test until S25-5. Each implementation PR must run exact-head required canonical, dependency/security, CodeQL if applicable, qualification and changed-component gates. S10/S16 visual regression and S17/S21 safety constraints are inherited and cannot be weakened or marked skipped to make checks green.

## Extraction and merge protocol

1. Audit and rebase *source assumptions*, not WIP commits, onto exact current main; confirm ADR numbers, applicable AGENTS/skills and shared paths. Only one owner at a time changes shared ShellBridge, tokens, operation registry, CI and QML SDK.
2. Create S25-1 from fresh main as a distinct implementation branch, with its real source code, tests, review and migration/recovery evidence. No speculative effect registration.
3. Extract S25-2 and S25-3 according to merge dependencies. S25-4 may develop in parallel after S25-1/2 but is gated on current S17/S21 native security/display semantics.
4. Integrate S25-5 and prove exact-source rendered state, inaccessible/negative paths, Q10 visual and physical Q11 where required. Keep unqualified operations explicitly disabled and unsupported.
5. Update S25 ledger evidence only with merged implementation PR numbers and dependency-closed accepted proof; do not change planned status or evidence arrays in this WIP.

**Nonclaims:** This plan creates no GitHub implementation PR numbers; does not assert runtime features, tests, visual evidence, native hardware access, acceptance or release readiness. It is the engineering starting boundary, not S25 completion.
