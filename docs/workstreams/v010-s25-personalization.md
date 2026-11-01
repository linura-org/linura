# S25 WIP engineering reference — Themes, wallpaper, fonts, icons and personalization

> **Status: development reference only. No PR, operation registration, implementation completion, release claim or evidence promotion.**
>
> Origin: `main` commit `e867f5348f1a0b6833d0b622187e1213cac0039e`; branch `wip/v010-s25-personalization`. This file intentionally lives **only** on that WIP branch. New implementation work must be independently reviewed and qualified before extraction into clean PRs.

## Authoritative scope and reuse

S10 establishes the compiled `org.linura.UI 1.0` design-system foundation; S16's first-party panel/Control Center/Quick Settings already consume Linura QML components and tokens. Reuse canonical tokens, shared theme propagation and session ownership. Personalization does not authorize mutation of arbitrary configuration files or system themes.

This workstream is defined by `contracts/v010-workstation-slices.toml`, `docs/milestones/v0.10.0.md`, ADR 0031/0032/0033 and `docs/qualification/v0.10.0.md`. S16 is the declared predecessor; completed code/merge evidence and separate physical Q11 release qualification are not interchangeable. A WIP branch is never merged into `main` directly.

## Exact resource, identity and observation requirements

Bind preference changes to authenticated local user/session, exact settings schema/revision and trusted asset provenance/content hash. Wallpaper selection must prove a regular bounded image file and safe URI/path ownership; fonts/icons require installed, allowed asset identity and deterministic fallback. Distinguish preview-only overrides from durable settings and apply scope; never silently mutate compositor, lock or global display geometry through theme preference.

Provider and transport objects are adapter mechanisms, not domain authority. Canonical `linura-observation::ObservationEnvelope` and Control-side resolution own freshness/identity decisions. Duplicate, missing, contradictory or stale proof must be visible as unavailable or indeterminate.

## Operation semantics and authority boundary

Preview, picker navigation and transient local presentation are `ExperienceEphemeral`; saved Linura-owned preference versions are `LinuraOwnedState` with typed CAS, audit/provenance, restore of previous revision. Any separate external wallpaper/compositor or system-level font/package effect requires independently classified narrow Control semantics; a theme file cannot transport commands, policy changes, QML, scripts or approval.

A mutable effect must follow the exact Control-owned trusted descriptor, authenticated principal, canonical plan, policy and trusted risk floor. `policy allow != executor grant`; `reviewed plan != prepared mutation`; `executor != verification`. No raw commands, ambient credentials, arbitrarily forwarded D-Bus methods or model-selected permits. Qualified transient paths, if any, still require fresh preconditions, narrow unprivileged execution, independent verification and audit.

## Workstation experience and accessibility

Use one versioned, declarative preference model shared by shell, installer, First Boot and Control Center where available: color roles, typography/scale, reduced motion, contrast, wallpaper selection, icon family and safe fallbacks. Show preview, explicit apply/cancel, persist success only on sealed revision, restart consistency and accessible keyboard navigation. Include HiDPI/multi-monitor behavior without overriding S21 display safety.

The first-party ShellBridge and shared `org.linura.UI` SDK are presentation/adaptation boundaries only. Keyboard/pointer/screen-reader/reduced-motion/HiDPI and offline/no-model paths are required. An optimistic UI receipt is never authoritative success.

## Required adversarial and regression coverage

Schema downgrade, malformed asset, decompression bomb, symlink/TOCTOU, external path traversal, stylesheet/script injection, QML injection through theme metadata, untrusted icon URI, conflicting concurrent edits, crash between settings and renderer, locked-session wallpaper visibility, reduced-motion ignored, insufficient contrast, incompatible font or renderer restart.

Test policy denial, missing provider, unsupported hardware, actor/seat/session/boot substitution where applicable, before/after-effect crash, dispatch ambiguity, daemon replacement and exact source pinning. Preserve all S17/S21 lock, power, display and recovery protections plus inherited v0.4/v0.6/v0.9/v0.10 gates; do not delete, skip or weaken checks.

## Adaptive decomposition into independently reviewed PRs

**No fixed PR count, fixed four-stage template or mandatory PR size.** This WIP branch is a reference workspace; an eventual implementation may require one, several or many PRs. Determine the actual number *for this slice* from its concrete code, architecture, dependencies, qualification gaps and review outcomes. The top-level v0.10 slice IDs in the canonical ledger must not be renumbered or multiplied just because implementation is divided into PRs.

Potential technical seams to evaluate, combine or subdivide as the implementation matures:

1. typed, versioned personal-preference schema and threat model, with invariant tests
2. atomic CAS persistence and deterministic preview/commit/revert contract, with recovery/fallback
3. shared first-party design token propagation, wallpaper/font/icon adapters and UI
4. multi-surface visual/a11y/HiDPI/reduced-motion/restart exact-source qualification

**Decision procedure before opening any PR:**

1. Inventory the actual changed code, callers, existing shared contracts, authority/security boundaries, native integration and dependency graph. Recheck S17/S21 and existing released/versioned behavior.
2. Separate independently reviewable and independently verifiable capabilities. Split at substantive ownership/trust/qualification boundaries or when one PR cannot be properly reviewed; combine tightly coupled edits when extracting either alone would leave an unusable or incoherent contract.
3. Make a slice-specific ordered PR plan with explicit base/dependency, active vs inactive operation state, acceptance tests, native evidence and rollback/recovery obligations. Revise its count when findings materially change the boundaries; never inflate or force a fixed quota.
4. Extract cohesive implementation and its negative tests together onto a fresh, accepted `main` base. Keep unfinished effects inactive, no speculative bypasses or placeholders masquerading as working providers. Run mandatory exact-head gates and resolve reviews for *each* PR.
5. Only after dependent PRs merge should the canonical ledger record dependency-closed, merged evidence. WIP commits, documents, CI results or partial qualification are not production support.

These are **capability seams, not PR-A–D promises**. Some seams may produce multiple PRs (for example separate authentication, executor, recovery or native qualification); others may merge into one coherent PR. No PRs are created from this document.

## Acceptance evidence and nonclaims

Same semantic tokens across QML SDK, First Boot, Control Center and shell, with representative nonuniform visual baselines/diffs, accessibility semantics, keyboard focus and scale checks. A persisted preference or screenshot alone does not prove actual renderer state; preserve Q10 artifact digests and review status.

WIP tests do not establish experimental support, production readiness, hardware proof or v0.10 release status. Before completing S25, record dependency-closed, merged-PR evidence in the canonical slice ledger and retain the proper native/visual/security/recovery artifact identities. Do not set `interactive_workstation.evidence_ready` or any Q10/Q11 readiness marker on the basis of this plan.

## Owned implementation areas to inspect before editing

apps/linura-shell/plugins/personalization/, apps/linura-shell/theme/, design/ and versioned Linura settings/protocol layer where accepted.

Before runtime changes: read scoped `AGENTS.md` and `agents/skills/` guides; perform full consumer/regression-impact analysis, threat review, then tests and implementation. For authority or security work, read `SECURITY.md`, `docs/security-model.md`, `docs/agent-architecture.md` and `docs/vision-coverage.md`. Preflight the pinned development environment and do not claim CI or physical tests that have not run.
