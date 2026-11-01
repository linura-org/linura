# S23 WIP engineering reference — Applications, packages and default-app management

> **Status: development reference only. No PR, operation registration, implementation completion, release claim or evidence promotion.**
>
> Origin: `main` commit `e867f5348f1a0b6833d0b622187e1213cac0039e`; branch `wip/v010-s23-applications`. This file intentionally lives **only** on that WIP branch. New implementation work must be independently reviewed and qualified before extraction into clean PRs.

## Authoritative scope and reuse

S12/S14 already provide deterministic desktop-file discovery, `NoDisplay` filtering, exact ID re-resolution and constrained user-systemd launches in `app.slice`, with source-qualified launcher behavior. Reuse that launch boundary; do not equate opening a desktop entry with authorization to install packages. `arch-hyprland-v1` pins Arch and pacman, and S24 explicitly depends on S23.

This workstream is defined by `contracts/v010-workstation-slices.toml`, `docs/milestones/v0.10.0.md`, ADR 0031/0032/0033 and `docs/qualification/v0.10.0.md`. S16 is the declared predecessor; completed code/merge evidence and separate physical Q11 release qualification are not interchangeable. A WIP branch is never merged into `main` directly.

## Exact resource, identity and observation requirements

For applications bind the stable desktop-entry ID, exact resolved file/source ownership, executable provenance and user session at activation. For package transactions bind immutable Arch repository snapshot, package manager/database lock generation, exact requested package identities/versions/repository trust and complete dependency/conflict plan; never trust arbitrary package names or executable output alone. For default apps bind normalized MIME/scheme targets, source .desktop identity, XDG configuration ownership and current effective association.

Provider and transport objects are adapter mechanisms, not domain authority. Canonical `linura-observation::ObservationEnvelope` and Control-side resolution own freshness/identity decisions. Duplicate, missing, contradictory or stale proof must be visible as unavailable or indeterminate.

## Operation semantics and authority boundary

App discovery/installed package inventory are `AuthoritativeQuery`; launching approved desktop applications uses S12's bounded experience path. Package install/remove or repository/source changes are `ManagedExternalEffect` with explicit security/destructive risk floors, durable plan/approval and independent installation verification. Default app association is a separate typed user-owned or bounded external-effect operation; must not silently trigger package install. Do not call generic privileged pacman commands from a GUI or expose raw flags/script hooks.

A mutable effect must follow the exact Control-owned trusted descriptor, authenticated principal, canonical plan, policy and trusted risk floor. `policy allow != executor grant`; `reviewed plan != prepared mutation`; `executor != verification`. No raw commands, ambient credentials, arbitrarily forwarded D-Bus methods or model-selected permits. Qualified transient paths, if any, still require fresh preconditions, narrow unprivileged execution, independent verification and audit.

## Workstation experience and accessibility

Provide bounded app catalog, installed package information, provenance and update availability; deterministic transaction preview (dependencies, removals, disk effect, trust), review/approval and exact post-install inventory; explicit default app selection for MIME/scheme with rollback; optional integration with release-approved application sources only. Support offline/no-model read/planning where feasible; secrets and untrusted package scripts never become plan authority.

The first-party ShellBridge and shared `org.linura.UI` SDK are presentation/adaptation boundaries only. Keyboard/pointer/screen-reader/reduced-motion/HiDPI and offline/no-model paths are required. An optimistic UI receipt is never authoritative success.

## Required adversarial and regression coverage

Repo mirror/package-index replacement, stale database lock, changed dependency graph after approval, untrusted sources, signature failure, package script side effects, conflict/replacement, disk exhaustion, interrupted upgrade/remove, power loss, different installed version, duplicate/replayed transaction, missing boot/recovery image, MIME handler substitution and unsafe desktop Exec expansion. No unsupported 'rollback' claim from pacman alone.

Test policy denial, missing provider, unsupported hardware, actor/seat/session/boot substitution where applicable, before/after-effect crash, dispatch ambiguity, daemon replacement and exact source pinning. Preserve all S17/S21 lock, power, display and recovery protections plus inherited v0.4/v0.6/v0.9/v0.10 gates; do not delete, skip or weaken checks.

## Adaptive decomposition into independently reviewed PRs

**No fixed PR count, fixed four-stage template or mandatory PR size.** This WIP branch is a reference workspace; an eventual implementation may require one, several or many PRs. Determine the actual number *for this slice* from its concrete code, architecture, dependencies, qualification gaps and review outcomes. The top-level v0.10 slice IDs in the canonical ledger must not be renumbered or multiplied just because implementation is divided into PRs.

Potential technical seams to evaluate, combine or subdivide as the implementation matures:

1. exact app/package/default-app observation, identity and provenance contracts
2. deterministic fixed-source package transaction planning, trust/risk and durable prepare, intentionally unactivated
3. narrow pacman effect executor, postcondition verification, interruption recovery and anti-replay
4. first-party app/package/default-app UX, CLI/SDK parity, exact-source native and security qualification

**Decision procedure before opening any PR:**

1. Inventory the actual changed code, callers, existing shared contracts, authority/security boundaries, native integration and dependency graph. Recheck S17/S21 and existing released/versioned behavior.
2. Separate independently reviewable and independently verifiable capabilities. Split at substantive ownership/trust/qualification boundaries or when one PR cannot be properly reviewed; combine tightly coupled edits when extracting either alone would leave an unusable or incoherent contract.
3. Make a slice-specific ordered PR plan with explicit base/dependency, active vs inactive operation state, acceptance tests, native evidence and rollback/recovery obligations. Revise its count when findings materially change the boundaries; never inflate or force a fixed quota.
4. Extract cohesive implementation and its negative tests together onto a fresh, accepted `main` base. Keep unfinished effects inactive, no speculative bypasses or placeholders masquerading as working providers. Run mandatory exact-head gates and resolve reviews for *each* PR.
5. Only after dependent PRs merge should the canonical ledger record dependency-closed, merged evidence. WIP commits, documents, CI results or partial qualification are not production support.

These are **capability seams, not PR-A–D promises**. Some seams may produce multiple PRs (for example separate authentication, executor, recovery or native qualification); others may merge into one coherent PR. No PRs are created from this document.

## Acceptance evidence and nonclaims

Frozen Arch archive/package database identity, real pacman filesystem transactions in disposable machines and explicit component-level recovery strategy. Validate real dependency/conflict and database-lock behavior, signature/trust faults and power interruptions. Coordinate with S24 rollback/snapshot semantics: S23 must not advertise snapshot protection it cannot independently prove.

WIP tests do not establish experimental support, production readiness, hardware proof or v0.10 release status. Before completing S23, record dependency-closed, merged-PR evidence in the canonical slice ledger and retain the proper native/visual/security/recovery artifact identities. Do not set `interactive_workstation.evidence_ready` or any Q10/Q11 readiness marker on the basis of this plan.

## Owned implementation areas to inspect before editing

apps/linura-shell/plugins/applications/, packages/, default-apps/, bounded Arch package adapter, canonical Control lifecycle; S24 later owns coordinated updates and recovery UX.

Before runtime changes: read scoped `AGENTS.md` and `agents/skills/` guides; perform full consumer/regression-impact analysis, threat review, then tests and implementation. For authority or security work, read `SECURITY.md`, `docs/security-model.md`, `docs/agent-architecture.md` and `docs/vision-coverage.md`. Preflight the pinned development environment and do not claim CI or physical tests that have not run.
