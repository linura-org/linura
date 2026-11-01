# S22 WIP engineering reference — Desktop utilities, screenshot/recording and clipboard history

> **Status: development reference only. No PR, operation registration, implementation completion, release claim or evidence promotion.**
>
> Origin: `main` commit `e867f5348f1a0b6833d0b622187e1213cac0039e`; branch `wip/v010-s22-utilities`. This file intentionally lives **only** on that WIP branch. New implementation work must be independently reviewed and qualified before extraction into clean PRs.

## Authoritative scope and reuse

The repo has a declarative `workflows/screenshot-share.toml` example and a first-party Wayland/Hyprland/Quickshell shell; this example is not a supported capture/recording executor. Existing ShellBridge remains the sole first-party authority-facing adapter, with S17 lock coverage and S21 protected display boundaries. Reuse the UI SDK, global shortcut infrastructure, status/notifications and permission principles.

This workstream is defined by `contracts/v010-workstation-slices.toml`, `docs/milestones/v0.10.0.md`, ADR 0031/0032/0033 and `docs/qualification/v0.10.0.md`. S16 is the declared predecessor; completed code/merge evidence and separate physical Q11 release qualification are not interchangeable. A WIP branch is never merged into `main` directly.

## Exact resource, identity and observation requirements

Bind capture to the exact logind user/session, compositor instance and outputs/window/region snapshot; never infer authority from environment variables, stale window handles or untrusted client-supplied surface IDs. Capture/clipboard data is sensitive user content; define memory/file lifetime, explicit ownership, bounded frame sizes/durations and redaction/exclusion policy. Clipboard selection/serial is not a durable authentication token.

Provider and transport objects are adapter mechanisms, not domain authority. Canonical `linura-observation::ObservationEnvelope` and Control-side resolution own freshness/identity decisions. Duplicate, missing, contradictory or stale proof must be visible as unavailable or indeterminate.

## Operation semantics and authority boundary

Region selection, clipboard picker navigation and other non-effect UI are `ExperienceEphemeral`. Screenshot/recording and clipboard reads are consent/privacy-sensitive user-session capabilities with explicit purpose and scope; they must not be misclassified as system-level privileged executor actions or permitted automatically to agents. Saved files, history retention and deletion use policy-appropriate Linura-owned or external-effect semantics independently of UI navigation.

A mutable effect must follow the exact Control-owned trusted descriptor, authenticated principal, canonical plan, policy and trusted risk floor. `policy allow != executor grant`; `reviewed plan != prepared mutation`; `executor != verification`. No raw commands, ambient credentials, arbitrarily forwarded D-Bus methods or model-selected permits. Qualified transient paths, if any, still require fresh preconditions, narrow unprivileged execution, independent verification and audit.

## Workstation experience and accessibility

Provide screenshot (screen/window/region), reviewed destination and optional annotation; bounded recording with visible indicator/stop and explicit audio inclusion; clipboard copy/paste and opt-in encrypted or otherwise suitably protected history with retention/deletion. On a locked or protected interaction, deny capture of secure surfaces and pause/abort history access; cannot use a blanket capture bypass. Per-monitor HiDPI, transforms, coordinates and focus must be accurate.

The first-party ShellBridge and shared `org.linura.UI` SDK are presentation/adaptation boundaries only. Keyboard/pointer/screen-reader/reduced-motion/HiDPI and offline/no-model paths are required. An optimistic UI receipt is never authoritative success.

## Required adversarial and regression coverage

Secure-lock screen leakage, protected authentication capture, portal denial/cancellation, window/monitor removed mid-capture, resolution drift, cursor exposure, audio capture without consent, recorder crashed/detached, orphan recording, symlink/path traversal to sensitive destination, oversized clipboard/image, content-type confusion, stale clipboard selection, clipboard history enabled without explicit consent, secrets/OTP captured in retained history.

Test policy denial, missing provider, unsupported hardware, actor/seat/session/boot substitution where applicable, before/after-effect crash, dispatch ambiguity, daemon replacement and exact source pinning. Preserve all S17/S21 lock, power, display and recovery protections plus inherited v0.4/v0.6/v0.9/v0.10 gates; do not delete, skip or weaken checks.

## Intended extraction into independently reviewed PRs

1. PR-A — bounded capture/recording/clipboard contracts, consent and sensitive-data threat model
2. PR-B — first-party screenshot/recording adapters with exact compositor/session binding and stop/recovery semantics
3. PR-C — privacy-bounded clipboard/history storage and expiry/clear flows
4. PR-D — native UI/shortcuts/accessibility, lock/protected-surface adversarial and visual qualification

These are architectural cut lines, **not PRs and not fixed PR numbers**. As code matures, rebase/extract reviewed coherent commits onto fresh `main` branches, minimize the diff per real dependency, compact final PR history, and run all applicable exact-head checks. If a cut does not stand on its own safely, keep its later effect inactive until dependencies merge.

## Acceptance evidence and nonclaims

Pinned Wayland/Hyprland/Quickshell with actual screenshot and recorder evidence, locked/unlocked/privacy scenarios, multioutput/HiDPI crop correctness and verified deletion/retention; demonstrate no secret leakage in audit or ordinary notifications. Recordings are supporting evidence, not independent truth for Control effects.

WIP tests do not establish experimental support, production readiness, hardware proof or v0.10 release status. Before completing S22, record dependency-closed, merged-PR evidence in the canonical slice ledger and retain the proper native/visual/security/recovery artifact identities. Do not set `interactive_workstation.evidence_ready` or any Q10/Q11 readiness marker on the basis of this plan.

## Owned implementation areas to inspect before editing

apps/linura-shell/plugins/screenshot/, recording/, clipboard/ and narrow user-session adapters; no generic privileged capture service.

Before runtime changes: read scoped `AGENTS.md` and `agents/skills/` guides; perform full consumer/regression-impact analysis, threat review, then tests and implementation. For authority or security work, read `SECURITY.md`, `docs/security-model.md`, `docs/agent-architecture.md` and `docs/vision-coverage.md`. Preflight the pinned development environment and do not claim CI or physical tests that have not run.
