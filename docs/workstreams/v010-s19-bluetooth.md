# S19 WIP engineering reference — BlueZ Bluetooth experience

> **Status: development reference only. No PR, operation registration, implementation completion, release claim or evidence promotion.**
>
> Origin: `main` commit `e867f5348f1a0b6833d0b622187e1213cac0039e`; branch `wip/v010-s19-bluetooth`. This file intentionally lives **only** on that WIP branch. New implementation work must be independently reviewed and qualified before extraction into clean PRs.

## Authoritative scope and reuse

The `arch-hyprland-v1` profile already selects BlueZ and platform discovery checks `org.bluez` availability. Treat that as provider discovery only. Build on existing Control, observation, session identity, S17 protected interaction and first-party ShellBridge boundaries; do not create an independently privileged Bluetooth control plane.

This workstream is defined by `contracts/v010-workstation-slices.toml`, `docs/milestones/v0.10.0.md`, ADR 0031/0032/0033 and `docs/qualification/v0.10.0.md`. S16 is the declared predecessor; completed code/merge evidence and separate physical Q11 release qualification are not interchangeable. A WIP branch is never merged into `main` directly.

## Exact resource, identity and observation requirements

Bind the exact BlueZ unique service owner and ObjectManager inventory, adapter path and native adapter identity, controller power generation, device identity and connection generation. MAC address, alias, device display name and D-Bus path alone cannot prove device continuity; distinguish classic/BLE device, paired, trusted, connected and service-resolved states. Revalidate adapter and target on every effect and after BlueZ/hardware reset.

Provider and transport objects are adapter mechanisms, not domain authority. Canonical `linura-observation::ObservationEnvelope` and Control-side resolution own freshness/identity decisions. Duplicate, missing, contradictory or stale proof must be visible as unavailable or indeterminate.

## Operation semantics and authority boundary

Discovery, scan results and pairing state are `AuthoritativeQuery`; picker navigation is `ExperienceEphemeral`. Power/discovery control, pairing, connect/disconnect, trust/revoke and forget are distinct candidate operations, each with registered class and risk floors. Persistence/security consequences of trusted pairing and key removal demand `ManagedExternalEffect` unless a narrower qualified semantic envelope is established; never downgrade because BlueZ exposes a D-Bus method.

A mutable effect must follow the exact Control-owned trusted descriptor, authenticated principal, canonical plan, policy and trusted risk floor. `policy allow != executor grant`; `reviewed plan != prepared mutation`; `executor != verification`. No raw commands, ambient credentials, arbitrarily forwarded D-Bus methods or model-selected permits. Qualified transient paths, if any, still require fresh preconditions, narrow unprivileged execution, independent verification and audit.

## Workstation experience and accessibility

One first-party adapter and device interface shared by Control Center/Quick Settings/CLI. Pairing must correlate the correct requesting principal, BlueZ agent request and exact currently presented device; treat PIN/passkey/confirmation as protected interactions. Never log pairing material or accept agent/model-supplied implicit consent. Reconnect/restart must not replay trust, pair or remove attempts.

The first-party ShellBridge and shared `org.linura.UI` SDK are presentation/adaptation boundaries only. Keyboard/pointer/screen-reader/reduced-motion/HiDPI and offline/no-model paths are required. An optimistic UI receipt is never authoritative success.

## Required adversarial and regression coverage

Device substitution/alias spoof, duplicated addresses, agent prompt spoofing, changing adapter identity, stale ObjectManager snapshot, interrupted passkey, headless/no agent availability, foreign seat, rfkill interference, permission denial, BlueZ crash, partial pair/unpair, disappeared device, failed disconnect, simultaneous pairing sessions, replayed RemoveDevice, device connected without required service readiness.

Test policy denial, missing provider, unsupported hardware, actor/seat/session/boot substitution where applicable, before/after-effect crash, dispatch ambiguity, daemon replacement and exact source pinning. Preserve all S17/S21 lock, power, display and recovery protections plus inherited v0.4/v0.6/v0.9/v0.10 gates; do not delete, skip or weaken checks.

## Intended extraction into independently reviewed PRs

1. PR-A — native adapter/device discovery, authoritative observation and bounded identity model
2. PR-B — purpose-bound pairing agent and security-sensitive trust/forget contracts, with no mutation activation
3. PR-C — narrow BlueZ operations through Control, durable recovery, independent postcondition and negative tests
4. PR-D — Bluetooth shell/CLI UX, accessibility and exact-source multi-device/restart qualification

These are architectural cut lines, **not PRs and not fixed PR numbers**. As code matures, rebase/extract reviewed coherent commits onto fresh `main` branches, minimize the diff per real dependency, compact final PR history, and run all applicable exact-head checks. If a cut does not stand on its own safely, keep its later effect inactive until dependencies merge.

## Acceptance evidence and nonclaims

Pinned BlueZ, kernel controller/adapter identity and logind owner with an independently inventoried adapter; native positive/negative pairing against controlled Bluetooth hardware when claimed. VMs and virtual HCI do not qualify physical pairing/radio. Require negative device-identity and foreign-subject tests; gate service availability, key material secrecy and ambiguous dispatch.

WIP tests do not establish experimental support, production readiness, hardware proof or v0.10 release status. Before completing S19, record dependency-closed, merged-PR evidence in the canonical slice ledger and retain the proper native/visual/security/recovery artifact identities. Do not set `interactive_workstation.evidence_ready` or any Q10/Q11 readiness marker on the basis of this plan.

## Owned implementation areas to inspect before editing

apps/linura-shell/plugins/bluetooth/, proposed crates/linura-provider-bluez/, narrow native agent/observation adapter and Control/CLI/SDK qualification.

Before runtime changes: read scoped `AGENTS.md` and `agents/skills/` guides; perform full consumer/regression-impact analysis, threat review, then tests and implementation. For authority or security work, read `SECURITY.md`, `docs/security-model.md`, `docs/agent-architecture.md` and `docs/vision-coverage.md`. Preflight the pinned development environment and do not claim CI or physical tests that have not run.
