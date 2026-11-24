# S21-6 — Workstation device-control convergence

**Status:** Reserved development scope; implementation not started; no support or qualification claim.
**Milestone:** v0.10.0, S21-6 (within S21).
**Profile:** `arch-hyprland-v1` (development).

## Ownership and dependencies

This scope integrates the accepted S21 domain implementations across Linura Control Center, Quick Settings, ShellBridge, keyboard/OSD, CLI and SDK. It depends on the domain boundaries and accepted contracts for S17 session security/power (PR #241), S21 architecture (PR #257), and the reviewed S21-2 through S21-5 implementations (PRs #259–#262). Work on inert UI state, interface contracts and negative tests may proceed while those PRs are draft; mutation-capable integration cannot be accepted ahead of its domain dependency.

The normative requirements remain in:
- [S21 device authority ADR](../adr/0045-s21-workstation-device-authority.md).
- [S21 native qualification](../qualification/v0.10.0-s21.md).
- [v0.10 workstation milestone](../milestones/v0.10.0.md).
- [32-slice completion ledger](../../contracts/v010-workstation-slices.toml).

## Required implementation (not yet completed)

- Reuse existing Control-owned typed operation identities, trusted risk floors, authenticated subjects, exact resource/generation and current authoritative observations for display, hardware backlight, power and removable media.
- Integrate Control Center, Quick Settings, optional keyboard/OSD, CLI and SDK without client-side authority or parallel mutation routes.
- Ensure all interfaces distinguish unsupported, unavailable, stale, denied, preparing, dispatched, indeterminate, recovering, independently verified and committed states as applicable. Never report a successful effect based only on a client animation or provider reply.
- Preserve original display Apply/Keep/Revert transaction identity, native protected-input/first-frame coverage and recovery; preserve S17 power/lock fencing, physical backlight safety and UDisks2/Polkit drive-sibling protections.
- Provide deterministic manual/no-model operation, restart/reconnect/timeout handling, safe notification content, keyboard/pointer parity, accessibility and multi-output/HiDPI behavior.
- Include positive, denial, stale-identity, lost-reply, process-loss, interruption and no-replay regressions for each supported path.

## Acceptance and explicit non-claims

This document reserves a future draft PR scope only. It adds **no runtime registration, public API, executor, UI control, qualified effect, support declaration, ledger completion or test evidence**. Unsupported domain actions must remain unavailable; no mock/provider shortcut may enable them.

Before the PR leaves draft: implement and internally review the actual integration, reconcile final accepted domain contracts, consolidate history, run every applicable exact-head CI/qualification gate, resolve findings, obtain final Codex review and record truthful acceptance evidence. S21-7 owns final cross-domain native acceptance; physical Q11 and release promotion remain separate gates.
