# S21-7 — Native device integration and acceptance

**Status:** Reserved development scope; qualification work not started; no acceptance evidence.
**Milestone:** v0.10.0, S21-7 (within S21).
**Profile:** `arch-hyprland-v1` (development).

## Ownership and dependencies

This scope validates the integrated S21 workstation device paths, after accepted S17 session security/power and the actual S21-2 through S21-6 implementations. The domain implementation PRs are #259 (display), #260 (backlight), #261 (UDisks2), #262 (power/idle); S21-6 will provide cross-interface convergence. Inert test specifications, fixture designs and evidence-harness groundwork may be developed before domain acceptance but cannot substitute for tests against final integrated native code.

Authoritative requirements:
- [S21 domain qualification](../qualification/v0.10.0-s21.md).
- [S21 adversarial security qualification](../qualification/v0.10.0-s21-security.md).
- [S21 device authority](../adr/0045-s21-workstation-device-authority.md).
- [v0.10 workstation qualification](../qualification/v0.10.0.md).

## Required implementation and proof (not yet completed)

- Run the pinned exact-source Arch/Hyprland native Level A path using **real** compositor and UDisks2 behavior, clearly separating virtual output/device evidence from nonvirtual hardware behavior. Retain reproducible source/substrate, environment and execution identities.
- Qualify native multi-output Apply/Keep/Revert, protected first-frame handoff, hotplug, partial modeset, original-rule/overlay restoration, timeout, compositor death/replacement and independently verified recovery.
- Qualify actual native backlight authorization and supported hardware-dependent behaviors only on a lane that can establish physical device identity, brightness limits, visibility and independent recovery; report absent physical hardware as unqualified.
- Qualify distinct UDisks2 Mount, Unmount, Eject and PowerOff operations and authenticated Polkit subjects, kernel/drive/sibling safety, busy-media rejection, device removal and no blind replay of ambiguous effects.
- Prove S17 lock, suspend/power, inhibitor, input/focus and protected-frame invariants under concurrent device operations, crash/restart, denial, stale state and adverse timing.
- Verify Control Center, Quick Settings, keyboard, CLI/SDK and no-AI paths converge on the same Control identity, policy, state, evidence and recovery. Cover semantic accessibility, keyboard/pointer interaction and multi-display presentation.
- Independently verify effects using authoritative state and admitted evidence. Neither screenshots, self-reported executor success, green unit tests nor simulated devices qualify native effects.

## Acceptance and release boundary

S21 Level A native evidence and cross-slice fault/security qualification belong in this PR. Interactive Level B may supply additional evidence; **maintained nonvirtual Level C / Q11** and broader v0.10 release promotion retain the separate milestone qualification/closure requirements. Do not declare either completed without their exact physical and release evidence.

This document reserves a future **draft PR only**. It introduces no implementation, test fixture, enforcement change, runtime effect, acceptance result or support claim. Before leaving draft: run exact-head native and inherited gates, reconcile proof with accepted implementation SHAs, conduct architecture/security and regression review, consolidate commits, resolve findings and complete final Codex review.
