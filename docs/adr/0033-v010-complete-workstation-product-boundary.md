# ADR 0033 — v0.10 requires a complete Experimental workstation product boundary

- **Status:** Accepted
- **Date:** 2026-09-26
- **Refines:** ADR 0031 product-scope items 9–10; ADR 0030 workstation product scope
- **Does not supersede:** ADR 0031 one-machine-model/one-authority-path invariants; ADR 0032 operation classification

## Context

The original v0.10 plan intentionally required bounded desktop integration while postponing a complete first-party shell and several ordinary workstation workflows until after v1. That sequencing kept the first interactive milestone small, but it created an undesirable product boundary: Linura could reach its first Stable version while ordinary workstation completeness still depended on later strategic phases.

Implementation through the current v0.10 shell, operation registry, workspace/launcher, Quick Settings and exact-source Arch/Hyprland runtime qualification has made the architectural boundary clearer. Product breadth can expand without weakening authority because UI surfaces remain clients of the same trusted operation registry, typed machine model and Control lifecycle.

Product completeness and support maturity are therefore separate decisions.

## Decision

v0.10 is rebaselined as Linura's **complete Experimental workstation** milestone on the exact `arch-hyprland-v1` PlatformProfile.

Within that narrow platform boundary, the release contract must cover the ordinary workstation experience rather than deferring basic product surfaces until after v1:

- first-party shell panel/status/tray and workstation entry points;
- launcher/workspace UX, command palette and Quick Settings;
- lifecycle notifications/OSD;
- lock screen and session/power controls;
- supported network, Bluetooth, audio/media, display/brightness/power and removable-storage workflows;
- screenshot/recording, clipboard/history and essential desktop utilities;
- supported application/package/default-app workflows;
- coordinated updates, snapshots, rollback/recovery and repair UX;
- themes, wallpaper, fonts/icons and coherent personalization;
- Control Center, Library/Setups/MachineProfiles and declarative configuration;
- complete deterministic manual/no-AI workflows with proposal-only agent assistance;
- at least one bounded, independently qualified installer path into the exact supported workstation profile plus First Boot/owner enrollment;
- keyboard/pointer parity, semantic accessibility, reduced-motion and qualified scaling/HiDPI behavior;
- diagnostics, explanation, audit and recovery guidance.

Linura owns the supported product behavior for those surfaces. Hyprland remains the qualified compositor and upstream services/components may remain implementation dependencies. This decision does **not** require Linura to implement its own compositor, kernel, display server, package manager or every upstream subsystem.

All authority invariants remain unchanged:

1. graphical/keyboard/config/agent surfaces are invocation/proposal surfaces, not authority surfaces;
2. registered trusted operation semantics determine the authority path;
3. privileged or durable external effects use the canonical Control lifecycle;
4. executor self-report is not authoritative success;
5. model output remains proposal-only;
6. no generic privileged shell or UI-specific mutation bypass is introduced.

The detailed implementation sequence is machine-locked by `contracts/v010-workstation-slices.toml`.

Phase 11 / v1.0 stabilizes this already-complete workstation scope. It must not use Stable qualification as a reason to defer ordinary product-critical workstation surfaces.

## Non-goals

v0.10 still does not claim:

- generic Linux or multi-distribution desktop support;
- every GPU, display topology, firmware or storage layout;
- generic dual-boot, RAID or arbitrary custom-partitioning installer support;
- unrestricted package sources or generic privileged command execution;
- comprehensive container/virtual-machine management;
- server/edge product completeness;
- fleet/enterprise authority;
- third-party extension ecosystem completeness;
- Stable support.

Those remain separately scoped work and evidence.

## Consequences

- Phase 10 becomes a product-completeness milestone under an Experimental support claim.
- Phase 11 becomes a support-maturity/Stable-qualification milestone for that complete product.
- Phases 12+ deepen provider breadth, workflows, derived UI, extensions and fleet capabilities instead of completing basic workstation UX.
- v0.10 qualification and visual/accessibility evidence must expand to the newly required surfaces.
- The roadmap, milestone contract, qualification contract and slice ledger must change atomically when this boundary changes again.
