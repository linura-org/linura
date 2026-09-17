# ADR 0030: Qualify Arch/Hyprland as the first interactive PlatformProfile in v0.10

- Status: Accepted
- Date: 2026-09-17

## Context

v0.9 qualified Linura's installation/adoption/update/recovery layer on the exact Ubuntu 24.04 LTS amd64 QEMU-TCG headless QualificationEnvironment. That environment intentionally proved the Linura layer before Linura claimed an interactive workstation PlatformProfile.

ADR 0003 already selected `arch-hyprland-v1` as the first explicit interactive PlatformProfile. The profile currently remains `development`, and the workstation release-qualified profile lane is empty.

v0.10 is the first milestone intended to be meaningfully usable by external experimental end users. The repository therefore needs one explicit decision about whether v0.10 merely adds UI on top of the v0.9 headless environment or actually qualifies the workstation profile that represents Linura's intended interactive product direction.

## Decision

v0.10 targets `arch-hyprland-v1` as Linura's first release-qualified interactive workstation PlatformProfile.

This does not convert the v0.9 Ubuntu QualificationEnvironment into a PlatformProfile and does not weaken its historical release claim. v0.10 must retain the Ubuntu lane as inherited regression evidence while independently qualifying the Arch/systemd/Wayland/Hyprland workstation boundary.

The v0.10 release may mark `arch-hyprland-v1` release-qualified only after both of these evidence classes pass:

1. deterministic disposable-system evidence for installation/adoption, persistence, authority, update, migration, recovery and supported typed effects; and
2. explicit interactive workstation evidence for the actual Wayland/Hyprland user/session/hardware surface.

Because Arch is rolling, the release evidence must freeze an immutable package/base identity rather than relying on an unbounded `latest` package universe.

Linura Control Center may become a supported v0.10 client only as an unprivileged typed protocol client. It must not own distro-specific privileged mutation logic, policy authority or executor handles.

A capability may enter the v0.10 workstation support claim only if it has typed desired state, authoritative observation, deterministic planning, bounded authority, durable prepare/recovery, a narrow executor and independent verification. Missing domain coverage remains read-only or unsupported; a generic privileged shell is not an acceptable compatibility mechanism.

## Consequences

- `arch-hyprland-v1` stays `development` during implementation.
- `hardware/support-matrix.json` stays unchanged until protected post-release closure has immutable v0.10 publication evidence.
- v0.10 qualification must include exact Arch package-set identity and exact hardware/driver/display evidence.
- Other distributions, desktops/compositors and hardware lanes require separate profiles/evidence and do not inherit support automatically.
- v0.9 Ubuntu qualification remains mandatory inherited regression evidence but is insufficient to prove v0.10 workstation support.
- The first meaningful graphical experience remains subordinate to Linura's deterministic authority and recovery model rather than creating a parallel control plane.
