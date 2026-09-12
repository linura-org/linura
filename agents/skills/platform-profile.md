# Platform-profile task guide

The first interactive workstation PlatformProfile is Arch/systemd/Wayland/Hyprland (`arch-hyprland-v1`), but core crates must stay distribution-neutral.

Do not confuse a PlatformProfile with either a portable MachineProfile or a release QualificationEnvironment. The v0.9 Ubuntu 24.04/amd64/QEMU-TCG/headless environment is an exact qualification substrate for the Linura layer; it does not replace `arch-hyprland-v1` as the first interactive workstation PlatformProfile.

- Put distro/compositor assumptions in profiles, packaging, providers, or executors.
- Update `profiles/arch-hyprland-v1.toml` and its hardware/workstation evidence when that PlatformProfile changes.
- Keep QualificationEnvironment identity/evidence version-scoped and separate from portable MachineProfile intent.
- A package being available is not equivalent to a feature or PlatformProfile being support-qualified.
- Never let evidence for one QualificationEnvironment silently qualify another PlatformProfile, machine class, architecture or hardware boundary.
