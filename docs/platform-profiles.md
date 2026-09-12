# Platform profiles

Linura does not claim generic “Linux support.” Concrete product/platform support is expressed through explicit **PlatformProfiles** that define an operating substrate and tested compatibility envelope.

`arch-hyprland-v1` remains Linura's **first interactive workstation PlatformProfile** under ADR 0003.

PlatformProfiles specify:

- distro/base package assumptions;
- init/session/compositor;
- selected providers;
- minimum supported subsystem versions;
- enabled Linura features;
- packaging/update/recovery expectations;
- exact qualification evidence required for a release support claim.

## Do not conflate three different concepts

Linura uses three related but distinct abstractions:

- **PlatformProfile** — concrete implementation/support envelope such as `arch-hyprland-v1`;
- **MachineProfile** — portable declarative description of what a machine should become; it is intentionally not tied to one distro/provider implementation;
- **QualificationEnvironment** — exact reproducible substrate used to qualify a bounded release claim.

The v0.9 Ubuntu 24.04/amd64/QEMU-TCG/headless environment is a **QualificationEnvironment**, not a replacement PlatformProfile and not a portable MachineProfile. It exists to prove the Linura control-plane/adoption/update/recovery path before the broader workstation experience is support-qualified.

Passing v0.9 qualification therefore does not mark `arch-hyprland-v1` supported, and it does not change Linura's first interactive workstation direction.

## Compatibility states

- **supported:** covered by the exact release qualification contract for the named PlatformProfile/environment;
- **experimental:** implementation/evidence exists, but the boundary is explicitly Experimental;
- **unsupported:** deliberately outside the contract;
- **unknown:** capability detection could not establish support.

Adding Fedora/Ubuntu workstation profiles should create new PlatformProfiles sharing providers where possible; do not add distro conditionals throughout the core.

A QualificationEnvironment may later inform or graduate into a PlatformProfile only through an explicit architecture/support decision and its own acceptance evidence.
