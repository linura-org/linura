# Supported-install security checklist

Linura has two distinct security qualification contexts that must not be conflated.

## Installer-capable PlatformProfiles

The `arch-hyprland-v1` development PlatformProfile does not qualify as a supported workstation installation until tests demonstrate all required installer properties on a clean install, including:

- encrypted root/storage according to the PlatformProfile;
- inbound firewall deny-by-default;
- SSH disabled until explicitly enabled through an approved intent/action;
- untrusted package sources disabled until explicitly enabled;
- baseline snapshot/factory-reset anchor when Btrfs/Snapper is selected;
- native shell/package-manager recovery path without a model provider;
- update guard does not prevent deliberate break-glass repair;
- First Boot can complete using deterministic defaults or imported profile when offline.

These requirements belong to the Arch/Hyprland workstation installer boundary. They remain relevant and are not replaced by v0.9.

## v0.9 QualificationEnvironment adoption

The v0.9 Ubuntu 24.04/amd64/QEMU-TCG/headless QualificationEnvironment begins from an independently verified existing base image. Its security claim therefore must not imply that Linura itself created guest disk encryption, partitioned storage or installed the bootloader.

Before v0.9 First Boot readiness, qualification must instead prove:

- the exact base-image/source identity and digest were verified;
- inbound exposure is deny-by-default;
- SSH/remote access is disabled initially and cannot be enabled implicitly by headless/unattended mode;
- untrusted package/software sources are disabled;
- persistent Linura state follows the qualified durability/migration contract;
- any bootstrap networking is explicit, bounded and separate from final managed networking;
- a restorable recovery checkpoint is verified;
- native recovery remains available without First Boot, a model provider or network access;
- offline/default/Library/import/unattended-local paths do not weaken the same authority lifecycle.

Any future storage-at-rest guarantee for this QualificationEnvironment must be stated explicitly and backed by environment-specific evidence. It cannot be inferred from the workstation PlatformProfile's installer policy.
