# Minimal bootstrap, installation and recovery

Linura's product architecture begins before the full desktop exists, but **Linura adoption/bootstrap and OS/platform installation are separate support claims**.

## Current release boundary

v0.9.0 qualifies Linura adoption, First Boot, update/recovery and migration on the exact Ubuntu 24.04/amd64/QEMU-TCG/headless QualificationEnvironment. The underlying Linux base image already exists and is independently verified; v0.9 does not claim that Linura partitioned disks, installed the base operating system, configured full-disk encryption, or installed the bootloader.

The rebaselined v0.10 workstation contract requires one bounded, independently qualified installer lane for the exact `arch-hyprland-v1` profile in addition to adoption. The supported lane must satisfy the profile's encryption/security requirements and prove restart/recovery semantics; generic dual-boot, RAID, arbitrary custom partitioning and every-firmware support remain outside the claim unless separately qualified.

Recovery must not require the graphical client, internet access or a model provider. Native CLI/TTY and profile-appropriate snapshot/package-repair paths must remain available, and administrator out-of-band repair must not be trapped behind Linura UI state.

## Installer-capable profiles

A future installer-capable PlatformProfile may own destructive OS-installation work, but only after its contract defines and qualifies transaction boundaries, storage/encryption policy, snapshot points, boot rollback, exact hardware/support reporting, offline behavior, interruption recovery and the boundary between installer authority and ordinary Linura Control.

See [Installer and bootstrap](installer-bootstrap.md), [First Boot](first-boot.md), and [v0.10 qualification](qualification/v0.10.0.md).
