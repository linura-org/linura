# Installer and bootstrap

Linura distinguishes **OS/platform installation** from **Linura adoption/bootstrap on an existing verified Linux base**. Both are staged and checkpointed; neither is one large shell script.

This distinction is important for v0.9: the Ubuntu/QEMU/headless QualificationEnvironment is supplied as an independently verified base image. v0.9 qualifies the Linura layer on top of that base and does not claim that Linura partitioned the disk, created guest full-disk encryption, built the base OS or installed the bootloader.

## PlatformProfile installer lifecycle

Concrete installer-capable PlatformProfiles may own destructive OS-installation stages such as:

1. preflight;
2. disk layout;
3. encryption;
4. base system;
5. platform packages;
6. bootloader;
7. security baseline;
8. baseline snapshot;
9. user provisioning;
10. first-boot-ready.

`arch-hyprland-v1` remains the first interactive workstation PlatformProfile and the existing ArchISO work remains the development path for that kind of installer. Its installation/security requirements do not become v0.9 Ubuntu QualificationEnvironment claims.

A persisted installer ledger must resume from the first incomplete stage and reject impossible out-of-order state.

## v0.9 Linura adoption/bootstrap lifecycle

`linura-bootstrap` uses a separate v0.9 sequence for the Linura-on-existing-Linux claim:

1. base-environment verification;
2. exact-source Linura installation;
3. persistent-state initialization/migration;
4. Linura adoption security baseline;
5. provisioning/ownership-mode selection;
6. bootstrap-connectivity resolution (`offline` or explicitly bounded network bootstrap);
7. hardware/QualificationEnvironment discovery;
8. declarative source selection;
9. fresh authoritative target observation;
10. First Boot planning;
11. recovery checkpoint verification;
12. owner-enrollment resolution (`enrolled` or explicit `owner-enrollment-pending`);
13. first-boot-ready.

This sequence deliberately contains no disk-layout, bootloader, base-system-construction or guest-full-disk-encryption stage. Those responsibilities belong to an installer-capable PlatformProfile and require separate qualification.

The v0.9 ledger is monotonic and restart-safe. Reboot/crash/repeated first-run resumes at the first incomplete stage and cannot treat a later marker as proof that an earlier safety boundary completed.

## Modes

OS/platform installer modes remain:

- **interactive** — human-guided installation;
- **non-interactive** — automation/image installation without a TTY;
- **recovery** — repair/bootstrap continuation with minimum UI dependency.

v0.9 provisioning additionally distinguishes:

- **interactive owner**;
- **prepare for another owner**;
- **unattended local**;
- **recovery/resume**.

These are provisioning modes, not authority classes.

## Security boundaries

For installer-capable PlatformProfiles such as the Arch/Hyprland development profile, the supported-install policy may require properties such as LUKS2-class encryption because Linura owns that installer boundary.

For the v0.9 QualificationEnvironment, Linura must not falsely claim guest disk-encryption work it did not perform. Instead the v0.9 adoption baseline requires at minimum:

- exact base-image/source integrity verification;
- inbound exposure deny-by-default;
- SSH disabled initially and never enabled merely because the target is headless;
- untrusted package/software sources disabled;
- qualified persistent-state durability/migration behavior;
- verified restorable recovery checkpoint;
- native break-glass recovery independent of First Boot, a model provider or network connectivity.

Any future storage-at-rest guarantee for a QualificationEnvironment or PlatformProfile must be explicit and separately evidenced.

## Arch/Hyprland development image

`packaging/arch/archiso/airootfs/etc/linura/install-policy.json` remains the machine-readable development policy for the Arch image profile.

The development image build stages from ArchISO `releng`, overlays Linura policy/profile files, and merges `packages.linura`; this keeps boot infrastructure inherited from a known ArchISO base while Linura owns its explicit additions. The image harness also stages the exact compiled Linura binaries into the image. The Arch ALPM update-guard hook is copied only in the same staging step that installs `linura-update-guard`, preventing a dangling package-manager hook from entering an image.

None of that Arch workstation installer evidence is automatically inherited by the v0.9 Ubuntu QualificationEnvironment, and v0.9 qualification does not automatically qualify the Arch PlatformProfile.
