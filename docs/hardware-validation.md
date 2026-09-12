# Hardware validation

A Linux system cannot claim production support based only on unit tests, one developer laptop, or one disposable VM.

## Evidence tiers

`linura-hardware` orders evidence from weakest to strongest:

1. unknown;
2. fixture-only;
3. virtual machine;
4. community hardware;
5. maintainer hardware;
6. release-qualified.

The evidence tier describes the strength of evidence. It does **not** by itself say what semantic scope that evidence qualifies.

## Separate support scopes

`hardware/support-matrix.json` deliberately separates two kinds of release-qualified scope:

- `qualification_environments.release_qualified` — exact reproducible release/test substrates used to prove bounded Linura behavior;
- `machine_classes.<class>.release_qualified_profiles` — concrete PlatformProfiles that are actually release-qualified as supported workstation/server/edge operating environments.

These lanes are intentionally different. Evidence for a QualificationEnvironment never silently promotes a PlatformProfile, and evidence for one PlatformProfile never transfers to another profile, machine class, architecture or hardware boundary.

While the current published release has `platform_support = "none"`, both lanes must remain empty.

For v0.9, the candidate QualificationEnvironment is:

`qualification/ubuntu-24.04-lts/amd64/qemu-tcg-headless`

It exists to prove the Linura installation/adoption/First Boot/update/recovery/migration control path on an exact Ubuntu/QEMU substrate. Qualifying it does **not** automatically qualify an Ubuntu server PlatformProfile and does not qualify `arch-hyprland-v1`.

`arch-hyprland-v1` remains Linura's first interactive workstation PlatformProfile under ADR 0003 and requires its own workstation-specific evidence before it can enter `machine_classes.workstation.release_qualified_profiles`.

## Canonical machine classes

The canonical target classes are:

- `workstation`;
- `server`;
- `edge`.

Declaring these classes in the support matrix is **not** a support claim. Each class starts with an empty `release_qualified_profiles` list. A release may add an exact PlatformProfile only when its distribution/desktop-or-headless boundary, architecture, hardware assumptions, relevant domain capabilities and qualification evidence are explicitly bounded by the release contract.

Enterprise/fleet is not a machine class. It is an optional management topology over individually authoritative workstation, server and edge nodes.

## Profile-qualified support

Product/platform support must be stated against an exact PlatformProfile rather than an entire machine class. Conceptually:

```text
machine class
→ PlatformProfile
→ architecture
→ hardware/domain evidence
→ release qualification
```

For example, evidence for a future `workstation/arch-hyprland-amd64` PlatformProfile would not automatically qualify `server/ubuntu-amd64`, an arm64 edge gateway, or every workstation.

A QualificationEnvironment follows a parallel but separate chain:

```text
QualificationEnvironment
→ exact base-image identity
→ exact architecture/virtualization/runtime shape
→ exact-source Linura evidence
→ release qualification
```

A QualificationEnvironment may later inform a PlatformProfile, but promotion requires an explicit contract and the missing real-world/product evidence; it is never automatic.

Domain maturity D0–D7 and profile/environment qualification answer different questions. A domain capability can be mature in implementation while remaining unqualified on a specific PlatformProfile or QualificationEnvironment.

## Class-specific qualification concerns

### Workstation

Typical matrix areas include Intel/AMD/NVIDIA graphics, Wi-Fi/Bluetooth, USB-C docks, HiDPI and mixed-DPI displays, NVMe/SATA/Btrfs storage, suspend/resume, batteries, audio devices, interactive session behavior and accessibility-relevant input/display paths.

### Server

Typical matrix areas include headless boot, NIC/storage/controller variants, long-running service behavior, remote recovery, container/virtualization host features, GPU/accelerator use where declared, maintenance/reboot behavior and resilience without a desktop session.

### Edge

Typical matrix areas include arm64 and other explicitly supported architectures, constrained CPU/RAM/storage, intermittent/offline networking, power loss, unattended recovery, image/OTA update and rollback behavior, device identity, removable/flash storage and specialized peripherals/accelerators.

## Sanitized fixtures

Fixtures under `hardware/fixtures/` contain structural observations only. They must not contain serial numbers, MAC addresses, hostnames, usernames, IP addresses, account identifiers, or other machine-owner secrets.

A support claim must cite exact evidence. Unknown or mismatched hardware/environment state degrades explicitly rather than pretending to be supported.
