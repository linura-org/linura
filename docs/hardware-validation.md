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

For the current published v0.9.0 release, `platform_support = "reference-experimental"`. The QualificationEnvironment lane contains exactly `qualification/ubuntu-24.04-lts/amd64/qemu-tcg-headless`; the workstation/server/edge `release_qualified_profiles` lanes remain empty. A future release may change either lane only through its protected qualification/support-promotion contract.

For v0.9, the release-qualified QualificationEnvironment is:

`qualification/ubuntu-24.04-lts/amd64/qemu-tcg-headless`

It proves the Linura installation/adoption/First Boot/update/recovery/migration control path on an exact Ubuntu/QEMU substrate. That completed qualification does **not** qualify an Ubuntu server PlatformProfile and does not qualify `arch-hyprland-v1`.

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


## Maintained physical workstation fixtures

v0.10 Level C/Q11 requires a maintained **physical workstation**, not merely a machine whose provider markets it as dedicated hardware. The lane must independently prove no virtualization and must retain the real workstation identities and interactions required by Q11: CPU, GPU/driver, connected display geometry/refresh/scale, Wayland/Hyprland, real keyboard/pointer behavior, accessibility/visual evidence, provider identities and the physical Session1 effect/recovery cases.

A cloud VM cannot satisfy Level C. A bare-metal datacenter server may provide useful supplementary hardware evidence, but it satisfies Level C only if the exact machine also meets the workstation GPU/display/input/session evidence contract; bare-metal status alone is insufficient.

Maintained fixtures are enrolled outside the repository at `/etc/linura/qualification-fixture.json` by default. The file is intentionally minimal and must not contain serial numbers, MAC addresses, hostnames, usernames, IP addresses, account IDs or other owner secrets. It follows `schemas/v010-maintained-workstation-fixture.v1.schema.json` and is required to be root-owned, single-link, non-symlink and not group/world writable. A representative contract is:

```json
{
  "schema_version": 1,
  "fixture_id": "linura-workstation-01",
  "profile_id": "arch-hyprland-v1",
  "machine_class": "workstation",
  "evidence_tier": "maintainer_hardware",
  "physical_hardware": true
}
```

The fixture contract is machine identity/configuration, not case execution authority and not evidence. The external controller identity belongs to each Q11 case's execution provenance rather than the machine fixture. Level C independently probes virtualization and the live machine on every run and binds the fixture-contract digest into retained capture evidence.

Retained Level C monitor evidence is sanitized before it is written: connector name, vendor/model, geometry, refresh, scale, transform and focus state may be retained, while Hyprland's raw `serial`, `description` and unrelated monitor fields are discarded. Raw `hyprctl monitors -j` output must never be committed or published as qualification evidence.


### Level C run-state and evidence boundary

The maintained-workstation runner uses a bounded lifecycle rather than arbitrary remote commands. A full Q11 attempt starts with `begin-run`, which requires a clean exact source checkout, the enrolled physical fixture, a successful physicality/session doctor, and every prerequisite product slice. It freezes one request for each canonical Q11 case into private state outside the source tree. External controllers may then execute only the named case mechanisms and submit digest-bound case attestations through `record-case`; substitutions of case, mechanism, source, environment, boot identity, controller provenance, event log, or accepted evidence digest fail closed.

`finalize-run` requires all nine case attestations and validates the complete candidate evidence bundle with `tools/check_v010_workstation_qualification.py` against an immutable archive of the exact source. This is candidate validation only: the runner writes `evidence_ready=false` and `release_support_promotion=false`, and never edits the real qualification contract. Q11 becomes release evidence only through the later reviewed promotion path after an actual maintained physical workstation has passed the canonical verifier.

Level C screen recording remains optional supporting evidence. Reused evidence directories hold one current fixture: a new Level C capture clears **all** previous fixture-keyed recordings and sidecars before replacing the shared machine snapshots, including when the new capture is not recorded. Use separate evidence roots to preserve historical captures. A root-owned fixture identity is still required for each run, and the user-owned global recorder lock is acquired through a private no-follow, non-truncating, single-link descriptor before any existing evidence is touched. Recorded Level C capture automatically stops with a bounded finalization margin before the recording contract's maximum duration. Recorded evidence is re-verified after publication, and its digest file is emitted from the verifier's stable snapshot digest rather than by independently reopening the mutable recording path.
