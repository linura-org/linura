# First-boot product architecture

> **Maturity:** v0.9.0 released and independently verified. `linura-firstboot` is an `integrated-experimental` distributable client for the release-qualified v0.9 QualificationEnvironment. This remains a bounded Experimental reference-environment claim, not generic Ubuntu/Linux or workstation support.

The Linura First Boot entry point is:

> **What do you want this computer to become?**

First Boot runs only after a bounded base environment exists. It is responsible for collecting/selecting declarative source material, checking the target against the bounded QualificationEnvironment, requiring fresh target evidence and a fresh plan, establishing recovery readiness, and submitting exact non-authorizing material to Linura Control.

It is **not** the authority plane and it is **not** a generic Linux installer.

ADR 0029 defines the v0.9 QualificationEnvironment, deferred-owner and unattended-provisioning boundaries while ADR 0003 remains active for the first interactive workstation PlatformProfile.

## Released v0.9 QualificationEnvironment

The release-qualified v0.9 reference environment is intentionally narrow:

- QualificationEnvironment ID: `qualification/ubuntu-24.04-lts/amd64/qemu-tcg-headless`;
- Ubuntu 24.04 LTS server;
- amd64 / `x86_64`;
- headless interaction model;
- QEMU TCG virtualization;
- systemd;
- pinned Ubuntu cloud image `https://cloud-images.ubuntu.com/releases/noble/release-20260725/ubuntu-24.04-server-cloudimg-amd64.img`;
- SHA-256 `d1940f7d69d343355e183dff1e08a59852d32e7309baa7a4bad8365b11b005ac`.

This environment completed the v0.9 dedicated Linura-install/First Boot/update/recovery/migration qualification, Trusted Release Proof, immutable tag-last publication and independent release verification. It is therefore release-qualified as the exact Experimental **QualificationEnvironment** above; that does not make it an Ubuntu PlatformProfile.

The candidate says nothing about bare metal, full-disk installation, dual boot, desktop Ubuntu, arm64, workstations, edge nodes or other VM/cloud configurations. The pinned Ubuntu image is the base substrate; v0.9 proves the Linura layer on top of it rather than claiming to have installed the underlying operating system.

## Source paths

First Boot has explicit typed source classes:

- fresh intent;
- deterministic default profile;
- local Library Setup;
- local Library MachineProfile;
- portable Setup import;
- portable MachineProfile import;
- recovery checkpoint.

Portable sources require an integrity digest. A Library or imported object remains declarative source material, not executable history.

Changing source invalidates discovery, observation, plan and recovery state derived from the previous source.

## Provisioning and ownership modes

First Boot distinguishes **machine provisioning** from **owner enrollment**. The machine, the person/operator preparing it and the eventual owner are not the same authority identity by default.

The v0.9 durable architecture models and qualifies:

1. **interactive owner provisioning** — the eventual owner is present;
2. **prepare for another owner** — an operator prepares the machine but stops at `owner-enrollment-pending` without creating fake final-owner credentials;
3. **unattended/headless provisioning** — a bounded declarative Provisioning Manifest selects allowed provisioning inputs without an interactive wizard.

The **release-exposed production entry point in v0.9 is only mode 2**: `linura-firstboot --bootstrap <absolute-state-root>`. Interactive-owner and unattended-manifest selection remain qualified internal contracts, not user-facing v0.9 CLI promises. Native recovery remains a separately qualified recovery path rather than a selectable production provisioning mode.

`--bootstrap` is not a raw-host hardening command. The exact bounded base environment and Q8 policy prerequisites must already be present and observable; First Boot verifies those postconditions and fails closed instead of silently enabling firewall/package/remote-access policy on an arbitrary unqualified Ubuntu host.

Deferred owner enrollment must be restart-safe and idempotent. Rebooting into enrollment must not replay completed machine-provisioning effects, and preparer approvals/credentials must not silently become final-owner authority.

Owner password material, private keys and other secret values are not portable Setup/MachineProfile content and are not stored in ordinary provisioning provenance.

## Unattended provisioning

An unattended path may consume a versioned, bounded, integrity-bound **Provisioning Manifest** from an explicitly qualified local transport such as removable or virtual media.

The manifest may select typed inputs such as provisioning mode, source/profile, deferred-owner state, bounded bootstrap networking and non-secret references to separately protected credential material. It may not contain arbitrary shell snippets, generic commands, policy overrides, executor permits, approval evidence or historical action transcripts.

Manifest integrity says which bytes arrived; it does not grant trust or authority. The receiving machine still validates the QualificationEnvironment, discovers local capabilities/hardware, performs fresh authoritative observation, produces a fresh plan and enters normal Control review/authorization.

## Fresh target convergence

Fresh/default/Library/import/unattended-local paths converge on the same pre-authority sequence:

```text
source/provisioning input
→ QualificationEnvironment discovery
→ fresh authoritative target observation
→ fresh plan exact-bound to that observation and session
→ verified recovery readiness
→ non-authorizing submission to Linura Control
```

First Boot must never directly replay an imported action transcript or historical plan. Adoption always observes the receiving machine again and creates a new plan for that machine.

## Authority boundary

The First Boot client does not receive generic root executor handles, privileged dispatch permits, policy-admin authority or a way to manufacture approval. The production deferred-owner bootstrap has one fixed privileged handoff responsibility: retire the fixed `linura-preparer` OS authority and authenticate that exact postcondition. Its signer cannot create final-owner enrollment evidence or authorize arbitrary mutation.

Its final submission carries exact source/provisioning, target/session, observation, plan and recovery bindings. It carries **no execution authority** and no caller-selected policy decision.

Canonical review/authorization remains inside Linura Control over retained canonical plan material. A First Boot session can establish that source material was selected, the target/reference environment was checked, a fresh plan exists and recovery is ready; it cannot assert that mutation is authorized.

A stale/substituted source, session, observation or plan binding fails closed.

## Bootstrap sequencing

For the v0.9 Linura-on-Ubuntu candidate, the qualified sequence begins from the pinned verified base image:

1. base-environment verification;
2. exact-source Linura installation;
3. persistent-state initialization/migration;
4. security-baseline assessment;
5. provisioning/ownership-mode selection;
6. optional bounded bootstrap networking;
7. hardware/QualificationEnvironment discovery;
8. source selection/adoption;
9. fresh target observation;
10. First Boot planning;
11. recovery checkpoint verification;
12. owner enrollment or `owner-enrollment-pending`;
13. First Boot ready.

A persisted gap or skipped stage is invalid. Resume starts at the first incomplete stage rather than trusting later markers. Repeated first login, crash or reboot must not blindly repeat completed external effects.

Generic future bootstrap types for disk layout, guest full-disk encryption, base-system construction or bootloader work are not a v0.9 support claim. Those destructive OS-installer responsibilities need their own future profile and qualification if Linura chooses to own them.

The v0.9 installation model remains fail closed by default: exact base/source integrity verification, qualified persistent-state durability, inbound/default exposure denied, SSH not automatically enabled, and untrusted package/software sources disabled.

## Network and remote access

Offline operation remains mandatory once all required local material exists.

First Boot separates:

- offline/no-network provisioning;
- temporary explicitly bounded bootstrap connectivity;
- final desired networking, which becomes normal managed state and therefore goes through observe → plan → review → authority → verify.

Headless or unattended does **not** mean remotely open. SSH, VPN or tailnet access requires explicit typed intent and separately qualified security behavior. No remote-access provider gets implicit First Boot authority.

## Hardware adaptation

Hardware detection is an input, not an executor.

Hardware-specific adaptation follows:

```text
discover
→ authoritative observation
→ supported profile/capability resolution
→ deterministic desired state and plan
→ Control review/authority
→ narrow executor
→ independent verification
```

Linura must not add a generic vendor-script escape hatch merely to copy conventional installer convenience. Unsupported/ambiguous hardware stays unsupported or fails closed.

## Recovery requirement

First Boot readiness is not satisfied merely because a plan exists. The pre-authority sequence requires a recovery checkpoint that is:

- integrity-bound;
- verified restorable;
- paired with a native recovery path independent of the First Boot/model/network stack.

TTY/native CLI recovery remains a required escape hatch. A broken UI, unavailable provider or lost network must not trap the machine behind First Boot.

## Offline/default path

First Boot must remain useful without any model provider. The deterministic default, local Library/import and unattended-local paths must work without hosted inference or hosted catalog synchronization once required local installation material exists.

Agent/model interpretation, when used, stays inside the released v0.8 proposal-only contract. It cannot strengthen or replace deterministic planning/recovery/Control gates.

## Hardware and support evidence

`linura-hardware` owns the exact candidate QualificationEnvironment identity and evidence-tier checks. Candidate evidence must be immutably bound to the exact QualificationEnvironment, source commit, base-image digest, VM mode and qualification artifact/run before it can advance a support claim.

The guest-installed `linura-firstboot` binary must be hashed/measured inside the guest and match the exact host-built binary used to produce the acceptance evidence.

The current release is v0.9.0 with `platform_support = "reference-experimental"`. `hardware/support-matrix.json` therefore contains the exact Ubuntu/QEMU QualificationEnvironment in `qualification_environments.release_qualified`, while every `machine_classes.*.release_qualified_profiles` lane remains empty. In particular, `arch-hyprland-v1` is still a development candidate and has not been support-promoted.

## What v0.9 proved and what remains bounded

v0.9.0 has already proved the version-scoped First Boot/reference-environment contract through exact-source qualification and independent release verification, including:

- installation of exact Linura source into the pinned Ubuntu/QEMU substrate;
- bounded interactive/deferred-owner/unattended-local provisioning contracts;
- malformed/tampered manifest rejection;
- offline/no-model behavior;
- authoritative observation/session/plan binding;
- Control-owned review/authorization;
- restart/resume, update interruption, migration/backup/restore and native recovery cases;
- default-deny remote exposure and bounded bootstrap networking;
- immutable qualification evidence and guest binary identity;
- inherited v0.6/v0.7/v0.8 authority/durability gates.

Those results qualify only `qualification/ubuntu-24.04-lts/amd64/qemu-tcg-headless` as the v0.9 Experimental reference environment. They do not qualify a workstation PlatformProfile, generic Ubuntu, bare metal, arbitrary virtualization, additional architectures, or a general OS installer.

## v0.10 boundary

The first coherent broader end-user UI experience remains v0.10 work. The v0.9 headless reference profile does not require Control Center, desktop shell, display/audio/theme/input integration or a general workstation experience, and v0.9 must not pull those claims forward merely to make First Boot appear more complete.
