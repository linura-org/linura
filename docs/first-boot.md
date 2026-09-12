# First-boot product architecture

> **Maturity:** v0.9 candidate implementation, not yet a released platform-support claim. `linura-firstboot` is activated as an `integrated-experimental` v0.9 client and distributable binary, but `v0.8.0` remains the current release until the full v0.9 protected qualification/release lifecycle completes.

The Linura First Boot entry point is:

> **What do you want this computer to become?**

First Boot runs only after a bounded base environment exists. It is responsible for collecting/selecting declarative source material, checking the target against the bounded QualificationEnvironment, requiring fresh target evidence and a fresh plan, establishing recovery readiness, and submitting exact non-authorizing material to Linura Control.

It is **not** the authority plane and it is **not** a generic Linux installer.

ADR 0029 defines the v0.9 QualificationEnvironment, deferred-owner and unattended-provisioning boundaries while ADR 0003 remains active for the first interactive workstation PlatformProfile.

## Current v0.9 candidate QualificationEnvironment

The first candidate is intentionally narrow:

- QualificationEnvironment ID: `qualification/ubuntu-24.04-lts/amd64/qemu-tcg-headless`;
- Ubuntu 24.04 LTS server;
- amd64 / `x86_64`;
- headless interaction model;
- QEMU TCG virtualization;
- systemd;
- pinned Ubuntu cloud image `https://cloud-images.ubuntu.com/releases/noble/release-20260725/ubuntu-24.04-server-cloudimg-amd64.img`;
- SHA-256 `d1940f7d69d343355e183dff1e08a59852d32e7309baa7a4bad8365b11b005ac`.

This is a **candidate**, chosen because Linura already has exact-source disposable acceptance infrastructure on this image shape. It becomes a release-qualified Experimental QualificationEnvironment only after v0.9's dedicated Linura-install/First Boot/update/recovery/migration qualification, Trusted Release Proof, immutable publication and independent verification all succeed.

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

The v0.9 architecture supports:

1. **interactive owner provisioning** — the eventual owner is present;
2. **prepare for another owner** — an operator prepares the machine but stops at `owner-enrollment-pending` without creating fake final-owner credentials;
3. **unattended/headless provisioning** — a bounded declarative Provisioning Manifest selects allowed provisioning inputs without an interactive wizard.

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

The First Boot client does not receive root executor handles, privileged dispatch permits, policy-admin authority or a way to manufacture approval.

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

While the current release is v0.8 with `platform_support = "none"`, the support matrix remains empty. Candidate code must not pre-announce platform support.

## What v0.9 still must prove

The first implementation slice establishes the typed contracts and invariants. v0.9 is not release-ready until the repository also proves:

- exact-source Linura installation into the candidate VM;
- interactive-owner, deferred-owner and unattended-local First Boot modes;
- malformed/tampered Provisioning Manifest rejection;
- offline/no-model First Boot inside the guest;
- exact authoritative observation/session/plan binding;
- canonical Control-owned review/authorization rather than caller-manufactured approval;
- bootstrap/provisioning restart/resume and corruption/failure cases;
- update interruption and indeterminate-outcome recovery;
- persistent-state migration plus backup/restore;
- native recovery when First Boot is unavailable;
- bounded bootstrap networking and default-deny remote exposure;
- typed hardware adaptation and unsupported-hardware rejection;
- immutable support evidence and guest binary identity verification;
- security/adversarial qualification;
- inherited v0.6/v0.7/v0.8 authority and durability gates;
- Trusted Release Proof, immutable tag-last publication, independent verification and protected closure.

See [v0.9 milestone contract](milestones/v0.9.0.md), [ADR 0029](adr/0029-v09-first-boot-reference-and-provisioning-boundary.md) and [v0.9 qualification](qualification/v0.9.0.md).

## v0.10 boundary

The first coherent broader end-user UI experience remains v0.10 work. The v0.9 headless reference profile does not require Control Center, desktop shell, display/audio/theme/input integration or a general workstation experience, and v0.9 must not pull those claims forward merely to make First Boot appear more complete.
