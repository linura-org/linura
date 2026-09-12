# ADR 0029 — v0.9 First Boot qualification environment and provisioning boundary

- **Status:** Accepted
- **Date:** 2026-09-12
- **Refines:** ADR 0003 by separating the first qualification environment from the first interactive workstation platform profile

## Context

ADR 0003 selected `arch-hyprland-v1` as Linura's first explicit platform profile. That decision remains useful: Linura still needs one opinionated interactive workstation profile before claiming broad desktop support.

The release-qualification sequence has since gained a second need that ADR 0003 did not name. Before the interactive workstation profile is support-qualified, Linura needs a highly reproducible environment in which the Linura layer itself can be installed, adopted, observed, updated, interrupted, recovered and migrated end to end.

The existing disposable-system proof substrate already pins an Ubuntu 24.04 LTS amd64 cloud image and QEMU/TCG execution. v0.9 therefore uses that exact shape as its first **QualificationEnvironment**. This does not replace `arch-hyprland-v1`, and it does not redefine Ubuntu/headless as Linura's first user-facing platform direction.

First Boot also needs a precise product boundary. Real machines may be prepared by an administrator, imaging service or operator before the eventual owner is present. Headless machines may be provisioned without an interactive wizard. At the same time, provisioning input, portable profiles and unattended configuration must never become an alternate authority path, carry historical approval, or introduce arbitrary privileged scripting.

## Decision

### 1. Keep three different profile/environment concepts explicit

Linura distinguishes three concepts that must not be conflated:

1. **PlatformProfile** — a concrete implementation/support envelope for an operating environment: distro/base assumptions, init/session/compositor, providers, packaging, update/recovery behavior and compatibility evidence. `arch-hyprland-v1` remains the first interactive workstation PlatformProfile under ADR 0003.
2. **MachineProfile** — portable declarative user intent describing what a machine should become. It carries machine class, Setups, intents and constraints; it is not tied to one distro and never carries historical execution authority.
3. **QualificationEnvironment** — an exact reproducible substrate used to prove a bounded Linura release claim. It may be narrower and less user-facing than a PlatformProfile and does not become a portable MachineProfile.

A QualificationEnvironment may eventually graduate into or inform a PlatformProfile, but no such promotion is implicit.

### 2. v0.9 qualification environment

For v0.9, the first candidate QualificationEnvironment is exactly:

`qualification/ubuntu-24.04-lts/amd64/qemu-tcg-headless`

with:

- machine class context: `server`;
- Ubuntu 24.04 LTS server cloud image;
- amd64 / `x86_64`;
- QEMU TCG;
- headless operation;
- systemd;
- the exact base-image URL and SHA-256 named by the v0.9 milestone contract.

This environment exists to qualify the Linura layer: installation/adoption, First Boot, local authority, update/recovery, persistent-state migration and exact-source acceptance.

It is **not** the first interactive workstation PlatformProfile, does not supersede ADR 0003, and does not make Ubuntu/headless the default Linura product personality.

### 3. ADR 0003 remains active for the interactive workstation profile

`arch-hyprland-v1` remains the first interactive workstation PlatformProfile and the first target for the opinionated desktop/workstation experience.

Its future support qualification remains separate from v0.9's headless QualificationEnvironment and must cover the workstation-specific concerns already named by Linura: compositor/session behavior, display/input/audio, suspend/resume, GPU variation, workstation recovery, accessibility and user-visible update/reboot behavior.

Passing v0.9 qualification must not silently mark `arch-hyprland-v1` supported, and work on `arch-hyprland-v1` must not weaken or bypass the v0.9 control-plane qualification.

### 4. Three distinct lifecycle phases

Linura separates:

1. **base-environment establishment** — obtain and independently verify the bounded Linux substrate on which Linura will run;
2. **machine provisioning/adoption** — install/initialize Linura, discover the target, select declarative source material, observe, plan, establish recovery readiness and submit non-authorizing material to Control;
3. **owner enrollment/personalization** — establish the eventual human owner's local identity and owner-specific settings/credentials.

These phases may occur in one interactive session, but they are not required to. A machine may be prepared for another owner and stop in an explicit `owner-enrollment-pending` state without inventing credentials or weakening recovery/security policy.

Machine identity, installer/operator identity and eventual owner identity are distinct. Preparing a machine for another owner never grants the preparer durable owner approval for future plans.

### 5. Deferred owner enrollment

v0.9 must support the architecture for deferred owner enrollment even though its QualificationEnvironment is headless.

A deferred machine:

- has a verified Linura installation and recovery path;
- retains fail-closed network/security defaults;
- contains no fabricated final-owner credentials;
- may contain only explicitly permitted bootstrap identity material needed to complete enrollment;
- resumes deterministically into owner enrollment rather than replaying completed provisioning work;
- requires fresh local authority for owner-specific changes.

Credentials, password material and private keys are never stored inside portable Setup/MachineProfile artifacts or ordinary provisioning provenance.

### 6. Unattended provisioning is declarative input, not authority

A v0.9 unattended path may consume a versioned, bounded, integrity-bound **Provisioning Manifest** supplied through local removable/virtual media or another explicitly qualified local transport.

The manifest may select only typed provisioning inputs such as:

- machine/provisioning mode;
- a deterministic default or specific local/portable Setup/MachineProfile source;
- whether final owner enrollment is deferred;
- bounded bootstrap network intent;
- non-secret references to separately handled credential/secret material;
- host identity inputs such as an explicitly bounded hostname where supported.

The manifest must not contain executable shell snippets, arbitrary commands, executor permits, approval evidence, policy overrides, historical action transcripts or model-generated authority.

Manifest integrity proves only which bytes were supplied. It does not make those bytes trusted. The receiving machine still performs local qualification-environment validation, hardware/capability discovery, fresh authoritative observation, fresh planning and Control-owned review/authorization.

### 7. Bootstrap networking and remote access

Offline operation remains mandatory once required local installation material is present.

Network bootstrap is explicit and bounded. First Boot distinguishes:

- no-network/offline provisioning;
- temporary bootstrap connectivity needed to obtain explicitly allowed material;
- final desired networking, which is ordinary managed state and therefore enters the normal observe/plan/review/authority lifecycle.

Inbound access is fail closed by default. SSH or another remote-access mechanism is never enabled merely because the machine is headless or unattended. Enabling remote access requires explicit typed intent plus its own qualified security path. Future VPN/tailnet providers follow the same rule rather than receiving special authority.

### 8. Hardware adaptation is typed and reviewable

Hardware-specific adaptation must not become an arbitrary vendor-script escape hatch inside Linura authority.

The allowed pattern is:

`discover → authoritative observation → match supported capability/environment → deterministic desired state/plan → Control review/authority → narrow executor → independent verification`

Unsupported or ambiguous hardware fails closed or remains outside the support claim. Vendor/model detection alone cannot authorize a mutation.

### 9. First-run work is durable and idempotent

First Boot/provisioning stages are restartable state-machine transitions, not a collection of best-effort login scripts. Reboot, crash or repeated first login must not blindly repeat completed external effects.

Durable stage identity, exact input binding and recovery/reconciliation determine whether work is complete, needs fresh planning, or is indeterminate.

### 10. v0.9 installer claim is intentionally narrow

The pinned Ubuntu cloud image is the v0.9 base QualificationEnvironment. v0.9 qualifies **Linura installation/adoption on that exact existing Linux substrate**.

It does not claim that Linura owns or supports the preceding Linux disk partitioning, guest full-disk encryption, base-system construction, bootloader installation, dual-boot layout or bare-metal OS installation process.

Those capabilities belong to an explicit installer/PlatformProfile path and require separate destructive-storage/boot qualification. The existing Arch/Hyprland image work remains relevant to that future workstation path.

## Security assessment

This decision adds unattended/deferred provisioning as an explicit trust boundary and clarifies that QualificationEnvironment evidence is not user intent or authority.

Provisioning manifests, removable media, imported MachineProfiles, network bootstrap inputs, claimed hardware identity and qualification-environment detection are untrusted inputs. They cannot establish approval or execution authority. Secret values stay out of portable declarative artifacts and ordinary provenance; secret references are resolved through separately protected local mechanisms. Remote access remains disabled unless explicitly and safely requested. Deferred-owner flows must prevent installer/operator credentials or approvals from silently becoming final-owner authority.

The existing malicious-profile, cross-class adoption, approval replay, observation freshness, break-glass recovery and command-injection mitigations remain mandatory.

## Consequences

- ADR 0003 remains coherent and active: `arch-hyprland-v1` is still Linura's first interactive workstation PlatformProfile.
- v0.9 can qualify the Linura control plane on a reproducible Ubuntu/QEMU/headless environment without changing Linura's workstation product direction.
- PlatformProfile, MachineProfile and QualificationEnvironment have distinct semantics and evidence.
- Omarchy-like prepare-for-another-owner and unattended workflows can be supported without copying a script-centric authority model.
- First Boot can support interactive, deferred-owner and unattended entry paths while all of them converge on the same local observation/planning/Control boundaries.
- Headless operation does not imply automatic SSH exposure.
- Hardware adaptation stays inside typed capability/executor boundaries.
- A future full OS installer and the Arch/Hyprland workstation profile remain possible, but each must earn its own exact support evidence rather than inheriting v0.9's QualificationEnvironment evidence.
