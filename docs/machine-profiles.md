# Machine profiles, reusable setups, personality and replay

A machine profile is a portable description of **what a whole machine should become**, not a frozen list of package names.

Profiles compose reusable setups, standalone intents and portable constraints.

```text
Machine Profile
├── machine class: workstation | server | edge
├── Setup: base development
├── Setup: Rust development
├── Setup: travel security
├── standalone intent: use external 4K display
└── portable constraints/preferences
```

Examples:
- AI development workstation
- distraction-minimized writing workstation
- headless container server
- GPU compute server
- edge gateway
- unattended appliance
- travel-security workstation profile
- accessible high-contrast workstation

## MachineProfile is not PlatformProfile or QualificationEnvironment

Linura deliberately keeps three concepts separate:

- a **MachineProfile** is portable user-owned desired-machine intent;
- a **PlatformProfile** is a concrete product/support implementation envelope such as `arch-hyprland-v1`;
- a **QualificationEnvironment** is an exact reproducible substrate used to prove a bounded release claim, such as the v0.9 Ubuntu/QEMU/headless environment.

A MachineProfile therefore does not say “install this distro image” or “replay these commands.” It expresses desired role, Setups, intents and constraints. The target is independently observed and the planner resolves those portable requirements against whatever PlatformProfile/capabilities are actually supported there.

Likewise, a release-qualified QualificationEnvironment is not automatically a portable MachineProfile or a supported PlatformProfile. Qualification evidence and user intent remain separate data with separate authority semantics.

## Target machine classes

Linura has three canonical target machine classes:

- **workstation** — interactive personal machines, including general-purpose desktops/laptops, developer workstations, AI/ML workstations, creative workstations, kiosks and other locally interactive machines;
- **server** — primarily headless or remotely administered machines, including application/database servers, container hosts, virtualization hosts, GPU/compute servers and infrastructure hosts;
- **edge** — constrained, appliance-like or intermittently connected Linux nodes, including gateways, edge-compute nodes, industrial devices and unattended embedded/headless systems.

These are target architecture classes, **not current support claims**. A class becomes supported only when an exact PlatformProfile is named and qualified by a published release contract.

`developer machine` is not a fourth class. It is normally a workstation profile, for example `workstation/ai-development` or `workstation/rust-development`. A developer may also intentionally use a server or edge profile when that is the machine's actual operating role.

## Machine class is orthogonal to system domains

Machine classes consume Linura system domains; they are not domains themselves. For example, networking, services, packages, storage and updates may apply to all three classes while displays/audio may be central to workstations and optional or specialized on servers/edge.

Domain capability maturity remains tracked by D0–D7 in [System domain map](system-domains.md). Machine/platform support answers a different question: **on which exact machine class + PlatformProfile + architecture/hardware boundary is that capability qualified?**

A capability can therefore be mature in source without being supported on every class. For example, a future `network.read` capability could be D6 Experimental supported for one workstation PlatformProfile, D5 release-qualified for one server profile, and only D3 integrated for an edge profile.

## Fleet is an optional overlay, not a machine class

Enterprise/fleet management is a deployment and control topology over locally authoritative Linura machines. A fleet may contain any mixture of workstation, server and edge nodes:

```text
            optional fleet plane
                     │
        ┌────────────┼────────────┐
        │            │            │
  workstation      server        edge
        │            │            │
        └────────────┼────────────┘
                     │
      local Linura authority
          on every machine
```

Fleet services never become a fourth machine class and never replace each node's local Linura authority, recovery path or local Library semantics. See [Enterprise and fleet architecture](enterprise.md).

## Setup vs profile

A **Setup** is a reusable slice of configuration such as Rust development, PostgreSQL development or a security posture. It can be used independently and included by multiple profiles.

A **MachineProfile** composes a larger machine personality from a machine class, setups, standalone intents and portable constraints.

See [Reusable setups and the Linura Library](reusable-setups.md).

## Example profile shapes

A developer workstation may express:

```text
machine_class = workstation
profile = ai-development

requirements:
- interactive desktop
- GPU compute when available
- containers
- local development toolchains
```

A server profile may express:

```text
machine_class = server
profile = container-host

constraints:
- headless
- remote administration
- maintenance-window reboot policy
- service availability requirements
```

An edge profile may express:

```text
machine_class = edge
profile = gateway

constraints:
- intermittent connectivity
- bounded CPU/RAM/storage
- unattended recovery
- staged/rollback-capable updates
```

These examples describe intent and constraints. They do not freeze provider implementations, package names or a distribution into the portable source of truth.

## Portable replay

Export/replay preserves machine class, intent, setup composition and policy constraints while allowing the planner to select implementations appropriate to different hardware/PlatformProfiles.

A portable profile export is self-contained: it carries the profile plus the referenced setup and intent definitions needed to adopt it elsewhere. It does not depend on another machine's local database merely to understand what the profile means.

Adoption always re-observes the target machine, resolves target capabilities and produces a fresh plan. A portable profile never replays historical executor effects.

Cross-class adoption is not silently assumed to be valid. Moving a profile between workstation, server and edge classes requires explicit compatibility/resolution rules and a fresh plan because interaction model, resource limits, recovery semantics and hardware expectations may differ materially.

## Class-specific qualification concerns

All classes use the same Linura trust/lifecycle architecture, but support evidence must reflect their different operating conditions.

### Workstation

Typical qualification concerns include interactive desktop/session behavior, displays/input/audio, suspend/resume, GPU, local recovery, accessibility and user-visible update/reboot behavior.

### Server

Typical qualification concerns include headless operation, long-running daemon resilience, service/network/storage availability, remote recovery, reboot/maintenance coordination, container/virtualization hosting and failure behavior without an interactive desktop.

### Edge

Typical qualification concerns include constrained resources, arm64 and other relevant architectures, intermittent/offline operation, power loss, unattended recovery, image/OTA update strategy, hardware identity, peripheral/accelerator variability and fleet-cohort rollout behavior.

These concerns inform qualification; they do not create alternate authority lifecycles.

## Secrets

Profiles and setups may declare required secret references such as `credential:github`, but exported artifacts never contain the underlying token/password/key. The receiving machine resolves missing secret refs through its local credential facilities before sensitive actions can proceed.

## Hardware

Hardware hints are advisory inputs to capability resolution. They can express preferences such as GPU use or display expectations, but they do not freeze exact drivers/packages as the portable source of truth.

The hardware support matrix records PlatformProfile and QualificationEnvironment evidence separately from MachineProfile intent. Declaring `workstation`, `server` or `edge` as a target class does not claim that any physical platform in that class is currently supported.

## Personality

The user's machine "personality" is therefore an explainable composition of active intents, reusable setups and preferences, not hidden model memory.

## Snapshots are separate

A filesystem/system snapshot is an exact recovery artifact for one machine. It is useful for rollback but is not a substitute for a portable setup/profile. Linura deliberately keeps portable declarative configuration and exact recovery state as separate concepts.
