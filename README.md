<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="./docs/assets/brand/linura-lockup-on-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="./docs/assets/brand/linura-lockup-on-light.svg">
    <img alt="Linura" src="./docs/assets/brand/linura-lockup-on-light.svg" width="380">
  </picture>
</p>

# Linura — The intelligent system layer for Linux.

> **Tell your computer what you want it to become. Linura turns that intent into verified machine state.**

**People express goals; AI agents can propose outcomes. Linura turns those inputs into structured intent, classifies the operation, and routes it through deterministic authority semantics appropriate to that operation class.**

Linux already has mature package managers, service managers, configuration tools, and orchestration systems. The harder problem appears when humans and probabilistic agents ask a machine to change across those systems: what is actually true now, what is allowed, what should change, who is authorized, did the effect really happen, and how can the machine recover or reconcile afterward?

Linura treats those as control-plane problems. A model may help interpret or propose intent, but it does not become the authority that mutates the machine.

```text
Human goal or agent proposal
        │
        ▼
structured intent
        │
        ▼
classify operation semantics
        │
        ├─ experience / query / Linura-local
        │     → typed non-external path
        │
        ├─ TransientExternalEffect
        │     → observe → plan → validate → authorize
        │     → execute → verify → audit
        │
        └─ ManagedExternalEffect
              → observe → plan → validate → authorize
              → prepare → execute → verify
              → commit → audit → reconcile
```

**Agents propose. Linura decides and executes.**

- Natural-language input becomes structured intent, never privileged executable text.
- Every external effect crosses a policy-controlled path selected by trusted operation classification; convenience cannot bypass or downgrade that class.
- Executors are narrow and bounded; there is no generic model-to-root interface.
- Execution success is not accepted as proof: resulting state is independently verified before the effect is accepted as successful; managed effects commit only after verification.
- Durable state records **why** a resource exists, so removal, recovery and reconciliation can reason about consequences instead of replaying shell history.
- The authority paths are model-independent: deterministic CLI, policy, inspection, execution and recovery remain usable without an AI provider.

## Who Linura is for

Linura is being built for people and systems that need Linux to be easier to direct without making probabilistic software authoritative:

- **Linux developers and power users** who want to describe the machine state they need instead of maintaining a pile of one-off commands.
- **AI-agent developers** who need agents to request real system changes through typed, policy-controlled capabilities rather than unrestricted shell or root access.
- **Platform and infrastructure teams** that need Linux hosts, containers, and VMs to share an observable, auditable authority model.
- **Security-sensitive organizations** that need changes to be bounded, authorized, independently verified, recoverable, and attributable.
- **Desktop, device, and distribution builders** that want intent-driven system experiences without putting a model inside the trusted execution boundary.

## What you can do with Linura

Linura is still experimental, so current support is deliberately narrow. The product model is designed for workflows such as:

- turn “make this a minimal Rust development workstation” into structured intent and a plan derived from observed machine state;
- let an agent request a supported package, service, network, audio, or system change without giving the model generic privileged execution;
- save a working configuration as portable intent and re-plan it on another supported machine instead of replaying shell history;
- detect and reconcile supported drift after machine state changes outside Linura; and
- retire an intent while checking dependencies and shared ownership before removing resources that other intents still need.

The long-term scope is one authority model across Linux desktops and servers, AI agents, containers, and virtual machines. Capability coverage can grow without changing the trust rule: proposals may be probabilistic; authorization, execution, verification, and state commitment remain deterministic.

## What Linura is

**Linura** is the umbrella system layer and code namespace, not merely an AI shell, desktop environment, or Linux distribution. **Linura OS** is reserved for the installable distribution. **Linura Control**, **Linura Agent**, **Linura Library**, **Linura Shell**, **Linura Control Center**, **Linura First Boot**, and **Linura SDK** are product surfaces or subsystems under that umbrella. “System control plane” and “authority plane” are architectural terms, not separate brands.

The name is inspired by **Linux + aura**: Linux underneath, with a coherent, intelligent layer around it. See [`docs/naming.md`](docs/naming.md) for the full naming contract.

## Current status

Linura is pre-1.0 and experimental. [`contracts/roadmap.toml`](contracts/roadmap.toml) is the machine-readable source of truth for current and next release metadata, while immutable release and version-scoped qualification evidence define what is actually supported. The `Status:` record below is a human-facing projection maintained by release tooling; roadmap work does not silently expand the support boundary.

<details>
<summary>Exact v0.9.0 support boundary</summary>

Status: `v0.9.0` released — Experimental First Boot and supported reference environment. The immutable release is independently verified. `executor_state = "integrated-narrow"`, `managed_mutation_support = "narrow-experimental"`, `complete_lifecycle = true` and `platform_support = "reference-experimental"` remain the authoritative v0.9.0 boundary. The release remains Experimental; the next roadmap milestone is `v0.10.0`.

</details>

## The product idea

A fresh Linura installation should be able to begin with a minimal, recoverable base and ask:

```text
┌──────────────────────────────────────────────┐
│                                              │
│     What do you want this computer           │
│              to become?                      │
│                                              │
│   > A minimal workstation for Rust and _     │
│                                              │
└──────────────────────────────────────────────┘
```

The answer is **not** converted into arbitrary shell commands. Linura converts it into durable structured intent, resolves capabilities and conflicts, derives desired state, and routes every managed mutation through one canonical authority lifecycle.

```text
Human intent / automation / saved setup / imported profile
                    │
                    ▼
          Intelligence plane
 intent → requirements → capability resolution
                    │
                    ▼
             Desired state
                    │
                    ▼
          Authority/control plane
 request/intent → observe → plan → validate
       → authorize → prepare → execute
       → verify → commit → audit → reconcile
                    │
                    ▼
                  Linux
```

A provider/executor cannot shorten that path. Observation feeds planning, policy/approval produces authorization evidence, `prepare` establishes the crash-recovery boundary before effects, executor success is independently verified against authoritative post-state, and only then are Linura state/provenance committed and audited.

**Agents propose. Linura decides and executes.** Agent-native never means agent-dependent: CLI, Control Center, Library, recovery, policy evaluation, state inspection, and deterministic execution must remain usable offline with no model provider.

## Save what works: reusable setups

Linura users should be able to preserve useful configurations and reuse them later on the same device or another supported device.

```text
Intent
  one goal
     ↓
Setup
  reusable versioned slice
     ↓
Machine Profile
  whole-machine composition
```

Examples of setups include `rust-development`, `postgresql-development`, `travel-security`, or `gpu-compute`. Setups are stored/cataloged through the local-first **Linura Library**.

A setup stores portable intent, composition and constraints—not shell history, package-manager transactions or a filesystem snapshot. Portable exports contain required intent/setup definitions and secret **references**, never secret values.

Reusing a setup always means:

```text
load/validate setup
→ observe target machine
→ resolve target capabilities
→ derive desired state
→ generate fresh plan
→ policy/approval
→ canonical mutation lifecycle
```

It never means replaying the commands that happened to work on another machine. Exact snapshots remain a separate machine-specific rollback/recovery mechanism.

See [`docs/reusable-setups.md`](docs/reusable-setups.md) and [`docs/machine-profiles.md`](docs/machine-profiles.md).

## Two core ideas, one architecture

Linura deliberately combines two ideas in one repository while keeping their trust boundaries separate:

1. **Authority/control plane** — typed Linux model, providers, canonical eleven-stage mutation lifecycle, policy/approval, narrow privilege, independent verification, crash-safe commit, reconciliation and audit.
2. **Intent-native system** — persistent user intent, reusable setups/Library, system graph, capability composition, dependency/conflict solver, semantic provenance, specialist agents, first-boot agent UX, portable machine profiles, derived workflows and UI surfaces.

The control plane is reusable without AI. The intelligence plane can be replaced without changing the authority plane.

## Architecture

```text
┌─────────────────────────────────────────────────────────────────┐
│ EXPERIENCE                                                      │
│ First Boot │ Agent UI │ Library │ Control Center │ Shell │ CLI  │
├─────────────────────────────────────────────────────────────────┤
│ INTELLIGENCE                                                    │
│ Intent │ Setups │ Profiles │ Context │ Specialists │ Planner    │
├─────────────────────────────────────────────────────────────────┤
│ AUTHORITY                                                       │
│ Observe │ Plan │ Validate │ Authorize │ Prepare │ Execute |     │
│ Verify │ Commit │ Audit │ Reconcile                             │
├─────────────────────────────────────────────────────────────────┤
│ SYSTEM GRAPH                                                    │
│ Setups │ Resources │ Dependencies │ Conflicts │ Ownership | Why │
├─────────────────────────────────────────────────────────────────┤
│ CAPABILITIES                                                    │
│ Blueprints │ Composition │ Workflows │ Derived Surfaces         │
├─────────────────────────────────────────────────────────────────┤
│ PROVIDERS + NARROW PRIVILEGED EXECUTORS                         │
│ systemd │ NetworkManager │ BlueZ │ PipeWire │ UDisks │ ...      │
├─────────────────────────────────────────────────────────────────┤
│ LINUX                                                           │
└─────────────────────────────────────────────────────────────────┘
```

## Non-negotiable invariants

- `linurad` runs unprivileged.
- No generic privileged shell execution API exists.
- Agents receive no privileged executor handle and never inherit the user's authority implicitly.
- Natural language produces an **IntentProposal**, never executable text.
- Conversation is input; approved structured intent and desired state are the durable source of truth.
- Managed state retains semantic provenance: **why it exists**, not only who mutated it.
- Removing an intent runs dependency/shared-ownership analysis before removing derived resources.
- Unknown/unsupported state fails closed for mutations.
- Every successful managed mutation follows **request/intent → observe → plan → validate → authorize → prepare → execute → verify → commit → audit → reconcile** without shortcuts.
- Planning consumes authoritative observation; it does not assume current machine state.
- Executor success is evidence of dispatch, not proof of resulting state; verification is a separate boundary.
- Supported `ManagedExternalEffect` operations require durable pre-execution prepare/recovery state. A qualified `TransientExternalEffect` is the narrow exception defined by the operation-semantics contract: unprivileged, at most `UserState`, plan-bound, independently verified/audited, and bounded so failure does not require durable indeterminate recovery.
- Reusable setups/profiles contain no secret values and carry no authority grants.
- Imported/synced setup data is untrusted and must be locally re-observed/replanned before mutation.
- Portable declarative configuration and exact recovery snapshots remain separate concepts.
- UI contains no distro-specific backend knowledge.
- Generated/derived UI is constrained to typed resources/actions or isolated extensions.
- Local deterministic operation, Library use and recovery work without network/model access.

## First platform profile

The first interactive workstation PlatformProfile target stays deliberately narrow: Arch Linux + systemd + Wayland/Hyprland + NetworkManager + PipeWire/WirePlumber + BlueZ + UDisks2 + Polkit + Btrfs/Snapper. `arch-hyprland-v1` remains a **development candidate for v0.10**, not an architectural dependency of the core model and not part of the current v0.9.0 release-qualified support boundary.

## Project navigation

| Resource | Link |
| --- | --- |
| Website | https://linura.org |
| Repository | https://github.com/linura-org/linura |
| Documentation | [`docs/index.md`](docs/index.md) |
| Architecture | [`docs/architecture.md`](docs/architecture.md) |
| Landscape | [`docs/concepts/landscape.md`](docs/concepts/landscape.md) |
| Roadmap | [`docs/roadmap.md`](docs/roadmap.md) |
| Contributing | [`CONTRIBUTING.md`](CONTRIBUTING.md) |
| Community | https://github.com/linura-org/linura/discussions |
| Issues | https://github.com/linura-org/linura/issues |
| Security | https://github.com/linura-org/linura/security/policy |
| Releases | https://github.com/linura-org/linura/releases |

## Try Linura

Linura is still experimental. Use release-qualified artifacts and disposable/reference environments for evaluation; do not treat the current pre-1.0 release as a production support guarantee.

For repository development and local qualification, install the pinned Rust toolchain and run:

```bash
cargo xtask check
```

The canonical development, VM, image, visual, qualification, and release paths are repository-owned. Start with [`CONTRIBUTING.md`](CONTRIBUTING.md) for a first contribution or [`docs/development-infrastructure.md`](docs/development-infrastructure.md) for system-level development.

## Repository layout

```text
apps/
  linurad/                     unprivileged authority/control service
  linuractl/                   deterministic CLI
  linura-firstboot/            signature "what should this become?" flow
  linura-control-center/       planned typed GUI client
  linura-agent-ui/             planned conversational Linura Agent client
  linura-shell/                integrated-experimental Quickshell/QML desktop shell host
    ui/                       first-party Linura QML UI component foundation
bindings/
  python/                      canonical PyPI package and non-privileged Python entry point
crates/
  linura/                      canonical top-level Rust crate
  linura-core/                 IDs, actions, semantic reasons, invariants
  linura-intent/               intents, reusable setups, machine profiles
  linura-graph/                causal graph + removal/shared ownership analysis
  linura-capability-sdk/       composable capability blueprints and resolution
  linura-planner/              intent/capabilities → desired-state planning
  linura-provenance/           semantic "why" chain
  linura-agent-runtime/        provider-neutral interpreters + specialist roles
  linura-policy/               policy/approval decisions
  linura-protocol/             versioned public + setup/profile portability contracts
  linura-provider-sdk/         observation/planning + executor/verifier contracts
  linura-sdk/                  public non-privileged developer API facade
  linura-control/              unprivileged authority orchestration
  linura-lifecycle/            mutation ordering + system lifecycle workflows
  linura-bootstrap/            bootstrap sequencing, durable provisioning and restart state
  linura-migrations/           versioned migration, backup and recovery coordination
  linura-update/               coordinated update, verification and reconciliation
capabilities/                  declarative capability blueprint examples
workflows/                     composable workflow definitions
surfaces/                      constrained derived UI definitions
agents/                        agent provider/specialist contracts and manifests
executors/                     narrow privileged effectors
interfaces/                    local D-Bus contracts
schemas/                       machine-readable contracts, including setups/profiles/bootstrap
profiles/                      platform and portable machine profiles
packaging/                     system integration assets
docs/                          product, architecture, security, ADRs, operations
```

The complete top-level ownership map, including declarative/evidence roots, is defined in [`docs/repository-topology.md`](docs/repository-topology.md) and enforced by `contracts/repository-topology.toml`.

## Development order

We will prove the entire model with a narrow vertical slice before building a broad desktop:

1. lock vocabulary, trust boundaries, reusable setup/Library semantics, the system graph and the canonical eleven-stage mutation lifecycle;
2. implement read-only authoritative observations and the system graph;
3. prove deterministic intent/capability/desired-state planning without an LLM;
4. implement plan validation, policy decisions and approval requirements;
5. implement durable `prepare`/`commit`, idempotency, recovery and append-only audit foundations;
6. implement one narrow privileged executor + Polkit and a separate verifier;
7. make one capability traverse all eleven stages with failure/crash/drift tests;
8. persist full intent lifecycle plus local Setup/Profile Library and safe retirement/removal impact;
9. add agent interpretation to `IntentProposal` only and the first-boot experience, including saved setup/profile adoption;
10. expand system domains, Control Center, shell, workflows, derived surfaces, release hardening and optional sharing/enterprise/fleet.

See [`docs/development-plan.md`](docs/development-plan.md), [`docs/action-lifecycle.md`](docs/action-lifecycle.md), and [`docs/vision-coverage.md`](docs/vision-coverage.md).

## Bootstrap quality gate

Rust `1.98.0` is pinned.

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
python3 scripts/check_repository.py
```

The bootstrap deliberately keeps Rust crates dependency-light while public contracts are still stabilizing.


## Development and system proof

Linura keeps its production-oriented development path in the repository rather than in maintainer folklore.

```bash
cargo xtask check
cargo xtask acceptance-list
cargo xtask vm-plan
cargo xtask image-plan
cargo xtask slices-ready
cargo xtask slices-waves
```

The grand development foundation includes checkpointed bootstrap, migrations, coordinated updates, config ownership/drift, sanitized hardware evidence, disposable QEMU/KVM acceptance, visual-regression contracts, exact-SHA release candidate proof, build/publish separation, and independent release-asset verification.

See [Development infrastructure](docs/development-infrastructure.md), [Development lessons adopted from Omarchy](docs/omarchy-development-lessons.md), and the non-normative [Landscape and architectural boundaries](docs/concepts/landscape.md). crates.io publication is governed by [crates.io publishing](docs/crates-io-publishing.md). Linura adopts [Omarchy](https://github.com/basecamp/omarchy)'s strong distro-development discipline while deliberately rejecting unsandboxed plugins, shell strings as the authority API, arbitrary privileged hooks, and model-to-root execution.

## Contributing

Linura has two contributor lanes so rigor does not become unnecessary friction.

A documentation fix, focused test improvement, or routine internal change can start with the short path in [`CONTRIBUTING.md`](CONTRIBUTING.md). Changes to authority, security, public contracts, persistence, recovery, supported platform behavior, or release control use the deeper architecture/security path and the RFC/ADR process where required.

The public contributor label taxonomy is documented in [`docs/community/labels.md`](docs/community/labels.md).

## Community

Use **GitHub Discussions** for Q&A, architecture exploration, ideas, show-and-tell, and general community conversation:

https://github.com/linura-org/linura/discussions

Use **GitHub Issues** for actionable tracked work:

https://github.com/linura-org/linura/issues

Cross-cutting proposals follow [`docs/rfcs/README.md`](docs/rfcs/README.md). Community conversation does not create technical authority; project decisions follow [`GOVERNANCE.md`](GOVERNANCE.md).

## Security

Do not disclose suspected vulnerabilities in public Issues, Discussions, pull requests, or chat.

Follow the private reporting instructions in [`SECURITY.md`](SECURITY.md):

https://github.com/linura-org/linura/security/policy

Linura treats authority, privilege, verification, recovery, and release integrity as product boundaries, not post-release hardening tasks.

## Support Linura

Linura is preparing an institutional sponsorship program for organizations building Linux, AI infrastructure, cloud platforms, hardware, security systems, runtimes, and developer infrastructure.

Funding may support development, infrastructure, hardware qualification, security work, documentation, and community operations, but sponsorship never purchases architecture, security, merge, release, or governance authority.

See the [sponsorship charter](docs/community/sponsorship.md) and the public program at <https://linura.org/sponsors>. Linura plans a dedicated Delaware corporate steward, expected to be named **Linura, Inc.**, but that entity is not yet formed. Native funding destinations therefore remain intentionally inactive until the legal recipient, receiving account, tax/accounting path, and destination ownership are verified.

## Partner with Linura

Linura welcomes strategic technical relationships that deepen interoperability, hardware and platform qualification, compute capacity, security review, research, distribution, and real-world design evidence.

Partnership categories include **Technology**, **Hardware**, **Cloud & Compute**, **Qualification**, **Distribution & OEM**, **Research & Security**, and **Design** partnerships. A partner is not automatically a sponsor, investor, customer, maintainer, or governance participant, and partnership does not grant architecture, roadmap, merge, release, security-policy, or maintainer authority.

For partnership discussions, contact **partners@linura.org**. See the [partnership policy](docs/community/partnerships.md) and the public program at <https://linura.org/partners>. Sponsorship remains a separate relationship handled through **sponsors@linura.org**, while equity and financing conversations belong at **investors@linura.org**.

## License

Apache License 2.0. See [`LICENSE`](LICENSE).
