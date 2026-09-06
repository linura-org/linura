# Linura — The intelligent system layer for Linux.

> **Tell your computer what you want it to become.**

**Linura is an intent-driven, agent-native Linux system that turns human goals into declarative, policy-controlled, verified machine state.**

Status: `v0.6.0` release candidate — Experimental complete bounded managed-mutation lifecycle for canonical `linura-managed-*.service` active/inactive convergence. Publication remains pending the protected proof-first/tag-last lifecycle and independent release verification. `executor_state = "integrated-narrow"`, `managed_mutation_support = "narrow-experimental"`, `complete_lifecycle = true` and `platform_support = "none"` define the candidate boundary. Linura remains Experimental and is not production-ready.

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
┌─────────────────────────────────────────────────────────────┐
│ EXPERIENCE                                                  │
│ First Boot │ Agent UI │ Library │ Control Center │ CLI      │
├─────────────────────────────────────────────────────────────┤
│ INTELLIGENCE                                                │
│ Intent │ Setups │ Profiles │ Context │ Specialists │ Planner│
├─────────────────────────────────────────────────────────────┤
│ AUTHORITY                                                   │
│ Observe │ Plan │ Validate │ Authorize │ Prepare │ Execute | │
│ Verify │ Commit │ Audit │ Reconcile                         │
├─────────────────────────────────────────────────────────────┤
│ SYSTEM GRAPH                                                │
│ Setups │ Resources │ Dependencies │ Conflicts │ Ownership | │
│ Why                                                         │
├─────────────────────────────────────────────────────────────┤
│ CAPABILITIES                                                │
│ Blueprints │ Composition │ Workflows │ Derived Surfaces     │
├─────────────────────────────────────────────────────────────┤
│ PROVIDERS + NARROW PRIVILEGED EXECUTORS                     │
│ systemd │ NetworkManager │ BlueZ │ PipeWire │ UDisks │ ...  │
├─────────────────────────────────────────────────────────────┤
│ LINUX                                                       │
└─────────────────────────────────────────────────────────────┘
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
- External effects are never supported without a durable pre-execution recovery record.
- Reusable setups/profiles contain no secret values and carry no authority grants.
- Imported/synced setup data is untrusted and must be locally re-observed/replanned before mutation.
- Portable declarative configuration and exact recovery snapshots remain separate concepts.
- UI contains no distro-specific backend knowledge.
- Generated/derived UI is constrained to typed resources/actions or isolated extensions.
- Local deterministic operation, Library use and recovery work without network/model access.

## Repository layout

```text
apps/
  linurad/                     unprivileged authority/control service
  linuractl/                   deterministic CLI
  linura-firstboot/            signature "what should this become?" flow
  linura-control-center/       planned typed GUI client
  linura-agent-ui/             planned conversational Linura Agent client
  linura-shell/                planned desktop shell
crates/
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
capabilities/                  declarative capability blueprint examples
workflows/                     composable workflow definitions
surfaces/                      constrained derived UI definitions
agents/                        agent provider/specialist contracts and manifests
executors/                     narrow privileged effectors
interfaces/                    local D-Bus contracts
schemas/                       machine-readable contracts, including setups/profiles
profiles/                      platform and portable machine profiles
bootstrap/                     installer/first-boot/recovery architecture
packaging/                     system integration assets
docs/                          product, architecture, security, ADRs, operations
```

## Product and namespace naming

**Linura** is the umbrella brand and code namespace. **Linura OS** is reserved for the installable distribution. **Linura Control**, **Linura Agent**, **Linura Library**, **Linura Shell**, **Linura Control Center**, **Linura First Boot**, and **Linura SDK** are product surfaces/subsystems under that umbrella. “System control plane” and “authority plane” remain architectural terms, not separate brands.

The name is inspired by **Linux + aura**: Linux underneath, with a coherent, intelligent and beautiful layer around it. See [`docs/naming.md`](docs/naming.md).

## First platform profile

The first planned platform target stays deliberately narrow: Arch Linux + systemd + Wayland/Hyprland + NetworkManager + PipeWire/WirePlumber + BlueZ + UDisks2 + Polkit + Btrfs/Snapper. This is a **planned platform profile**, not an architectural dependency of the core model and not a v0.4.0 support claim.

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

## License

Apache License 2.0. See [`LICENSE`](LICENSE).

## Development and system proof

Linura keeps its production-oriented development path in the repository rather than in maintainer folklore.

```bash
cargo xtask check
cargo xtask acceptance-list
cargo xtask vm-plan
cargo xtask image-plan
```

The grand development foundation includes checkpointed bootstrap, migrations, coordinated updates, config ownership/drift, sanitized hardware evidence, disposable QEMU/KVM acceptance, visual-regression contracts, exact-SHA release candidate proof, build/publish separation, and independent release-asset verification.

See [Development infrastructure](docs/development-infrastructure.md) and [Development lessons adopted from Omarchy](docs/omarchy-development-lessons.md). Linura adopts [Omarchy](https://github.com/basecamp/omarchy)'s strong distro-development discipline while deliberately rejecting unsandboxed plugins, shell strings as the authority API, arbitrary privileged hooks, and model-to-root execution.
