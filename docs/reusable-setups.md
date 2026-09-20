# Reusable setups and the Linura Library

Linura must let a user preserve useful machine configurations and reuse them later on the same machine or another supported machine without replaying opaque commands or copying an exact filesystem image.

The reusable abstraction is a **Setup**. The storage/catalog abstraction is the **Linura Library**.

## Concept hierarchy

```text
Intent
  one durable goal or constraint

Setup
  reusable versioned composition of intents and other setups

Machine Profile
  whole-machine composition of setups, standalone intents and constraints

Snapshot
  exact recovery point for one concrete machine
```

These concepts intentionally solve different problems.

- An **Intent** says what should be true.
- A **Setup** packages a useful, reusable slice such as Rust development, travel security or PostgreSQL development.
- A **Machine Profile** composes a complete machine personality from setups/intents.
- A **Snapshot** restores exact machine state; it is not a portable configuration format.

## Setup contract

A setup has:

- stable `SetupId`;
- human-readable name and description;
- positive revision number;
- referenced intents;
- optional included setups for composition;
- portable constraints/preferences;
- required secret references, never secret values;
- hardware hints that may influence resolution but are not mandatory package choices.

A setup is **not**:

- a shell script;
- an ordered command transcript;
- a frozen package-manager transaction;
- a filesystem snapshot;
- an implicit grant of authority;
- a container for passwords, tokens or private keys.

## Example

```text
setup:rust-development@3
├── intent:rust-development
├── intent:git-development
├── includes: setup:base-development
├── constraint: stable Rust toolchain
└── requires secret ref: credential:github
```

On one platform the capability resolver might select one implementation; on another supported platform it may select another. The setup preserves meaning, not implementation accident.

## Adoption is a new planning operation

Reusing a setup never means replaying the previous effects.

```text
load setup
  → validate bundle
  → resolve included setups/intents
  → locate required secret refs locally
  → observe target machine
  → resolve target capabilities
  → derive desired state
  → generate a fresh diff/plan
  → trusted operation classification in Control
  → policy for the classified operation and trusted risk
  → approval only when policy requires it
  → class-specific handling:
       Linura-owned local transaction
       OR bounded transient effect
       OR canonical managed lifecycle
```

Imported or synced setup data is untrusted input. It cannot directly execute, grant itself authority or bypass policy.

Missing credentials are reported as missing secret references. The receiving machine satisfies those references through its own local credential facilities.

## Self-contained portable bundles

A portable setup export carries:

- the root setup ID;
- all setup definitions required by the composition;
- the intent definitions required by those setups;
- an explicit export format version.

A portable machine profile export similarly carries its profile plus the referenced setup and intent definitions. This avoids the previous incomplete model where a profile named intent IDs without carrying the definitions needed to replay them elsewhere.

Portable exports remain declarative. They do not include historical executor receipts, machine-specific observed state, runtime secrets or filesystem snapshots.

## Linura Library

The Linura Library is the user-facing catalog/storage abstraction for reusable declarative artifacts. v0.7.0 shipped the first durable local-first Library implementation with persistent intent lifecycle, append-only Setup/MachineProfile revisions, causal ownership/removal-impact evidence, deterministic portable export/import/adoption, and validated local backup/restore.

The released local baseline includes:

- durable intents and lifecycle lineage;
- versioned Setups and MachineProfiles;
- deterministic SHA-256-integrity-bound portable Setup/Profile artifacts;
- validation/import and dry-run/direct adoption without imported authority;
- causal ownership/removal-impact evidence;
- local Library backup/restore.

Reusable workflows, hosted sync, enterprise catalogs, optional signatures/attestations and richer capability presets remain later/optional surfaces unless separately activated.

Storage/sync backends beyond the released local baseline are optional adapters, for example:

```text
Linura Library
├── local durable store          required baseline
├── export/import file           supported portable path
├── removable media              optional
├── Git-backed catalog           optional
├── user-owned sync/server       optional
├── Linura-hosted sync           optional future service
└── enterprise catalog           optional future service
```

No network service is the source of truth for local machine authority. A synchronized setup still has to be adopted and planned locally.

## Versioning and identity

Setups are revisioned. A user action such as "save this as a new version of my Rust setup" creates a new revision rather than silently rewriting historical meaning.

The released v0.7 portable Setup/Profile format is deterministic, versioned and SHA-256 integrity-bound. Optional signatures/attestations and any network synchronization trust model remain separate future contracts; they do not replace local parse/validate/adopt semantics.

Provenance should retain lineage between revisions and between a setup and the intents adopted from it.

## Capturing a working machine

"Save my current setup" must not blindly serialize every installed package. The capture flow should derive a portable representation from Linura-managed causal state:

```text
managed current state
  → select relevant intents/resources
  → follow provenance/ownership
  → discard ephemeral observations
  → remove machine-specific realization details where possible
  → replace credentials with secret refs
  → retain portable constraints/preferences
  → build/revise Setup
```

Unmanaged state may be proposed for inclusion only after Linura can explain how it was inferred and the user approves it. A package being installed is not enough evidence that it belongs in a reusable setup.

## Composition and safe removal

Setups can include other setups. Their causal relationship participates in the system graph:

```text
setup:ai-workstation
  → includes setup:base-development
  → includes setup:python-development
  → includes setup:gpu-compute
  → derives intents
  → requirements/capabilities/resources
```

Shared setup/resources are retained when another active intent/profile still needs them. Removing a setup from a profile triggers impact analysis and a fresh cleanup plan; it never performs blind inverse commands.

## Same-device reuse

A setup can be reapplied on the same device after state changes. Linura re-observes current state and plans only the necessary difference. This enables workflows such as:

- restore my CUDA development setup;
- switch back to my travel-security setup;
- reactivate the PostgreSQL development setup;
- compare the current machine with setup revision 4.

## Cross-device reuse

On another device, Linura evaluates the setup against that device's platform profile, hardware and available providers. Hardware hints can influence resolution, but unsupported requirements remain explicit rather than being silently dropped.

The target machine can therefore realize equivalent intent differently while preserving the original constraints and why-chain.

## Security invariants

- Portable setups contain secret references only, never secret values.
- Imports and synchronized library items are untrusted until validated.
- A setup never carries an authority grant.
- Adoption always requires local capability resolution, observation, planning, trusted operation classification and policy evaluation; imported data cannot choose a weaker class.
- Unsupported or ambiguous requirements fail closed for mutation.
- Package names and command strings are implementation details, not the portable source of truth.
- Snapshots remain separate exact-machine recovery artifacts.

## Current release boundary

v0.7.0 moved the Library from architecture-only design into an Experimental durable local implementation, and v0.8/v0.9 inherit that contract. The current v0.9 release therefore includes persistent intent/Setup/MachineProfile Library semantics and portable local adoption, but it does **not** claim hosted synchronization, remote/fleet Library authority, secret synchronization, general workflow execution, a polished graphical Library experience, or broader machine mutation authority than separately qualified effect paths.

v0.10 may expose this existing Library through Control Center and the many-interface workstation experience, but UI activation does not widen the Library's authority: imported/synced declarative data still requires fresh local validation, observation, planning, trusted operation classification and policy before any effect.
