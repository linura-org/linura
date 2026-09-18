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
  → policy
  → approval when required
  → operation classification
  → canonical managed lifecycle for resulting managed external effects
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

The Linura Library is the user-facing catalog/storage abstraction for reusable declarative artifacts. A future implementation may contain:

- setups;
- machine profiles;
- reusable workflows;
- capability presets/blueprints that are safe to expose;
- associated metadata, revisions, provenance and signatures.

The first implementation should be local-first and usable offline. Storage/sync backends are optional adapters, for example:

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

Future persisted/exported representations should support canonical serialization, content digests and optional signatures. Exact digest/signature formats remain a later ADR because canonical serialization must be stabilized first.

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
- Adoption always requires local capability resolution, observation, planning and policy evaluation.
- Unsupported or ambiguous requirements fail closed for mutation.
- Package names and command strings are implementation details, not the portable source of truth.
- Snapshots remain separate exact-machine recovery artifacts.

## `v0.0.0` boundary

At `v0.0.0`, Linura locks the domain/protocol/schema and trust semantics for reusable setups and self-contained profile exports. Durable Library storage, capture, sync providers, signatures and polished UX are implementation work for later milestones.
