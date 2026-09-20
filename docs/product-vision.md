# Product vision

> **Linura — The intelligent system layer for Linux.**

## Defining sentence

> **Tell your computer what you want it to become.**

Linura is not an AI chat panel embedded in Linux Settings. It is an intent-configured operating environment in which approved intent becomes durable structured state.

## Product loop

```text
user intent
  → structured intent proposal
  → requirements and constraints
  → capability/dependency/conflict resolution
  → desired system state
  → observed-state diff
  → deterministic action plan
  → policy and approval
  → trusted execution
  → independent verification
  → semantic provenance + audit
  → reconciliation over time
```

The loop also runs in reverse when an intent is retired: Linura computes derived state, shared ownership and removal impact before proposing cleanup.

## Starts minimal, becomes personal

The first-boot experience can start from a recoverable base rather than a fully opinionated desktop. A user can describe roles, preferences and constraints such as development, creative work, security posture, travel, accessibility, visual style, or hardware usage. Linura composes supported capabilities and shows the resulting system plan.

The result is not a bag of packages. Linura retains the causal graph explaining why each managed resource exists.

## Save what works and reuse it

Useful configurations can be preserved as reusable **Setups** in the local-first **Linura Library**. A setup is a versioned composition of portable intent and constraints, such as `rust-development`, `travel-security` or `postgresql-development`.

Setups can be reused later on the same device or adopted on another supported device. Adoption always re-observes the target machine and generates a fresh plan; it never replays opaque command history.

Machine profiles compose setups into whole-machine personalities. Portable setup/profile exports carry the intent definitions needed to understand them elsewhere while excluding secret values and machine-specific runtime state.

Exact filesystem/system snapshots remain a separate recovery mechanism.

## Agent-native, not agent-dependent

Model providers are optional adapters. A Linura machine remains inspectable, controllable, explainable, and recoverable through deterministic clients without network/model access.

## Many interfaces, one machine model

Linura is intent/state-centric and control-plane-centric underneath, but it is not limited to conversational interaction. A supported machine may expose the same model through declarative configuration, graphical controls, keyboard shortcuts, a command palette, quick settings, CLI/SDK automation and proposal-only agent assistance.

```text
intent / config / GUI / keyboard / palette / quick settings / CLI / agent
                                  │
                                  ▼
                       typed Linura state/actions
                                  │
                                  ▼
                           Linura Control
                                  │
                                  ▼
                        verified machine state
```

The interface does not become authority. Declarative configuration is validated data rather than an executable script. A keyboard shortcut or quick-setting toggle maps to a registered typed action instead of a hidden privileged command. Low-risk actions may be policy-authorized with minimal ceremony, while higher-risk actions can require explicit plan review or approval without changing the underlying authority model.

Before choosing an execution path, Linura classifies the registered typed operation according to [operation semantics](operation-semantics.md). Ephemeral experience/navigation, authoritative queries, Linura-owned local state, bounded transient external effects and managed external effects are different semantic classes. Risk is orthogonal to that class. Clients/agents/providers cannot select a weaker class, and unknown external-effect semantics fail closed.

Ephemeral desktop navigation such as opening a launcher, focusing a window or switching workspace is not durable Linura-managed machine state. It may remain a direct desktop interaction. Transient external effects remain Control-mediated and deliberately narrow; managed external effects retain the full canonical lifecycle.

## Product surfaces

- Linura First Boot: establish initial intents/profile or adopt saved setups/profiles.
- Linura Agent: conversationally propose/change/retire intent and save/reuse setups.
- Linura Library: local-first catalog for reusable setups/profiles and future reusable declarative artifacts.
- Declarative configuration: versioned, typed, previewable power-user input that carries no execution authority.
- Linura Control Center: inspect current/desired state, approvals, drift, graph, provenance and reusable configurations.
- Linura Shell/desktop integration: cohesive workstation entry points including command palette/launcher, bounded quick settings, workspace/session integration, notifications/OSD and shared visual/theme foundations, all consuming the same APIs.
- CLI/Linura SDK: deterministic automation, integrations and recovery.
- Enterprise/Fleet: optional remote policy/orchestration built on the same local authority model.

## Product hierarchy

Linura is the umbrella. **Linura OS** is the installable distribution when that product exists; **Linura Control** is the local authority subsystem; **Linura Agent** is the intent experience; **Linura Library** is the reusable declarative catalog; **Linura Shell** and **Linura Control Center** are graphical clients; **Linura SDK** and `linuractl` are deterministic developer/automation surfaces. All use the Linura namespace and the same authority model.
