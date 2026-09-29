# Configuration management and declarative systems

> **Status:** Non-normative  
> **Last externally verified:** 2026-09-29

Linura is not the first system to treat desired state as more important than a sequence of imperative commands.

Configuration-management systems and declarative operating systems have done this for decades.

Linura should treat those systems as important architectural predecessors.

The distinction is not that Linura discovered desired state. The distinction is the authority boundary Linura places around **arbitrary interactive intent becoming a managed state transition**.

## Nix and NixOS

Nix and NixOS provide one of the strongest existing examples of declarative and reproducible system construction.

NixOS allows a machine configuration to be described declaratively. The system can then build and activate a configuration corresponding to that declaration.

NixOS also provides generations and rollback, giving operators a strong recovery model when a new configuration is not acceptable.

### NixOS and Linura

The overlap is real.

Both architectures care about desired state, reproducibility, controlled system change, rollback, explicit dependency relationships, and making configuration understandable as data rather than opaque command history.

But their centers of gravity differ.

#### NixOS asks

> What complete declarative system configuration should this machine realize?

#### Linura asks

> Given an intent arriving now, what authorized state transition does it imply, how can it be executed safely, what state actually resulted, and what remains managed afterward?

Linura should not reproduce Nix. It should be capable of treating declarative systems such as NixOS as execution or state-management backends where that is the right platform mechanism.

### Comparison

| Dimension | NixOS | Linura |
| --- | --- | --- |
| Primary model | Declarative system configuration | Authorized state-transition model |
| Configuration source | Nix expressions/modules | Intent resolved into typed capabilities/plans |
| Reproducibility | Core strength | Desired property; capability/environment dependent |
| Rollback | Strong generation-based mechanisms | Capability-dependent rollback / compensation / reconciliation |
| Runtime interaction | Supported, but declarative configuration is central | Interactive transitions are first-class |
| Human/agent intent | Normally translated into configuration externally | Explicit architectural input |
| Authorization per requested effect | Primarily conventional system/security mechanisms | Intended part of the control-plane lifecycle |
| Post-effect observation | System activation mechanisms | Independent observation/verification is explicit |
| Distribution dependency | Nix/NixOS model | Intended to support multiple Linux profiles |

### Strengths of NixOS

Linura should not understate Nix/NixOS strengths:

- declarative machine configuration;
- reproducible package construction;
- dependency closure;
- side-by-side generations;
- rollback;
- system image construction;
- reusable modules.

These are extremely strong primitives.

### Tradeoffs relative to Linura's scope

NixOS asks users and systems to express machine state through the Nix ecosystem.

Linura intends to accept intent from multiple surfaces and map that intent into platform-native capabilities.

That gives Linura a broader interaction boundary but also a harder verification problem.

Nix can often derive the desired artifact from a complete declaration. Linura may need to reason about mutable runtime state controlled by external systems such as systemd, PipeWire, NetworkManager, BlueZ, UDisks, desktop compositors, existing package managers, and container runtimes.

This increases complexity considerably.

### Upstream source

- [NixOS Manual](https://nixos.org/manual/nixos/stable/)

## Ansible

Ansible expresses automation primarily through playbooks and modules.

Most Ansible modules check whether the requested final state has already been achieved and avoid mutation when no change is required. Ansible calls such behavior idempotent, while also documenting that not every module or playbook is necessarily idempotent.

### Ansible and Linura

The overlap is strongest around desired outcomes, idempotency, remote/local execution, and automation across heterogeneous systems.

The authority model is different.

Ansible normally assumes the playbook/operator already possesses the credentials and authority necessary to make the requested changes.

Linura intends authorization itself to be part of the machine transition.

#### Ansible

> Execute this automation so these resources reach the requested state.

#### Linura

> Determine whether this proposed state transition is authorized, derive the required effects, execute them through controlled capabilities, and verify the authoritative result.

Ansible could therefore be invoked beneath Linura for appropriate capabilities without becoming Linura's authority model.

### Upstream source

- [Ansible playbooks: desired state and idempotency](https://docs.ansible.com/projects/ansible/latest/playbook_guide/playbooks_intro.html)

## Puppet

Puppet provides a clear historical precedent for reconciliation.

A Puppet resource describes desired state. When Puppet applies a catalog, it reads the actual state of each managed resource, compares actual state with desired state, makes changes where necessary, and records the changes.

This observe/compare/enforce loop is directly relevant to Linura.

### Puppet and Linura

Puppet demonstrates that continuous state management is practical and valuable.

Linura extends the problem in a different direction:

- interactive requests;
- local workstation state;
- agent-originated intent;
- capability-scoped authorization;
- user-session state;
- immediate lifecycle evidence;
- heterogeneous execution semantics behind one authority path.

Linura should reuse the conceptual lesson:

> **Desired state without observation is incomplete.**

It should not imply that reconciliation itself is novel.

### Upstream source

- [Puppet resources and desired state](https://help.puppet.com/core/current/Content/PuppetCore/lang_resources.htm)

## Comparative matrix

| Dimension | NixOS | Ansible | Puppet | Linura |
| --- | --- | --- | --- | --- |
| Declarative desired state | Strong | Common | Strong | Core architectural concept |
| Reconciliation | Activation/generation model | Usually run-driven | Core resource loop | Intended continuous managed-state capability |
| Reproducibility | Exceptional strength | Environment dependent | Environment dependent | Capability/platform dependent |
| Rollback | Strong generations | Playbook-specific | Resource/workflow-specific | Explicit lifecycle goal; capability dependent |
| Heterogeneous Linux targets | Limited by Nix/NixOS adoption model | Strong | Strong | Architectural goal via platform profiles |
| Interactive desktop state | Not central | Not central | Not central | First-class intended domain |
| Agent as intent source | External concern | External concern | External concern | First-class but non-authoritative |
| Per-effect authorization plane | Not primary abstraction | Not primary abstraction | Not primary abstraction | Core architectural boundary |
| Independent post-state evidence | Depends on mechanism | Module/task dependent | Resource observation | Explicit lifecycle requirement |

## What Linura should learn from configuration management

### From Nix

Make state definitions composable.

Make dependency relationships explicit.

Prefer deterministic construction wherever possible.

Make rollback cheap and unsurprising.

Treat system configuration as data.

### From Ansible

Do not mutate something that is already in the required state.

Keep platform adapters practical.

Make operations understandable to operators.

Represent failures explicitly.

### From Puppet

Observe reality.

Compare observed state with desired state.

Reconcile drift instead of assuming that a previous command permanently established truth.

Produce durable evidence of what changed.

## What Linura adds to this lineage

Linura's intended contribution is not desired state by itself.

Its contribution is the composition of desired state with an explicit authority boundary:

`proposal → semantic resolution → policy → authorization → controlled effects → authoritative observation → verification → managed state`

This lifecycle is intended to work for immediate interactive operations as well as persistent configuration.

That makes Linura closer to a **machine authority layer** than to a traditional configuration-management tool.

## Architectural conclusion

Configuration-management systems prove that machines can be managed in terms of state rather than command history.

Linura builds on that idea but moves the boundary closer to interactive computation:

> **Any interface may express intent, but only the control plane may turn that intent into authoritative machine state.**
