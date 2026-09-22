# Omarchy comparison and lessons

Linura is not “Omarchy plus an AI chat box.” Omarchy is a strong opinionated Arch/Hyprland developer distribution that demonstrates the value of coherent defaults, integrated updates/migrations, a polished shell, and real acceptance testing.

Linura changes the source of opinionation:

```text
Omarchy:  maintainer opinions → preconfigured environment
Linura:   user intent → structured model → personalized environment
```

| Area | Omarchy-style product | Linura target |
| --- | --- | --- |
| Primary abstraction | opinionated distro/desktop | intent-driven operating environment |
| Source of desired configuration | curated maintainer defaults + user config | approved persistent user intent + machine profile |
| System contract | shell/native UI APIs/config | typed resources, capabilities, graph, desired state and actions |
| Mutation | commands/configuration workflows | request/intent → observe → plan → validate → authorize → prepare → execute → verify → commit → audit → reconcile |
| Privilege | integrated sudo/pkexec/system tooling | narrow typed executors + Polkit; no generic root API |
| Agent role | agent skills invoke system tools | untrusted interpreter producing `IntentProposal` only |
| Dependency semantics | packages/config/application knowledge | capability solver + semantic ownership/system graph |
| Why state exists | mostly implicit in configuration/history | explicit semantic provenance from intent to resource |
| Removing a goal | manual/tool-specific cleanup | retire intent → shared ownership/dependency impact → cleanup plan |
| New workflows | scripts/plugins/configuration | typed workflow composition + isolated extensions |
| UI growth | shipped shell/plugins | unified trusted Quickshell surfaces + standalone apps + isolated extensions |
| Portability | controlled Arch substrate | explicit platform profiles with portable intent/profile replay |
| Fleet/enterprise | not primary | later optional extension of the same local authority model |

## Lessons to carry forward

- strong opinionated defaults still matter, especially for the deterministic fallback profile;
- begin with one controlled platform contract;
- package-backed updates, idempotent migrations and snapshots/recovery are product features;
- graphical/VM acceptance testing is required for a desktop product;
- keyboard UX and visual coherence deserve first-class engineering;
- document contributor/agent workflows precisely;
- integration quality matters as much as architectural novelty;
- transient desktop chrome belongs in one supervised shell host, while substantial management tools may remain standalone clients;
- a plugin-shaped first-party shell component is not permission to load arbitrary third-party QML into the trusted shell process.

## Where Linura deliberately goes further

- user intent becomes durable declarative state;
- the machine can explain why managed state exists;
- capability composition resolves dependencies/conflicts before mutation;
- every successful managed mutation follows one ordered authority lifecycle with crash-safe prepare/commit boundaries;
- agents do not own execution authority;
- executor success is independently verified against authoritative post-state;
- UI is another client over the same typed system model;
- managed intent can be retired safely with shared-resource analysis;
- equivalent intent can be replayed on another supported machine without requiring identical packages;
- local deterministic operation remains available if every model provider disappears.
