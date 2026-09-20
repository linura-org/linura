# ADR 0032: Classify operations before authority and apply control proportional to consequence

- Status: Accepted
- Date: 2026-09-18

## Context

ADR 0012 defines Linura's canonical eleven-stage lifecycle for a **managed external mutation**. ADR 0031 defines the v0.10 interaction invariant: many interfaces share one typed machine model and one authority path.

Those decisions are necessary but insufficient to prevent two opposite implementation failures as Linura becomes an interactive workstation and an agentic system:

1. **over-control:** treating every interaction, query or low-consequence session action as a durable managed transaction with prepare/commit/reconcile machinery and visible approval ceremony; and
2. **under-control:** bypassing Linura Control for convenience because an action came from a shortcut, quick setting, GUI, configuration file, automation or agent.

Risk classification alone does not solve this distinction. `RiskClass` answers how consequential an operation is. Linura also needs a separate semantic answer to **what kind of operation this is** before choosing an authority/execution path.

A workspace switch, authoritative Bluetooth query, Library metadata update, transient volume change and durable SSH enablement are not the same operation class even if several are initiated from the same command palette.

## Decision

Linura classifies every supported operation into one trusted semantic class before choosing its authority path.

ADR 0031's **one authority path** means one trusted Control-owned authority architecture and no interface-specific bypass. It does **not** require every operation class to execute the identical eleven-stage transaction. The operation class selects proportionate machinery inside that single authority architecture; only `ManagedExternalEffect` requires the complete managed-mutation lifecycle.

The canonical classes are:

1. **ExperienceEphemeral** — interaction/session navigation that does not create Linura-managed durable machine state, such as opening a palette, focusing a window or changing workspace. It may use bounded desktop integration directly but may not use privileged executors or masquerade as a managed mutation.
2. **AuthoritativeQuery** — read-only state acquisition/inspection through the observation/query plane. It cannot mutate external or Linura durable state.
3. **LinuraOwnedState** — a typed mutation of Linura-owned durable state with no external Linux effect, such as a local declarative artifact or preference update. It uses the responsible typed Linura persistence/Control boundary, not an external executor lifecycle.
4. **TransientExternalEffect** — a bounded, Control-mediated external effect that is deliberately not adopted as durable desired state. This path is restricted to unprivileged, `UserState`-class effects with explicit post-effect verification/audit. If trusted classification raises risk above `UserState`, requires privilege, needs durable crash/ambiguity recovery, or cannot prove the lightweight semantics, the operation must be promoted to `ManagedExternalEffect` or remain unsupported.
5. **ManagedExternalEffect** — an external effect that requires Linura's durable authority/recovery semantics because it is durable desired state, privileged, system-level, security-sensitive, destructive, ambiguity-sensitive, or otherwise outside the transient-effect envelope. It uses the complete canonical lifecycle:
   `request/intent → observe → plan → validate → authorize → prepare → execute → verify → commit → audit → reconcile`.

### Classification authority

Operation class is **not caller-controlled metadata**.

- UI, CLI, configuration, agents, providers and imported artifacts may identify a registered operation but cannot lower its trusted class.
- The trusted operation registry/domain contract binds the operation to its semantic class.
- Linura Control validates the class at the orchestration boundary and may route an operation only through a path permitted by that class.
- Unknown or ambiguous effect semantics fail closed for mutation. They do not default to `TransientExternalEffect`.
- A provider may report mechanism requirements such as privilege/reversibility, but it cannot use those reports to weaken the trusted class.

### Risk is orthogonal

`OperationClass` and `RiskClass` answer different questions.

```text
OperationClass
  what kind of state/effect path is this?

RiskClass
  how consequential is the reviewed operation?
```

The lightweight transient external-effect envelope is intentionally narrow: its trusted risk may not exceed `UserState`, and it may not cross a privileged executor boundary. Higher trusted risk or privilege therefore selects the managed external-effect path or blocks the operation.

### Proportional control does not weaken deterministic authority

"Proportional" refers to the amount of machinery and user ceremony required by the operation semantics and trusted risk. It never means that an interface may bypass Control for a managed or transient external effect.

For example:

```text
open command palette
  → ExperienceEphemeral

inspect Bluetooth state
  → AuthoritativeQuery

save a local Linura theme preference
  → LinuraOwnedState

set current user-session volume to 40%
  → TransientExternalEffect when the qualified domain contract proves the narrow envelope

maintain a profile's external system state / enable SSH / change firewall / mutate disks
  → ManagedExternalEffect
```

The same subsystem may participate in multiple classes. "Set volume now" and "maintain volume at 40% as desired profile state" are semantically different requests and need not use the same operation class.

### Lifecycle efficiency

The eleven managed-mutation stages are **semantic trust stages**, not a requirement for eleven human prompts, processes, D-Bus/RPC calls, synchronous UI transitions, network/model access, or avoidable latency.

Implementations may locally compose stages and auto-authorize when deterministic policy returns `Allow`, while preserving mandatory durable/security boundaries. User-visible ceremony remains proportional to trusted risk.

A transient external effect uses the bounded semantic path:

`request → observe/preconditions → plan → validate/classify → authorize → execute → verify → audit`

The `plan` stage is the same canonical non-executable `linura-planner::ReconciliationPlan` authority subject used by policy elsewhere. Control derives policy review from that exact plan plus the authenticated principal; transient semantics do not permit a client/provider-authored policy subject or a direct authorize-from-request shortcut.

The transient exemption begins **after** authorization: it has no durable `prepare/commit/reconcile` transaction because it is not durable managed desired state and its failure envelope is bounded. If durable ambiguity/recovery semantics are needed, the operation is a managed external effect.

## Consequences

- `linura-core` owns the provider-neutral `OperationClass` primitive.
- `linura-capability-sdk` exposes a validated typed operation descriptor so future action registries cannot silently omit semantic class/risk-floor information.
- `contracts/operation-semantics.toml` is the machine-readable anti-drift contract.
- v0.10 qualification must prove operation-class convergence and class-downgrade resistance across Control Center, CLI, configuration, shortcuts, command palette, quick settings and agent proposals.
- A privileged executor is valid only for a `ManagedExternalEffect`.
- Unknown/ambiguous external effect classification fails closed rather than choosing the fast path.
- Providers and UI remain mechanisms/clients; neither owns operation classification authority.
- Full managed lifecycle correctness remains unchanged for `ManagedExternalEffect`; this ADR refines where ADR 0012 applies rather than superseding it.
- ADR 0031 remains authoritative for interface convergence; this ADR defines how Control chooses the proportionate path after semantic classification.
