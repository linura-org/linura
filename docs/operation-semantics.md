# Operation semantics and proportional control

Linura applies deterministic control **proportional to consequence** without allowing convenience paths to become authority bypasses. Linura still has one Control-owned authority architecture; operation classes select proportionate machinery within it rather than creating competing authority planes.

The canonical decision is recorded in [ADR 0032](adr/0032-classify-operations-before-authority.md). The machine-readable source of truth is `contracts/operation-semantics.toml`.

## Two independent axes

Every supported operation has two distinct concerns:

- **OperationClass** — which semantic state/effect path is valid;
- **RiskClass** — how consequential the reviewed operation is.

Risk does not determine whether something is a query, Linura-owned state, transient external effect or managed external effect. Operation class does not let a caller lower trusted risk.

## Canonical operation classes

| Operation class | Meaning | Control/authority path |
| --- | --- | --- |
| `ExperienceEphemeral` | UI/session navigation with no Linura-managed durable state | bounded experience integration; no privileged executor |
| `AuthoritativeQuery` | read-only authoritative observation/query | observation/query plane; no mutation |
| `LinuraOwnedState` | typed durable mutation owned by Linura with no external Linux effect | typed local persistence/Control transaction |
| `TransientExternalEffect` | temporary external effect not adopted as durable desired state | Control-mediated bounded effect path; unprivileged and at most `UserState` |
| `ManagedExternalEffect` | durable/consequential/privileged/ambiguity-sensitive external effect | full canonical managed-mutation lifecycle |

The trusted operation registry/domain contract owns classification. Clients, agents, configuration and providers cannot self-declare a weaker class.

## Promotion rules

A transient external effect is valid only when all of these remain true:

- trusted risk is at most `UserState`;
- no privileged executor is required;
- the domain has a narrow typed operation;
- required authoritative preconditions can be established;
- post-effect state can be independently verified;
- bounded failure can be reported without needing durable indeterminate recovery;
- the operation is not durable desired state.

If any condition fails, Control must use `ManagedExternalEffect` semantics or report the operation unsupported. It must never keep the lightweight path merely to preserve UX speed.

## Managed external effects

Only `ManagedExternalEffect` uses the complete ADR 0012 path:

```text
request / intent
→ observe
→ plan
→ validate
→ authorize
→ prepare
→ execute
→ verify
→ commit
→ audit
→ reconcile
```

These are semantic stages. They may be implemented efficiently and do not imply eleven user prompts, processes, IPC calls or model invocations.

Policy `Allow` may make a supported operation feel immediate. Approval is presented only when policy requires it.

## Transient external effects

The bounded transient path is:

```text
request
→ authoritative observation/preconditions
→ validate + trusted class/risk
→ authorize
→ bounded unprivileged execute
→ independent verification
→ audit
```

This is not a generic "fast mutation" API. It is unavailable to privileged, `SystemMutation`, `SecuritySensitive`, `Destructive`, ambiguity-sensitive or durable desired-state work.

## Examples

| User action | Operation class | Notes |
| --- | --- | --- |
| Open palette / focus window / switch workspace | `ExperienceEphemeral` | no fabricated durable authority transaction |
| Inspect network/Bluetooth/audio state | `AuthoritativeQuery` | authoritative provider evidence |
| Save a local Linura UI preference or declarative draft | `LinuraOwnedState` | typed local state; no external executor |
| Set current session volume | `TransientExternalEffect` only if the qualified domain stays in the narrow envelope | otherwise managed/unsupported |
| Maintain a desired workstation state | `ManagedExternalEffect` | durable desired state |
| Enable SSH / modify firewall / privileged package or storage mutation | `ManagedExternalEffect` | higher consequence/privilege |

The same subsystem can expose operations in different classes. Classification follows the requested semantics, not the widget or provider name.

## Anti-drift rules

- Unknown/ambiguous external effect semantics fail closed.
- UI surface never determines operation class.
- Agent/model confidence never determines operation class or risk.
- Provider mechanism metadata cannot lower trusted classification.
- No `ExperienceEphemeral`, `AuthoritativeQuery`, `LinuraOwnedState` or `TransientExternalEffect` operation may acquire a privileged executor.
- No `ManagedExternalEffect` may bypass the canonical lifecycle for latency or convenience.
- Every public registered effect operation must have a typed operation descriptor before support is claimed.
- Qualification must test class substitution/downgrade, interface inconsistency and privilege-path attempts.
