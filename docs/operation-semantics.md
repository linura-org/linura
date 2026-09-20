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

The trusted operation registry/domain contract owns classification. The concrete v0.10 binding is `linura_capability_sdk::OperationRegistry` for duplicate-safe registered descriptors plus `linura_control::OperationSemanticsControl` for Control-owned external-effect resolution against the canonical plan and trusted risk classification. Every registered external effect also carries a validated `OperationEffectBinding` that fixes the trusted provider, observation capability, resource scope, and allowed material change keys; Control rejects a plan whose shape does not match that binding before risk/policy resolution. Clients, agents, configuration and providers cannot self-declare a weaker class or pair a registered operation with an unrelated plan.

## First concrete registered external operation

The first built-in external operation registered through this v0.10 substrate is the already-qualified v0.6 managed systemd active-state effect:

- operation ID: `operation:systemd.unit.set-active-state`;
- class: `ManagedExternalEffect`;
- trusted risk floor: `SecuritySensitive`;
- trusted risk-floor provenance: `operation-registry.managed-systemd-active-state.risk-floor`;
- provider: `systemd`;
- observation capability: `systemd.unit.observe`;
- resource scope: exact trusted prefix/suffix match `systemd:unit:linura-managed-*.service` (both `systemd:unit:linura-managed-` and `.service` are encoded in the registered effect binding);
- allowed material change key: `active_state`.

This registration does not widen the v0.6 effect. It makes the existing narrow lifecycle consume the same trusted registry that future v0.10 interfaces and domains must use. `ManagedLifecycleControl` constructs the built-in registry internally, validates that registration at composition time, and resolves the initial canonical candidate plus any post-approval refreshed candidate through `OperationSemanticsControl` before durable prepare. Every privileged handoff is revalidated against the registered operation immediately before authority crosses the handoff boundary, including an indeterminate-recovery `Reprepared` candidate, so recovery cannot become an unclassified execution path. The registered risk floor is also fed into durable candidate and recovery construction before policy evaluation: the `PolicySubject`, approval decision, risk provenance, review digest and signed `AuthorityBinding.trusted_risk` all carry the floored risk. Handoff requires the current registry resolution to equal that durable trusted risk, so raising a registered floor cannot reuse weaker prior authority.

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
→ deterministic canonical plan
→ validate + trusted class/risk
→ authorize
→ bounded unprivileged execute
→ independent verification
→ audit
```

A qualified transient effect still produces the canonical non-executable `linura-planner::ReconciliationPlan` from the exact typed requested postcondition plus authoritative observation. Linura Control derives the `PolicySubject` from that plan plus the transport-authenticated principal, so policy/approval remains bound to the same request, evidence, provider/resource/capability, material change, risk and policy revision as other external-effect authorization. The transient class does **not** create an independently authored policy subject or skip planning.

The exemption is specifically the durable prepare/commit/reconcile recovery transaction. That exemption is part of the class boundary, not an optimization: it is valid only while the operation is unprivileged, at most `UserState`, independently verifiable/auditable, carries no durable desired state, and has bounded failure semantics that do not require durable indeterminate recovery. If any of those conditions stop being true, Control must promote the operation to `ManagedExternalEffect` or reject it.

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
- Every `TransientExternalEffect` and `ManagedExternalEffect` that reaches policy authorization is bound to a canonical `ReconciliationPlan` plus the authenticated principal.
- No `ManagedExternalEffect` may bypass the canonical lifecycle for latency or convenience.
- Every public registered effect operation must have a typed operation descriptor before support is claimed.
- Qualification must test class substitution/downgrade, interface inconsistency and privilege-path attempts.
