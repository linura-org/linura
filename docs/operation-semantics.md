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

## Built-in registered external operations

The registry now contains two deliberately narrow external-operation descriptors. Registration is an authority contract, not by itself a release-support claim.

The already-qualified v0.6 managed systemd active-state effect remains:

- operation ID: `operation:systemd.unit.set-active-state`;
- class: `ManagedExternalEffect`;
- trusted risk floor: `SecuritySensitive`;
- trusted risk-floor provenance: `operation-registry.managed-systemd-active-state.risk-floor`;
- provider: `systemd`;
- observation capability: `systemd.unit.observe`;
- resource scope: exact trusted prefix/suffix match `systemd:unit:linura-managed-*.service` (both `systemd:unit:linura-managed-` and `.service` are encoded in the registered effect binding);
- allowed material change key: `active_state`.

The first concrete v0.10 transient candidate is current-session output volume:

- operation ID: `operation:audio.output.set-session-volume`;
- class: `TransientExternalEffect`;
- trusted risk floor: `UserState`;
- provider: `pipewire`;
- observation capability: `audio.session.observe`;
- mutation resource scope: exact numeric `audio:session:output:<node-id>` resources only;
- allowed material change key: `volume_percent`.

The moving `audio:session:default-output` alias is observation/discovery-only and is intentionally outside the registered mutation prefix. A caller must bind a mutation to the concrete output-node identity observed before planning so a default-device change cannot silently retarget an already authorized effect. PipeWire/WirePlumber observation uses a repository-owned, root-installed `wpexec` helper with a fixed SPA-JSON action surface, WirePlumber `ObjectManager`, `default-nodes` and `mixer-api`; transport mechanics do not enter the semantic plan.

The audio descriptor is still a **candidate activation**, not a widened v0.10 support claim: runtime executor/audit composition and interactive workstation qualification must land before support promotion.

The systemd registration does not widen the v0.6 effect. It makes the existing narrow lifecycle consume the same trusted registry that future v0.10 interfaces and domains must use. `ManagedLifecycleControl` constructs the built-in registry internally, validates that registration at composition time, and resolves the initial canonical candidate plus any post-approval refreshed candidate through `OperationSemanticsControl` before durable prepare. Every privileged handoff is revalidated against the registered operation immediately before authority crosses the handoff boundary, including an indeterminate-recovery `Reprepared` candidate, so recovery cannot become an unclassified execution path. The registered risk floor is also fed into durable candidate and recovery construction before policy evaluation: the `PolicySubject`, approval decision, risk provenance, review digest and signed `AuthorityBinding.trusted_risk` all carry the floored risk. Handoff requires the current registry resolution to equal that durable trusted risk, so raising a registered floor cannot reuse weaker prior authority.

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

The concrete v0.10 substrate is `linura_control::TransientEffectControl`. It accepts only a Control-owned trusted operation registry, builds the canonical plan from fresh authoritative observation, resolves the exact registered operation through `OperationSemanticsControl`, applies the trusted transient risk classification, requires policy `Allow`, calls only an unprivileged typed executor, then **always re-observes authoritative state** before reporting success. Registration validation and trusted transient risk refinement both cover the **complete requested postcondition**, including attributes already satisfied in the pre-effect observation and therefore absent from the initial plan diff. A key may enter the typed executor only when both the registered effect binding and the trusted transient risk rule cover it. The executor receives that same complete requested state, and verification rechecks every requested attribute after execution. Executor self-report never proves the postcondition. Audit records bind the authenticated principal, provider/resource/capability, operation/plan/request identities, trusted semantic risk, the exact policy ID/revision and reviewed policy-subject risk, trusted risk-classification revision/rule IDs, pre/post evidence identities, a SHA-256 digest of the complete canonical plan, and a separate SHA-256 digest of the complete requested postcondition. Executor/provider error text is not durable audit material: terminal failures use stable typed categorical codes so credentials, tokens, or provider diagnostics cannot be copied into the audit sink. Before any executor dispatch, Control must first obtain durable, idempotent acceptance of an `AttemptReserved` audit record keyed by a SHA-256 binding of the authorization/effect material; terminal outcomes append/finalize that same reserved attempt identity. If reservation fails, dispatch does not occur. If a terminal audit write fails after dispatch, the durable reservation remains evidence that an attempt occurred. An audit sink is mandatory for every attempted effect/no-change terminal path.

The planner remains deliberately conservative and currently labels any proposed external change as `SystemMutation` before operation semantics are known. That coarse planner value may be refined downward only inside the **exact registered transient** path after Control has matched the canonical plan against the trusted descriptor's provider, observation capability, resource scope and allowed change keys. The ordinary risk classifier still rejects such a downward move. The trusted transient refinement is therefore not a general risk override: missing registration, shape mismatch, unknown risk rule, a result above `UserState`, privilege, durable desired state or ambiguity requiring durable recovery all fail closed or promote the operation to managed/unsupported.

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


## First concrete transient domain: session output volume

The first production-composed `TransientExternalEffect` is `operation:audio.output.set-session-volume` on the v0.10 workstation path. The trusted binding is PipeWire/WirePlumber observation capability `audio.session.observe`, exact resource `audio:session:output:<numeric-node-id>`, and desired key `volume_percent`.

This activation is intentionally narrower than the observer. `audio:session:default-output` is a discovery alias only; it may identify the current default sink for a read, but it is never accepted as mutation authority. The unprivileged session executor passes the trusted pre-effect `node_id`, `object_serial`, `node_name` and `media_class` material to the same root-owned WirePlumber helper used by observation. Inside one `wpexec` WirePlumber event-loop callback, the helper resolves exactly one `Audio/Sink` object whose bound ID, object serial and node name all match the authorized evidence and immediately calls `mixer-api` on that matched object without yielding. Mutation therefore does not perform a second external numeric-ID lookup that could silently retarget a recycled PipeWire ID. Control still performs its own independent fresh post-effect observation and exact postcondition verification; helper self-report is never success evidence.

The public mutation surface is the Experimental session-bus `org.linura.Session1.SetAudioOutputVolume` method hosted by `linurad`. The transport authenticates the D-Bus sender and additionally requires its Unix UID to equal the UID owning the `linurad` session-bus connection, preventing a misconfigured cross-user bus from turning Session1 into a confused deputy. Session1 delegates to the same `TransientEffectControl`; it does not add a second classification, policy, execution or verification path. Durable audit uses a bounded per-user SQLite/WAL store with `synchronous=FULL`, an exact validated STRICT schema, single-link regular database identity and explicit database/WAL growth ceilings; Control's attempt reservation is committed before executor dispatch and terminal disposition finalizes that same attempt identity.
