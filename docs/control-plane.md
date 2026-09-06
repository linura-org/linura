# Linura Control and the system control plane

`linura-control` implements Linura Control, the local semantic authority subsystem. The **system control plane** is the architectural role it fulfills and is not a separate product brand or daemon.

Control is the canonical mediator between requested desired state and operating-system effects. It owns lifecycle ordering, deterministic planning/policy orchestration, exact authority binding and recovery semantics. Concrete transports, observation adapters, persistence engines, executors and verifiers remain outside that semantic ownership and are wired through typed boundaries by composition roots.

## Canonical managed-mutation lifecycle

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

A successful managed mutation cannot skip or reorder these stages. Failure/denial may stop earlier; ambiguous execution is retained durably and reconciled rather than automatically replayed. See [Action lifecycle](action-lifecycle.md), [ADR 0012](adr/0012-canonical-mutation-lifecycle.md) and [ADR 0025](adr/0025-bounded-v0.6-managed-mutation-authority.md).

## Control responsibilities

For a capability that has reached the relevant milestone, Control owns or coordinates the semantic decision for:

- retaining canonical request identity and semantic origin;
- obtaining authoritative current state through observation ports;
- deriving deterministic reconciliation plans through the canonical planner;
- validating exact plan/evidence/freshness invariants before authority is granted;
- evaluating policy and required approval evidence over the exact reviewed subject;
- durably preparing intent-to-execute before an external effect;
- revalidating exact authority immediately before handoff;
- crossing the durable one-shot execution handoff without serializing bearer authority;
- classifying execution ambiguity conservatively;
- re-observing and independently verifying the intended postcondition;
- committing only after the exact durable generation is verified;
- appending correlated audit/integrity evidence;
- reconciling committed desired state through fresh verification/planning;
- retaining recovery state across process restart without blindly reconstructing dispatch permission.

Transport/process responsibilities remain outside `linura-control`. For example, `linura-dbus` authenticates the system-bus sender and performs the v0.6 Authority1 Polkit interaction, while `linura-authorityd` composes Control with SQLite/WAL, native observation, the executor client and verifier.

## Authority maturity by milestone

### v0.1–v0.2 — authoritative observation and plan preview

The early Control lineage established authenticated/non-privileged local requests, authoritative observation and deterministic planning. The released v0.2 `PlanPreviewControl` path is:

```text
authenticated principal
→ authoritative observation
→ deterministic ReconciliationPlan
→ non-executable PlanPreview
```

It has no privileged mutation authority.

### v0.3 — policy and approval review

v0.3 extends the same plan lineage with deterministic policy/risk classification and exact approval review. An `allow` decision or valid approval is review evidence; it is not permission to invoke an executor.

### v0.4 — durable authority/recovery foundation

v0.4 adds durable SQLite/WAL authority transactions, exact reviewed bindings, `prepare`, process-local sealed dispatch permission, indeterminate recovery and verified-commit semantics without shipping a supported managed external effect.

Durable rows, signatures and digests are evidence/binding state, not executor credentials.

### v0.5 — isolated executor/verifier qualification

v0.5 qualifies the first narrow privileged systemd executor and independent verifier on disposable real-system fixtures while deliberately leaving them disconnected from product mutation authority. That historical boundary is recorded in [ADR 0021](adr/0021-v0.5-isolated-executor-verifier-qualification.md).

### v0.6 — first bounded complete lifecycle

The v0.6 candidate is the first composition of all eleven stages for one real Experimental external effect:

- canonical resource namespace: `systemd:unit:linura-managed-*.service`;
- desired state: exactly `active` or `inactive`;
- external mechanism: native systemd `StartUnit` / `StopUnit`;
- public mutation transport: Experimental `org.linura.Authority1`;
- authority runtime: unprivileged `linura-authorityd` under the dedicated `linura-authority` service identity;
- durable state: SQLite/WAL authority store;
- executor: separately authorized/hardened root `linura-executor-systemd`;
- verification: fresh canonical native-systemd observation independent of executor receipts.

`linura-control::ManagedLifecycleControl` composes this path over the existing durable authority lineage. It is not a new policy, transaction or recovery authority.

The v0.6 claim remains narrow and Experimental until exact-source disposable-system qualification and release proof succeed. Completing the lifecycle for this capability does not mean Linura has generic managed configuration.

## Stable operation identity and idempotency

For v0.6, a stable external `operation_id` is mapped to the durable request identity:

`request:v06:<operation_id>`

The exact canonical request body is checked independently against its durable `request_digest`.

- exact retry reuses the same transaction and committed result without a second dispatch;
- changed request content under the same operation ID fails closed with `RecoveryRequestMismatch`;
- substitution cannot allocate a second transaction or inherit prior authority.

This binding is part of recovery correctness, not only API convenience.

## Pre-dispatch and recovery authority

A successful executor handoff requires fresh exact validation plus durable progression across the prepared boundary. One-shot dispatch permission remains process-local/non-serializable.

If an external effect may have been attempted, durable state becomes `Indeterminate`. Restart must not reconstruct the prior dispatch permit. Recovery re-observes the machine and determines what is safe from current evidence.

The v0.6 recovery approval flow constructs one exact fresh recovery candidate first and then mints `FreshRecoveryApproval` against that same candidate. This prevents a fresh approval from being applied to a different/staler candidate.

Conflicting evidence blocks recovery. If fresh evidence proves the intended effect absent and the state machine permits re-prepare, another dispatch still requires a new explicit invocation and a new exact one-shot handoff.

## Verification, commit and reconciliation

An executor receipt is evidence about dispatch, not final state.

The v0.6 runtime obtains fresh canonical systemd observation independently of the executor path and applies the active-state verifier to the expected postcondition. Only after verified recovery/commit invariants succeed may the exact transaction become durable `Committed`.

Audit/integrity checks follow commit. Reconciliation then performs fresh verification/planning and must prove `NoChange`; reconciliation never means replaying the original executor request.

## Public/process boundaries

### Control1 / linurad

`linurad` hosts the existing non-privileged Control1 planning/query lineage. v0.6 does not add privileged apply semantics to that interface.

### Authority1 / linura-authorityd

`linura-authorityd` hosts the bounded v0.6 `Authority1` system-bus entry point through `linura-dbus`. The transport authenticates the caller and performs the human Polkit decision, while Control owns the semantic authority/recovery path.

### Executor.Systemd1

The root executor is an internal privileged boundary, not the public policy/authority plane. Its production managed action is separately authorized for the authority service identity. Human/admin callers cannot treat it as a generic systemd gateway.

## Non-responsibilities

Control does not:

- replace NetworkManager, BlueZ, PipeWire, systemd or other Linux subsystem managers;
- parse arbitrary natural language itself;
- accept arbitrary shell scripts or executables as system actions;
- provide a generic root RPC endpoint;
- treat D-Bus/Polkit transport checks as a replacement for Control policy/recovery semantics;
- trust executor success as proof of resulting machine state;
- allow providers/executors to create a parallel plan/policy/authority path;
- let an approval, digest or durable row become an executor bearer credential;
- grant model/agent processes privileged handles;
- make UI-specific layout decisions.

## Component maturity boundary

The workspace contains foundations and future scaffolds in addition to integrated components. `contracts/components.toml` defines component maturity and activation; workspace membership is not a claim that Control currently composes that component.

In particular, v0.6 does not broaden itself into First Boot, agent interpretation, supported hardware/bootstrap, Control Center, Shell or general managed-configuration work. See [ADR 0026](adr/0026-component-maturity-and-milestone-activation.md).

## Gateway transport

D-Bus is the first local transport because Linux system/session integration and caller identity naturally fit it. Domain/control contracts remain transport-neutral.

A future remote/fleet gateway must be a separate process/service with its own authentication, enrollment and threat model rather than exposing `linurad` or `linura-authorityd` directly to the network.
