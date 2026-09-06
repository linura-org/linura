# Action lifecycle

A managed mutation is downstream of approved intent or an explicit deterministic request. Managed state carries semantic origin and passes through one canonical authority lifecycle. No transport, provider, approval artifact or executor may create a second execution path around that lifecycle.

## Canonical successful path

```text
request / intent
      ↓
observe
      ↓
plan
      ↓
validate
      ↓
authorize
      ↓
prepare
      ↓
execute
      ↓
verify
      ↓
commit
      ↓
audit
      ↓
reconcile
```

The order is normative. Concrete implementations may stop early on unsupported capability, invalid input, denial, failed approval, stale evidence, execution failure, failed verification or recovery conditions, but a successful managed mutation must not reorder or skip stages.

## Stage contracts

1. **Request / intent** — establish authenticated principal/actor provenance, stable request identity, resource/capability target and semantic origin.
2. **Observe** — read authoritative current state and prerequisites from the responsible Linux/provider boundary. Observation is an explicit input to planning and later recovery.
3. **Plan** — derive a deterministic `ReconciliationPlan` from normalized desired state plus authoritative observed state. The plan is immutable review evidence; replanning against different material input creates a different authority subject even if a pre-1.0 identifier happens to be reused.
4. **Validate** — validate identifiers, semantic origin, evidence identity/freshness, planned changes/findings, capability assumptions and structural invariants before authority is granted.
5. **Authorize** — evaluate policy over the exact validated plan and authenticated principal and, when required, resolve explicit human/admin/destructive approval. Authorization evidence must satisfy the exact plan/evidence/policy/principal binding.
6. **Prepare** — durably record the exact reviewed authority binding, intent-to-execute, idempotency/correlation data and recovery metadata before external effects are dispatched.
7. **Execute** — dispatch only the narrow typed effect permitted by the prepared/authorized plan, and only after the durable ambiguity boundary and fresh handoff validation have succeeded.
8. **Verify** — re-observe authoritative state after execution and evaluate expected postconditions through a verifier boundary independent from executor success reporting.
9. **Commit** — finalize the exact durable authority generation only after successful independent verification. Broader product desired-state/graph/provenance persistence evolves by milestone and must not be implied where it is not implemented.
10. **Audit** — append correlated evidence linking request, principal/actor, plan, policy/approval, prepared authority, effects, observations, verification and commit outcome. Failure/recovery evidence is append-only as well.
11. **Reconcile** — compare committed desired state with fresh authoritative state and prove convergence or surface drift through policy-controlled work. Reconciliation is not blind replay.

## Plan and effect boundary

Linura deliberately separates a **reviewable reconciliation plan** from later executable effect materialization.

The canonical `ReconciliationPlan` retains:

- plan/request/actor/resource/provider/capability identity;
- intent/requirement/capability origin (`SemanticReason`);
- exact authoritative evidence identity;
- prospective risk;
- deterministic current→desired changes;
- findings/blockers.

A reviewed/approved plan is still not an executable credential. Durable prepare, handoff-time revalidation and the narrow executor boundary remain separate steps. This prevents provider-owned executable plans, transport authorization or approval artifacts from becoming parallel execution paths.

## Transaction semantics

**The lifecycle does not require distributed two-phase commit across Linux subsystems.** Many operating-system effects are not atomically reversible and many upstream services do not expose prepare/commit primitives.

Linura's transactional guarantees come from the canonical lifecycle itself: immutable review subjects, exact authorization binding, durable prepare records, stable request identity, idempotency/deduplication where valid, explicit indeterminate states, checkpoints, independent re-observation, postcondition verification, compensation/rollback metadata where a safe inverse exists, and reconciliation when exact rollback is impossible.

A provider or executor must not pretend a non-transactional upstream mechanism is atomic. Cross-provider plans must make ordering, preconditions, failure boundaries and compensation/recovery semantics explicit rather than relying on an implicit distributed transaction.

v0.6 does not claim cross-provider or multi-resource atomicity; it qualifies exactly one bounded systemd active-state effect.

## Stable request identity and idempotency

Every mutation has stable request identity plus an immutable reviewed/authority binding. For the v0.6 managed surface, external `operation_id` maps to:

`request:v06:<operation_id>`

The exact canonical request body is independently checked against its durable `request_digest`.

- an exact retry reuses the same durable transaction and must not duplicate dispatch;
- reusing the operation ID with changed content fails closed with `RecoveryRequestMismatch`;
- request substitution cannot allocate a second transaction under the same stable operation identity or inherit prior authority.

Idempotency is therefore a durable authority invariant, not merely an HTTP/RPC convenience.

## Durable handoff and crash recovery

`prepare` persists that an authorized operation is eligible to approach the external-effect boundary, but `Prepared` does not carry a reusable execution credential.

Immediately before dispatch, Control revalidates the exact current authority/evidence and atomically crosses the durable ambiguity boundary. The resulting process-local one-shot permission is non-cloneable/non-serializable and is consumed by the exact dispatch path.

If a crash or ambiguous transport/executor failure occurs after external dispatch may have happened, the operation remains `Indeterminate` and authoritative state is re-observed before any further effect. Restart cannot reconstruct the old dispatch permission and must not blindly replay the previous command.

The v0.6 recovery path constructs one exact fresh recovery candidate and only then mints `FreshRecoveryApproval` against that same candidate. Conflicting recovery evidence blocks progress. Evidence that the intended effect did not occur may permit re-prepare under current authority, but another dispatch still requires a new explicit invocation and a new one-shot handoff.

## Verification

Executor success is execution evidence, not state proof. Verification re-observes the authoritative subsystem and evaluates the expected postcondition through an independent verifier boundary.

For the v0.6 systemd effect, verification uses a fresh canonical native-systemd observation path separate from the executor. The executor receipt is not verifier input and cannot make a transaction `Committed`.

## Commit, audit and reconciliation

`commit` finalizes the verified durable authority generation. `audit` records who requested/authorized what, which exact evidence and effect binding crossed the boundary, and how verification/recovery resolved it. Semantic provenance remains distinct: it records *why* managed state exists.

Post-commit reconciliation performs fresh verification/planning and proves `NoChange` for the bounded managed resource. If reconciliation fails, retry is verify/reconcile work; it must not replay the already-committed executor action.

## v0.6 concrete authority path

The first complete implementation is deliberately narrow:

```text
Authority1 caller
→ authenticated system-bus sender
→ human Polkit authorization
→ linura-authorityd
→ ManagedLifecycleControl
→ durable SQLite/WAL authority
→ separately authorized root executor
→ systemd StartUnit / StopUnit
→ fresh independent SystemdObserver
→ verifier
→ commit → audit → reconcile
```

The public `Authority1` method is `ConvergeSystemdActiveState` for canonical `linura-managed-*.service` units and exactly `active`/`inactive`. It is Experimental and is not a generic apply, root-RPC or systemd gateway. See [ADR 0026](adr/0026-bounded-v0.6-managed-mutation-authority.md).

## Implementation maturity

The canonical stage state machine remains in `linura-lifecycle`; semantic orchestration/authority remains in `linura-control`.

Milestone progression is cumulative but claim-scoped:

- v0.3 implemented review-only authority and stopped before durable prepare/execution;
- v0.4 established durable transaction, handoff and recovery semantics without a supported effect;
- v0.5 qualified the isolated root executor and independent verifier without product integration;
- v0.6 is the first candidate integrating all eleven stages for one bounded Experimental external effect.

This does **not** mean all workspace/future components participate in the lifecycle or that Linura has generic managed configuration. Component maturity is separately governed by `contracts/components.toml` and [ADR 0025](adr/0025-component-maturity-and-milestone-activation.md).
