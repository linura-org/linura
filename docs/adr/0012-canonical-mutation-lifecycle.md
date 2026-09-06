# ADR 0012 — Canonical trustworthy mutation lifecycle

- Status: Accepted
- Date: 2026-08-30

## Context

Linura turns intent and deterministic requests into operating-system effects. A trustworthy authority plane needs more than `plan → execute`: it must prove which state was observed, why a plan was valid, who authorized it, what crossed the privilege boundary, whether the intended postconditions actually exist, and what durable/audit state was committed afterward.

Without one canonical lifecycle, providers and future domain implementations could accidentally skip observation, conflate policy with approval, treat executor success as verification, persist state before postconditions are proven, or omit recovery/audit evidence.

## Decision

Every successful managed mutation follows exactly these ordered stages:

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

The successful path may not reorder or skip stages. Failure/denial may terminate the path early, but failure, compensation and indeterminate outcomes remain auditable.

Additional invariants:

- authoritative observation is an explicit input to deterministic planning;
- authorization combines policy evaluation with any required approval evidence;
- `prepare` persists intent-to-execute before external effects;
- executors are narrow effect boundaries and do not define truth about resulting state;
- verification consumes post-execution authoritative observation and is a separate interface from execution;
- commit occurs only after verification succeeds;
- audit and semantic provenance are distinct but correlated;
- reconciliation follows durable commit and remains policy controlled;
- request IDs, plan IDs and stage receipts remain correlated for recovery and evidence;
- model/agent output never bypasses the lifecycle.

## Implementation boundary for 0.0.0

`linura-lifecycle` owns the canonical stage enum and ordering state machine. `linura-control` owns orchestration. Concrete runtime behavior is injected through explicit ports so future persistence, approval, executor, verifier, audit and reconciliation implementations can evolve without changing the authority sequence.

`linura-provider-sdk` separates provider observation/planning from effect execution and independent verification.

## Implementation evolution

This ADR remains the canonical lifecycle decision; later milestones refine how its stages become concrete without replacing or reordering them.

- v0.1–v0.3 established authoritative observation, deterministic planning and policy/approval review without external mutation.
- v0.4 established durable reviewed-authority preparation, recovery and verified commit semantics.
- v0.5 qualified an isolated privileged executor and independent verifier without product lifecycle integration; see ADR 0021.
- v0.6 is the first bounded concrete composition of all eleven stages for one Experimental external effect. Its exact Authority1/process/privilege/recovery boundary is recorded in ADR 0026.

The original `0.0.0` implementation-boundary text above is retained as historical context; it must not be read as the current v0.6 maturity statement.

## Consequences

- Domain providers must plan from observed state rather than implicit assumptions.
- A complete capability implementation requires evidence for all eleven stages.
- Crash recovery has a defined pre-effect (`prepare`) and post-verification (`commit`) boundary.
- Tests can assert lifecycle ordering independently of specific Linux subsystems.
- Early `0.0.0` code may expose interfaces before production backends exist; this is intentional and must be documented as contract scaffolding rather than completed production functionality.
