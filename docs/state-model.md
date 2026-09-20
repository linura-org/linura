# State model

Linura distinguishes four truth categories:

1. **Intent** — approved durable purpose/constraints.
2. **Desired state** — deterministic state derived from intent/capabilities/policy.
3. **Observed state** — what providers prove is currently true on Linux.
4. **Provenance/history** — why and how desired/observed state changed.

The local database is authoritative for Linura-managed intent and history; Linux providers are authoritative for actual current system state.

## Derived and retrieved context

Linura may retain, aggregate or retrieve additional context without creating new truth categories:

- a **cached observation** is previously acquired provider evidence with preserved provenance and freshness;
- a **context projection** is a normalized derived view assembled for a specific planner/UI/agent/diagnostic question;
- **retrieval context** may include documentation, historical evidence, logs/diagnostics or future RAG/index results.

**Retrieval context is not observed state.** A cache is not automatically current truth, a context projection is not an authority grant, and an agent/model assertion cannot manufacture machine-state evidence.

When planning, policy or verification requires current authoritative state, Linura must use an `ObservationEnvelope` satisfying the required provider/resource/capability identity and freshness contract. Cached evidence may be reused only when it still satisfies that exact contract.

A probabilistic **confidence** score belongs to derived/retrieval context unless it is explicitly provider-native quality/uncertainty evidence defined by a domain contract. Confidence assigned by a model, retriever or aggregator cannot upgrade an inferred/cached fact into authoritative observed state. If a required authoritative fact is unavailable or ambiguous, mutation paths fail closed rather than substituting a high-confidence inference.

This keeps the hierarchy explicit:

```text
approved intent        → authority for what Linura should manage
desired state          → deterministic target derived from intent
fresh observation      → evidence for what is currently true
cached observation     → retained evidence with explicit freshness
context projection     → derived consumer view
retrieval / RAG        → reasoning context only
```

## Operation semantics versus state truth

State truth and operation semantics are separate concerns. `ObservationEnvelope` answers what Linux proves is true; `OperationClass` answers which authority path a requested operation may use.

A direct experience action such as focusing a window does not become durable desired state merely because it changes session behavior. A transient external effect is intentionally not retained as desired state. Conversely, when a user expresses durable intent such as "maintain this profile state", the resulting external convergence is a managed external effect even if the same subsystem also exposes lightweight transient actions.

Operation class is bound by trusted registered semantics and Control, never by UI choice or model confidence. See [Operation semantics](operation-semantics.md).

## Reconciliation

Reconciliation compares desired and observed state, then produces the same plan/policy/execute/verify lifecycle as an interactive request. It never silently overwrites an administrator's intentional out-of-band repair. Drift can be report-only, require approval, or reconcile according to explicit policy.

## Intent-aware cleanup

When intent is retired, desired state is recomputed through the system graph. Shared resources remain if another active intent/capability owns them. Cleanup is a plan with impact, policy, verification and provenance—not package-manager autoremove by itself.
