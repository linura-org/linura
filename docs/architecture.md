# Architecture

Linura separates **experience**, **intelligence**, and **authority**. Only the authority plane can cause trusted system effects, and no transport, model, UI or executor is allowed to become a parallel source of policy or machine truth.

## Current v0.6 process and trust boundaries

The v0.6 candidate has two deliberately different local D-Bus roles.

`Control1` remains the non-privileged planning/query lineage hosted by `linurad`. The first real managed external effect enters through a separate Experimental `Authority1` system-bus boundary hosted by `linura-authorityd`.

```text
                           local machine

 ordinary client / approved human caller
                 │
                 │ org.linura.Authority1
                 │ authenticated system-bus sender
                 ▼
       ┌──────────────────────────────┐
       │         linura-dbus          │
       │ Authority1 transport adapter │
       │ caller binding + Polkit      │
       └──────────────┬───────────────┘
                      │ human approval for exact request
                      ▼
       ┌──────────────────────────────┐
       │      linura-authorityd       │
       │ unprivileged composition     │
       │ dedicated linura-authority   │
       │ service identity             │
       ├──────────────────────────────┤
       │ linura-control               │
       │ ManagedLifecycleControl      │
       │ durable authority/recovery   │
       │ SQLite/WAL + integrity       │
       │ authoritative observation    │
       └──────────────┬───────────────┘
                      │ exact one-shot managed handoff
                      │ separately authorized as service identity
                      ▼
       ┌──────────────────────────────┐
       │ linura-executor-systemd      │
       │ separately hardened root     │
       │ bounded native effect only   │
       └──────────────┬───────────────┘
                      │ StartUnit / StopUnit
                      ▼
                    systemd
                      │
                      │ fresh native observation
                      ▼
       ┌──────────────────────────────┐
       │ independent verification     │
       │ SystemdObserver + verifier   │
       │ no executor receipt as truth │
       └──────────────┬───────────────┘
                      │ verified postcondition
                      ▼
              commit → audit → reconcile
```

The original human Polkit decision and the executor's service-identity authorization are separate trust decisions. Passing human approval does not create an executor credential. Transaction IDs and digests correlate and bind evidence but are not bearer authority.

The only v0.6 managed external effect is convergence of canonical `linura-managed-*.service` units to exactly `active` or `inactive`. `Authority1` is not a generic apply/systemd/root-RPC surface. See [ADR 0025](adr/0025-bounded-v0.6-managed-mutation-authority.md).

### Non-mutating Control1 lineage

`linurad` remains an unprivileged local control service for the established planning/query surface. In particular, v0.6 does not silently turn `Control1` plan preview into a privileged mutation API.

```text
CLI / SDK / local client
          │
          │ versioned non-privileged protocol
          ▼
       linurad
          │
 authoritative observation
          │
 deterministic planning
          │
 policy/review projections
          ▼
 non-executable result
```

The Authority1 runtime and the Control1 client surface share inward domain/control components where appropriate, but their transport and privilege claims remain explicit.

## Future experience/intelligence topology is not current maturity

Linura's target experience includes First Boot, Agent UI, a local Library, Control Center and Shell. Their architectural position remains outside privileged execution authority:

```text
 First Boot   Agent UI   Library   Control Center   Shell   CLI/SDK
     │           │         │            │             │       │
     └───────────┴─────────┴────────────┴─────────────┴───────┘
                                 │
                      typed Linura protocols
                                 │
                         Control/authority plane
```

However, presence in this target topology does **not** mean current product activation. `contracts/components.toml` is the source of truth for component maturity and milestone activation. For the v0.6 candidate:

- `linura-firstboot` is a `roadmap-scaffold` owned by v0.9 and is not a v0.6 release artifact;
- `linura-agent-runtime` and Agent UI remain future proposal-only v0.8 components with no mutation authority;
- Control Center and Shell remain later roadmap scaffolds;
- supported-reference-environment bootstrap/hardware and broad managed configuration remain later work.

See [ADR 0026](adr/0026-component-maturity-and-milestone-activation.md).

Agent/model processes always remain outside the authority plane. They may eventually read scoped context and emit structured `IntentProposal` objects; they do not receive privileged executor handles. Model output is untrusted proposal data and cannot bypass the canonical lifecycle.

The future Linura Library is also outside execution authority: loading or synchronizing a declarative artifact cannot mutate the machine until Control validates/adopts it through the normal planning and authority path.

## Canonical managed-mutation data flow

A successful managed mutation follows exactly:

```text
request / intent
      │
      ▼
 authoritative observe
      │
      ▼
 deterministic plan
      │
      ▼
    validate
      │
      ▼
   authorize
      │
      ▼
 durable prepare
      │
      ▼
 bounded execute
      │
      ▼
 fresh independent verify
      │
      ▼
    commit
      │
      ▼
     audit
      │
      ▼
  reconcile
```

The successful path cannot skip or reorder stages. Denial/failure may stop earlier; indeterminate execution enters durable recovery rather than replay. See [ADR 0012](adr/0012-canonical-mutation-lifecycle.md) and [Action lifecycle](action-lifecycle.md).

For the broader target product, semantic composition remains:

```text
Conversation / API / saved Setup / imported Profile
                    │
                    ▼
             Intent / adoption
                    │
              requirements
                    │
                    ▼
            Capability Solver
              │            │
        dependencies     conflicts
              └──────┬─────┘
                     ▼
              Desired State
                     │
             Observed State
                     │
                     ▼
                    Diff
                     │
                     ▼
                    Plan
                     │
              policy/approval
                     │
                     ▼
           canonical lifecycle
                     │
                     ▼
            Provenance + Audit
                     │
              System Graph
```

Saved setup/profile adoption does not enter below intent/planning and is never an executor replay mechanism.

## Context acquisition and query plane

Linura must answer increasingly broad semantic questions without turning D-Bus, shell calls or any other transport into its model of the machine. The observation side therefore follows a separate transport-neutral flow:

```text
Semantic context query
        │
        ▼
query planning/orchestration
        │
        ▼
   bounded probes
        │
   ┌────┼───────────────┬─────────────┐
   ▼    ▼               ▼             ▼
systemd hardware     containers     storage/...
provider provider      provider       provider
   │    │               │             │
 D-Bus sysfs/...   socket/API/...   native/...
   └────┴───────────────┴─────────────┘
        │
        ▼
 ObservationEnvelope
        │
        ▼
ObservationCoordinator
        │
        ▼
    System Graph
        │
        ▼
 Context Projection
    │            │
 planner       future agent/RAG
```

A **probe** is one bounded provider-backed acquisition attempt. A **context query** may require one or many probes. A future query runtime may own deadlines, cancellation, bounded concurrency/fan-out, retries, query coalescing, cache/freshness policy, backpressure, partial-result semantics and aggregate resource budgets.

This query plane is not a second authority plane and does not add a stage to the managed-mutation lifecycle. When planning, policy or verification requires current machine truth, the required authoritative observation/freshness contract still applies.

D-Bus has permitted adapter roles, not semantic ownership:

- local Linura client/control transport;
- the v0.6 `Authority1` system-bus transport/caller-authorization boundary;
- provider/internal transport to upstream Linux services such as systemd.

D-Bus object paths, interfaces, signals, Unix file descriptors and wire values remain adapter details. `linura-dbus` must delegate planning, policy, persistence and recovery semantics inward rather than owning them.

Cached observations, context projections and retrieval/RAG may improve efficiency or reasoning, but they do not become current machine truth merely by being available. Retrieval cannot manufacture observed state or grant authority.

## Layering

The practical dependency boundary is encoded in `contracts/layering.toml`; prose is explanatory and must not override that machine contract.

Key ownership rules are:

1. `linura-core`: stable IDs and semantic domain primitives.
2. `linura-intent`: typed intent/setup semantics.
3. `linura-graph`: causal/dependency/conflict/ownership graph.
4. `linura-capability-sdk`: declarative capability/composition contracts.
5. `linura-planner`: deterministic desired-state/reconciliation planning.
6. `linura-provenance`: semantic why-chain primitives.
7. `linura-policy`: risk, policy and approval requirements.
8. `linura-protocol` / `linura-sdk`: non-privileged versioned client contracts/facade.
9. `linura-observation`: canonical authoritative observation envelope/freshness semantics.
10. `linura-observation-control`: provider-neutral authoritative observation coordination.
11. `linura-linux-observation`: concrete Linux observation adapters.
12. `linura-provider-sdk`: provider/executor correlation contracts without policy ownership.
13. `linura-transaction` + persistence adapters: durable authority identity/state and storage.
14. `linura-control`: canonical policy/query orchestration and managed-lifecycle authority.
15. `linura-dbus`: local/system-bus transport adapter, caller binding and Authority1 Polkit boundary.
16. process composition roots such as `linurad` and `linura-authorityd`.
17. narrow privileged executors.
18. non-privileged clients/future experience applications.

Dependencies point inward. UI, Library adapters and agents do not import privileged/provider implementations. Semantic/planning crates do not import transport libraries or concrete Linux providers. `linura-control` does not depend directly on concrete SQLite or systemd adapters; composition roots wire those ports to concrete implementations.

The v0.6 `linura-authorityd` runtime is therefore a composition boundary, not a new semantic layer. Its `main.rs` is intentionally small; its runtime/systemd adapter modules wire inward Control contracts to concrete observation/persistence/executor infrastructure.

## Persistence boundary

The v0.6 authority path has real local durable SQLite/WAL state for authority transactions, request identity/binding, recovery and audit/integrity evidence. That database is authoritative for Linura's durable control records, **not** for current Linux machine state.

Observed Linux state is re-derived from authoritative providers whenever truth matters for planning, verification or recovery. Storage cannot make a desired postcondition true merely because a transaction row says execution occurred.

Broader persistent product state will later include durable intents, requirements, reusable setup/profile revisions, Library metadata, graph edges, desired state and richer provenance/reconciliation records as their milestones activate.

Portable export/import remains separate from authority-state backup. Portable artifacts preserve reusable declarative meaning; authority-state backup preserves local operational/evidence records; filesystem snapshots preserve exact machine recovery state.

## Architectural sources of truth

When prose and implementation appear to disagree, resolve the disagreement rather than choosing whichever source is convenient:

- architecture decisions: `docs/adr/`;
- dependency direction: `contracts/layering.toml`;
- API stability: `contracts/stability.toml`;
- component maturity/activation/packaging: `contracts/components.toml`;
- milestone sequence and claim boundaries: `contracts/roadmap.toml` plus `docs/milestones/`;
- exact D-Bus ABI: `interfaces/dbus/*.xml` plus live introspection tests;
- release evidence: release contracts and exact-source qualification workflows.
