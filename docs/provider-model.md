# Provider model

Providers adapt Linux subsystems to Linura domain contracts. They supply bounded authoritative observation mechanisms and, in later mutation milestones, narrow subsystem-specific execution/verification mechanisms. They do not own Linura's global planning, policy, approval or authority sequence.

A provider/observer declares:
- stable provider ID/version;
- supported observation capabilities;
- resources it can authoritatively observe;
- authoritative typed state/evidence through `ObservationEnvelope`;
- diagnostic metadata;
- bounded transport/resource behavior.

Later mutation-capable adapters may additionally declare narrowly typed effect families, required privilege, postconditions, reversibility/recovery constraints and independent verifier strategy. Those authority contracts are introduced only when the durable prepare/execution milestones require them; they are not inferred from the presence of an observer or provider package.

## Required separation

The current provider SDK has one implemented authority-neutral role:

1. `Observer::observe_authoritative` performs a bounded read-only probe and returns the canonical `linura-observation::ObservationEnvelope`.

Planning remains owned by Linura's deterministic planner/control plane. Providers do **not** author an independently executable plan and policy does not evaluate provider-generated effects.

The old bootstrap `Provider::plan → ActionPlan` path was removed before v0.3 because the released v0.2 architecture established `linura-planner::ReconciliationPlan` as the canonical planning lineage. Preserving both would create competing planning and approval authorities.

Future narrow executors and independent verifiers remain required by the roadmap, but their provider-SDK authority contracts are introduced against the durable prepared-transaction model after v0.4 and qualified in v0.5 rather than freezing the earlier generic scaffold. The existing `executors/linura-executor-systemd` package remains a deliberately narrow future implementation scaffold.

For a `ManagedExternalEffect`, providers/executors/verifiers cannot skip `authorize`, `prepare`, `commit`, `audit` or `reconcile`; those stages remain owned by Linura Control's canonical mutation lifecycle. A provider cannot relabel work as transient to avoid those boundaries.

Operation class is a trusted Linura semantic contract, not provider-owned metadata. Providers may expose bounded mechanism facts such as required privilege, reversibility and postconditions, but any privilege requirement or trusted risk above `UserState` makes the transient external-effect path ineligible. See [Operation semantics](operation-semantics.md) and ADR 0032.

## Bounded probes and orchestration

**Providers expose bounded mechanisms; Linura owns orchestration.**

A provider/observer may perform a narrow probe against its authoritative upstream subsystem. Cross-provider fan-out, global retry policy, query deadlines, cancellation, concurrency limits, admission control, query coalescing, cache policy, backpressure, partial-result policy and aggregate resource budgets belong to Linura's control-plane query orchestration rather than to individual providers.

The current `Observer` interface is intentionally small and synchronous. ADR 0017 defines the boundary for a future context-query runtime without requiring a speculative runtime today. When that runtime is introduced, it may wrap or evolve observer calls to carry explicit budgets/cancellation while preserving the existing authority and freshness semantics.

The probe boundary should remain narrow and stable: semantic request/result types cross it, while D-Bus objects, file descriptors, sockets, process/session handles and other implementation-specific handles remain provider-owned and lifetime-bounded. They are not portable Linura resource identities.

Provider implementations must not turn a bounded request into unbounded polling or silently widen a caller's deadline, resource, freshness or partial-result contract. If the runtime cannot satisfy a requested service bound, it should reject or return an explicit degraded/partial outcome rather than allow a provider to exceed the bound invisibly.

## Transport boundary

D-Bus has two legitimate adapter roles in the current architecture:

1. the local Linura client/control transport (`org.linura.Control1`);
2. a provider/observer's native upstream transport when Linux subsystems such as systemd, NetworkManager or BlueZ expose authoritative APIs over D-Bus.

Neither role defines Linura domain semantics. D-Bus object paths, interfaces, signals, Unix file descriptors and wire values must not leak into transport-neutral capability, desired-state, observation, planning, policy or lifecycle contracts.

The same rule applies to Unix sockets, subprocesses, filesystem/kernel interfaces, native libraries and HTTP/RPC: they are provider/transport mechanisms, not Linura's semantic model.

## Observation and context

`linura-observation::ObservationEnvelope` is the canonical authoritative observation envelope. It preserves provider/resource/capability identity, authority, timestamp/validity, sequence and typed attributes.

There is no second compact provider observation contract. The superseded bootstrap `linura_provider_sdk::Observation` was removed; deterministic planning consumes a validated projection derived from the canonical authoritative envelope rather than allowing a competing state representation to become authority.

Caching and aggregation may retain observations for bounded reuse, history, coalescing and context projection. Cached evidence keeps its provenance and freshness semantics. Cache presence cannot satisfy a consumer that requires a fresh authoritative observation unless the cached envelope still satisfies that exact authority/freshness contract.

Probabilistic confidence from a model/retriever/aggregator is context metadata, not an authority upgrade. Provider-native quality/uncertainty may be represented as typed evidence where a domain requires it, but a required authoritative fact still has to satisfy the provider/resource/capability/freshness contract.

Context projections and future RAG/retrieval may combine observations with historical evidence, documentation or indexed material for reasoning. Retrieval output cannot manufacture authoritative observed state, authorize an effect or replace required post-effect verification.

Expected first providers/adapters:

| Domain | Mechanism/adaptor direction |
|---|---|
| Network | NetworkManager over D-Bus |
| Bluetooth | BlueZ over D-Bus |
| Audio/media | PipeWire/WirePlumber |
| Services | systemd D-Bus |
| Storage | UDisks2 + filesystem-specific helpers |
| Authorization | Polkit integration at the appropriate authority milestone |
| Snapshots | Snapper |
| Firewall | nftables/firewalld profile, selected by platform profile |
| Packages | pacman on Arch profile |

Providers must not leak raw command output into public API types. Provider-specific diagnostics may be attached in explicitly namespaced diagnostic fields. Observation and future verification evidence should be structured enough to support freshness, correlation and audit without making provider-specific text the source of truth.

## v0.5 observation/verifier ownership

For the v0.5 systemd restart qualification, `linura-linux-observation` owns native systemd observation and exposes the canonical monotonic activation timestamp in `ObservationEnvelope`. The verifier is intentionally transport-independent: it receives canonical observation as input and must not open D-Bus connections, call systemd, or consume executor self-report as truth. This keeps observation authority in the provider/observation boundary and verification logic independently testable.
