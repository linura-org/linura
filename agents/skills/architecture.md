# Architecture task guide

Use this guide for changes that cross Linura subsystem boundaries.

1. Read `docs/architecture.md`, `docs/control-plane.md`, `docs/operation-semantics.md`, ADR 0017, ADR 0018 and ADR 0032 for authority/path-selection work, plus any other relevant ADRs.
2. Preserve the layers: experience → intelligence → authority → graph/capabilities → providers/executors.
3. Preserve transport neutrality: D-Bus, Unix FDs, sockets, subprocesses and native APIs remain adapter details; semantic/planning crates do not import them.
4. Preserve query ownership: providers expose bounded mechanisms; Linura Control owns cross-provider scheduling, budgets, deadlines, caching/coalescing and aggregation.
5. Agents and UI clients never gain direct executor authority; retrieval/RAG never becomes observed state or an authority grant.
6. Keep identity terms separate: `Principal` is the transport-authenticated authority identity; `Actor` is request provenance/classification. Neither term is a backend worker abstraction, and actor kind alone never grants authority.
7. Classify operation semantics separately from risk. Never use a UI/provider/agent hint to weaken the trusted `OperationClass`; only `ManagedExternalEffect` may use a privileged executor, and transient effects are limited to the machine contract's narrow envelope.
8. Prefer new typed domain concepts over shell-output parsing in core code.
9. Update `contracts/layering.toml` and its checker/tests when a legitimate long-lived dependency boundary changes; do not bypass the contract with aliases or target-specific dependencies.
10. Add or update an ADR when changing a long-lived boundary, trust assumption, persistence invariant, operation-semantics rule, or protocol compatibility rule.
11. Run `cargo xtask check`.

A refactor is incomplete if docs, schemas, tests, repository invariants, and dependency direction disagree with code.
