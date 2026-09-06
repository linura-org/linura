# Testing strategy

Linura changes host state **and** interprets user intent, so correctness requires systems testing, deterministic authority testing and adversarial intelligence-boundary testing. A green unit suite is not sufficient evidence for a privileged managed effect.

## Layers

1. Pure unit/property tests — IDs, intent lifecycle, graph invariants, solver, policy, lifecycle state machines and deterministic planning.
2. Schema/contract tests — public JSON/TOML/D-Bus/API compatibility, live introspection and stability metadata.
3. Provider/observation contract tests — fake/native buses/APIs, canonical observations and freshness/authority semantics.
4. Durable authority tests — SQLite/WAL transactions, exact bindings, idempotency, recovery generations, corruption and write-failure behavior.
5. Executor/verifier tests — bounded privileged input, transport/authorization failure, independent verification and malformed binding rejection.
6. Deterministic managed-lifecycle fault matrix — exact state-machine/control failure scenarios with durable persistence and dispatch counters.
7. Disposable-system integration/acceptance — real systemd, system D-Bus, Polkit, SQLite/WAL, process restart and privileged service boundaries.
8. Release-proof replay — exact-source mandatory qualification repeated from the release authorization before build/promotion.
9. Agent boundary tests — prompt injection, malicious proposal, stale context, disagreement, provider outage; these activate only with the relevant agent milestones.
10. Profile/hardware/support matrices — required only when a release actually claims a platform/machine/hardware boundary.
11. Supply-chain/release verification — SBOM, checksums, provenance/attestations, byte reproduction and published-asset verification.

## Required negative paths for managed mutation

Mutation work is incomplete without coverage appropriate to the capability for:

- unauthorized actor / failed human approval;
- direct privileged-executor bypass attempt;
- unsupported/missing capability or resource namespace;
- malformed/changed stable request identity;
- dependency/conflict/unsatisfied plan where applicable;
- stale authoritative evidence at review/prepare/handoff;
- provider/executor unavailable;
- dispatch failure/ambiguity;
- verification `NotSatisfied` / `Inconclusive` or transport failure;
- retry/idempotency ambiguity and duplicate-dispatch prevention;
- crash after durable handoff or possible effect but before finalization;
- recovery evidence conflict;
- reconciliation failure after commit without effect replay;
- corrupted/failed durable state where applicable.

## v0.6 qualification model

v0.6 deliberately requires **two complementary proof layers**, followed by release-time replay.

### Deterministic fault/recovery matrix

The repository-owned v0.6 matrix exercises the complete authority composition using real SQLite persistence plus controlled authoritative observer/executor/verifier behavior. It must cover all eleven named scenarios:

1. inactive→active success, exact retry and changed-body substitution rejection;
2. active→inactive success;
3. denial/out-of-scope before dispatch;
4. stale evidence;
5. executor failure → durable indeterminate/no redispatch;
6. verifier transport failure → no commit/replay;
7. indeterminate execution → no blind replay;
8. crash/restart after handoff → durable indeterminate/no reconstructed dispatch authority;
9. `NotSatisfied` → safe re-prepare semantics; restart retires stale `Prepared` authority;
10. conflicting recovery → block;
11. reconciliation failure after commit → retry verification/reconciliation only, without execution replay.

Dispatch counters are part of the proof: it is not enough to return an idempotent-looking receipt while executing twice.

### Disposable real-system gate

`.github/workflows/v06-managed-lifecycle-vm.yml` runs the exact source in a disposable Ubuntu guest with real:

- systemd;
- system D-Bus;
- Polkit;
- `linura-authorityd`;
- root `linura-executor-systemd`;
- SQLite/WAL authority state;
- production-style packaged D-Bus/Polkit/systemd service boundaries plus test-only qualification grant material.

The guest proves the actual `Authority1 → authorityd → Control → executor → systemd → independent observation/verifier` path, including:

- live Authority1/Executor introspection;
- unapproved human denial;
- ordinary/root direct-executor denial;
- wrong namespace/state rejection;
- inactive→active and active→inactive complete success;
- exact retry without duplicate systemd dispatch;
- same operation ID / changed body rejection without side effect;
- real verification-not-satisfied behavior without replay;
- executor loss + authority restart without blind replay;
- SQLite WAL mode and integrity evidence;
- the deterministic eleven-case fault matrix executed inside the disposable guest.

The real-system gate does not replace the deterministic fault matrix, and the deterministic matrix does not replace the real-system gate.

### Trusted Release Proof

The final release authorization reruns mandatory inherited qualification plus the v0.6 exact-source managed-lifecycle gate before the sealed builder/promotion can run. Evidence from an obsolete PR head or earlier development commit is not release evidence for a compacted/final source SHA.

## Intent lifecycle negative paths

When the persistent intent lifecycle activates, it is incomplete without:

- retire an intent with exclusively owned resources;
- retire an intent sharing dependencies with another active intent;
- suspend/resume without accidental cleanup;
- supersede while preserving lineage;
- out-of-band administrator repair conflicting with reconciliation.

Those are principally v0.7+ claims; their scaffold presence does not widen v0.6.

## Agent-native UX negative paths

When agent/First Boot surfaces activate, their evidence includes:

- no network;
- no model configured;
- model provider outage/rate limit;
- malicious content attempting prompt/tool escalation;
- specialist disagreement;
- deterministic default/import path.

v0.6 has no agent execution authority and does not claim these future surfaces as implemented merely because their architecture is documented.

## Future context-query/probe acceptance contract

When a generalized context-query runtime is implemented, its work is incomplete without repeatable negative-path coverage for:

- per-probe timeout/deadline enforcement and propagation of remaining deadline to downstream probes;
- cancellation without orphaned unbounded work;
- admission control when requested latency/resource/freshness service bounds cannot be honored;
- bounded concurrency/fan-out and aggregate resource budgets;
- provider unavailability and deterministic partial-result semantics;
- stale/future/mismatched cached evidence rejection when current authority is required;
- query coalescing that preserves caller isolation, freshness, provenance and each caller's service contract;
- bounded cache/history growth and deterministic eviction;
- backpressure and bounded response/result size;
- deterministic aggregation for contracts that require deterministic output;
- per-result source/provenance/freshness retention;
- retries that do not silently exceed the caller's deadline/resource budget;
- transport/provider handles remaining scoped to their adapter rather than escaping into semantic/public contracts;
- transport/provider failure without leaking implementation-specific authority into the domain model;
- proof that model/retrieval confidence cannot substitute for required authoritative observation;
- proof that retrieval/RAG output cannot become authoritative observed state or an authority grant;
- fleet/cluster federation, when introduced, preserving local-machine authority and explicit partial-failure semantics.

These requirements are a future implementation contract, not a current release capability claim. They do not add a stage to the canonical managed-mutation lifecycle.

## Acceptance principle

A demo is not an acceptance test. Release/support claims require repeatable evidence from clean/disposable machines and recovery from injected failures appropriate to the exact declared capability.

A harness existing is not evidence. A workflow file existing is not evidence. A successful run for a different SHA is not evidence. Release documentation must identify exact-source proof once it exists.

## Executable harnesses

The repository includes executable harness boundaries:

- `cargo xtask check` for canonical local/CI validation;
- `tools/acceptance.py` for versioned guest scenarios;
- `tools/vm.py` for disposable QEMU/KVM planning/start;
- `tools/image.py` for image planning/build where relevant;
- `tools/visual.py` for reviewed visual-baseline comparison;
- permanent milestone-specific workflows such as v0.4 durability/ENOSPC, v0.5 executor/verifier and v0.6 managed-lifecycle qualification;
- `hardware/fixtures/` and `hardware/support-matrix.json` for later support evidence.

Release claims must identify the exact source, workflow/scenario, guest image/environment and successful evidence used to support the claim.
