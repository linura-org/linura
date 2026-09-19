# AGENTS.md

Linura is operating-system authority software. AI agents are useful contributors and runtime interpreters but are never trusted authorities.

## Product invariant

> **Tell your computer what you want it to become.**

Implement that by converting human/model input into typed intent and deterministic desired state. Never implement it by letting a model improvise privileged shell commands.

## Mandatory rules

- Read `SECURITY.md`, `docs/security-model.md`, `docs/agent-architecture.md`, and `docs/vision-coverage.md` before modifying authority, agent, policy, executor, persistence or extension code.
- In a Codex/cloud development environment, run `bash scripts/preflight_codex_environment.sh` before modifying repository files. If it fails, report the environment mismatch rather than silently repairing the task environment.
- `scripts/setup_codex_environment.sh` is environment-creation/bootstrap tooling, not an ordinary task-time installer. Do not install mutable/latest development tools during delegated work; repository-owned Codex tool versions live in `tools/codex/versions.env`.
- Conversation/model output is never the durable source of truth; approved structured intent is.
- Every managed resource must be explainable through semantic provenance.
- Retiring intent must analyze shared ownership/dependencies before cleanup.
- Never introduce arbitrary elevated shell execution.
- Never move general orchestration into a privileged executor.
- Never bypass policy because the caller is local, root-owned, trusted by the user, or an AI agent.
- Agent/model code cannot depend on or receive a privileged executor handle.
- Policy review derives from the canonical `linura-planner::ReconciliationPlan`; do not revive provider-owned or independently client-authored executable plan models.
- Policy `allow`, valid approval, and a reviewed plan are **not** execution authority. They cannot be converted directly into an executor call or privileged credential; durable prepare/revalidation is a later lifecycle boundary.
- Authenticated principal identity is derived by the trusted transport/control boundary and remains distinct from `Actor` provenance. Clients/models cannot choose their principal.
- Never pass secrets in process arguments, logs, audit payloads, model prompts/context, panic messages or fixtures.
- Unknown/unsupported state fails closed for mutations and authority review.
- Provider/platform dependencies stay out of UI and core domain crates.
- D-Bus objects, Unix file descriptors, sockets, process/session handles and other transport primitives remain adapter details. Providers expose bounded mechanisms; cross-provider query budgets, deadlines, caching/coalescing and aggregation belong to Linura Control.
- PlatformProfile compatibility is derived from canonical `linura-observation::ObservationEnvelope` evidence. Do not introduce a second observation authority/envelope in `linura-hardware`, and do not aggregate platform compatibility inside `linura-linux-observation`.
- Cached observations and retrieval/RAG context do not become authoritative current state merely because they are available; required authoritative facts retain provider/resource/capability/freshness requirements.
- Contract version is not contract stability. Before preserving, removing, or changing a public interface/schema/SDK/CLI surface, read `contracts/stability.toml` and `docs/api-versioning.md`.
- Do not create compatibility shims for Experimental contracts merely because an earlier development commit exposed them; replace the contract coherently and update all in-repo consumers/tests/docs in the same change.
- Stable compatibility obligations exist only for contracts explicitly marked `stable` in `contracts/stability.toml`; Stable breaking changes require a new major generation, overlap/migration documentation, and compatibility evidence.
- Generated UI must use typed constrained surfaces or isolated extensions.
- Preserve an offline/no-model path for deterministic control and recovery.

## Architecture ownership

- `linura-core`: stable IDs, actor/principal/risk primitives and semantic reason invariants.
- `linura-intent`: intent/requirements/profile lifecycle.
- `linura-graph`: system causal/dependency/conflict/ownership/evidence projection.
- `linura-capability-sdk`: capability blueprints and relations.
- `linura-planner`: deterministic desired-state derivation and canonical non-executable `ReconciliationPlan`.
- `linura-observation`: canonical authoritative observation envelope and freshness primitives.
- `linura-observation-control`: provider-neutral authoritative observation coordination and bounded retained evidence.
- `linura-linux-observation`: concrete narrow Linux observation adapters/probes; transport mechanisms remain internal and cross-provider compatibility aggregation is forbidden.
- `linura-hardware`: QualificationEnvironment/hardware evidence plus provider-neutral PlatformProfile contracts and single-fact compatibility rules over canonical `ObservationEnvelope` evidence; Control owns cross-fact aggregation; no observation or support-promotion authority.
- `linura-provenance`: why-chain lineage.
- `linura-policy`: deterministic policy/review/approval semantics over the canonical plan lineage; no provider/executor authority.
- `linura-protocol`: versioned public contracts.
- `linura-provider-sdk`: bounded provider/observer contracts; future executor/verifier authority contracts are introduced only at the milestones that can qualify them.
- `linura-agent-runtime`: untrusted intent interpreters/specialists; no authority.
- `linura-control`: Linura Control; unprivileged authority/control-plane and future context-query orchestration.
- `linura-lifecycle`: canonical eleven-stage state machine; presence of future stages is not a support claim.
- `linura-dbus`: local D-Bus transport adapter; does not own planning/authority semantics.
- `linura-sdk`: public non-privileged client/integration façade; must not expose authority/provider/executor internals.
- `executors/*`: narrow future privileged effectors only; dormant roadmap scaffolds are not deleted merely because execution is not yet supported.
- `apps/*`: clients/process entry points; no duplicate domain rules.

## Change procedure

1. Identify the user intent and durable domain object affected.
2. Identify graph/provenance consequences.
3. Identify trust/privilege boundary crossed.
4. Identify whether code is obsolete, live, or deliberate future scaffold before deleting it.
5. Update core/intent/graph/protocol first where their contract actually changes.
6. Update planner/policy/provider/executor as applicable without creating parallel authority paths.
7. Add failure/denial/shared-ownership and anti-drift tests before UI work.
8. Update ADR/RFC and threat model for contract or trust-boundary changes.
9. Run the repository quality gate.

## Task-specific guides

Before changing a specialized subsystem, read the corresponding guide under `agents/skills/`:

- architecture;
- intent and system graph;
- protocol/SDK;
- providers;
- privileged executors;
- policy;
- migrations;
- platform profiles;
- VM acceptance;
- shell/UI;
- visual verification;
- security review;
- release engineering.

Use `cargo xtask check` as the canonical completion gate. A missing VM/hardware/visual dependency means that evidence was not run; never report it as passing.
