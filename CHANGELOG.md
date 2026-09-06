# Changelog

All notable changes to Linura will be documented here. Version entries stay concise; detailed claims and acceptance boundaries live in `docs/releases/`.

## [Unreleased]

## [0.6.0] - 2026-09-06

Experimental complete bounded managed mutation lifecycle for canonical `linura-managed-*.service` active/inactive convergence. Full release contract: [`docs/releases/v0.6.0.md`](docs/releases/v0.6.0.md).

### Added
- Experimental `org.linura.Authority1.ConvergeSystemdActiveState` managed-authority entry point and dedicated unprivileged `linura-authorityd` composition/runtime service.
- Complete canonical eleven-stage lifecycle for the exact bounded systemd active-state effect, including durable prepare/handoff/recovery, verified commit, audit and reconciliation.
- Stable operation/request-digest binding, exact candidate-bound administrator approval, separately authorized narrow root execution, and fresh independent native-systemd verification.
- Permanent deterministic eleven-case fault/recovery qualification plus disposable-system qualification with real systemd, D-Bus, Polkit and SQLite/WAL.

### Changed
- Trusted Release Proof now requires the v0.6 managed-lifecycle qualification in addition to inherited observation, plan-preview, v0.4 durability/ENOSPC and v0.5 executor/verifier gates before sealed construction or promotion.
- Release-artifact governance includes `linura-authorityd` and continues to exclude future `linura-firstboot` scaffolding.

### Boundaries
- v0.6 remains Experimental and supports only canonical `linura-managed-*.service` active/inactive convergence; no generic apply, shell, arbitrary systemd, package, file, network, storage, firewall, user, container or VM mutation is claimed.
- No supported distribution, machine class, hardware profile, agent/model execution authority, Stable mutation API or production-readiness claim is introduced.

## [0.5.0] - 2026-09-05

Experimental isolated privileged systemd executor and independent verifier qualification. Full release contract: [`docs/releases/v0.5.0.md`](docs/releases/v0.5.0.md).

### Added
- Bounded executor/verifier component contracts with deterministic exact effect/dispatch correlation that remains non-authoritative metadata.
- A qualification-only root systemd executor on the system bus with authenticated D-Bus sender identity, fixed Polkit action, strict `linura-v05-qualification-*.service` namespace, native `RestartUnit`, hardened systemd service isolation, and no shell/arbitrary-command surface.
- Canonical systemd observation of `ActiveEnterTimestampMonotonic` plus a pure independent restart verifier that requires fresh native authoritative evidence and never trusts executor self-report.
- Exact-source disposable Ubuntu 24.04 QEMU qualification covering authorization denial, namespace/binding/effect substitution rejection, provider ambiguity, authoritative pre/post observation, verifier satisfied/not-satisfied/inconclusive outcomes, and hardened service evidence.

### Changed
- Privileged outgoing D-Bus method calls are bounded to five seconds; a timeout after the dispatch attempt is conservatively `Indeterminate` and requires authoritative observation rather than blind retry.
- Trusted Release Proof now requires the v0.5 executor/verifier VM qualification before sealed build and promotion.

### Boundaries
- v0.5 remains Experimental with `executor_state = "isolated-qualified"`, `managed_mutation_support = "none"`, and `complete_lifecycle = false`.
- No public `apply`, `execute`, `mutate`, `restart`, or other managed-mutation surface is released; v0.4's one-shot `DispatchPermit` is not connected to the executor in v0.5.
- No supported Linux distribution, machine class, hardware profile, virtualization profile, or production-readiness claim is introduced.

## [0.4.0] - 2026-09-04

Experimental durable reviewed-authority transaction and recovery foundation. Full release contract: [`docs/releases/v0.4.0.md`](docs/releases/v0.4.0.md).

### Added
- Persistence-neutral durable transaction/generation state with immutable exact authority bindings, stable idempotency, typed recovery outcomes, restart-safe verified material, and Control-owned signer/verifier separation.
- SQLite/WAL authority persistence with application/schema identity, versioned migration ledger, keyed retained-record integrity, bounded persisted-input validation, logical/physical recovery reservations, and a same-filesystem emergency reserve.
- Real ext4 ENOSPC and SQLite/WAL crash/power-loss qualification for the v0.4 recovery guarantees.

### Changed
- Persistence validation now serializes cross-statement integrity checks, authenticates complete retained generation history, validates the complete bounded migration ledger, and repairs only the exact one-slot filesystem-reserve deficit attributable to a rolled-back terminal transition.
- Trusted Release Proof now reruns both v0.4 durability-fault and real-ENOSPC qualification before release build or promotion.

### Boundaries
- v0.4 remains Experimental and adds no supported executor, Polkit grant, apply/execute/mutate surface, generic command authority, or supported Linura-managed external effect.
- Raw storage writers may alter bytes but cannot mint valid keyed integrity tags without the integrity key; coherent whole-database/filesystem/VM-snapshot rollback remains unsupported without a future protected monotonic anchor/restore protocol.
- No supported distribution, machine class, hardware profile, or production-readiness claim is introduced.

## [0.3.0] - 2026-09-02

Experimental policy, authorization, approval, and plan-review milestone. Full release contract: [`docs/releases/v0.3.0.md`](docs/releases/v0.3.0.md).

### Added
- Canonical `workstation`, `server`, and `edge` machine classes, with developer/AI development machines represented as workstation profiles and fleet/enterprise retained as an optional management overlay; no machine class is release-qualified as a supported platform.
- v0.3.0 milestone and qualification contracts plus ADR 0018 for canonical plan-review authority, trusted risk classification, and exact approval binding.
- Typed authenticated-principal, policy/revision, approval-request, and approval-evidence identities with Control-owned opaque trusted review material.
- Deterministic trusted risk classification that treats planner risk as a floor, conservatively elevates the initial typed systemd `active_state` route, blocks unclassified mutation shapes and attempted risk downgrades, and retains risk-policy revision/rule provenance.
- Deterministic typed policy outcomes: `allow`, `deny`, `require-approval`, and fail-closed `blocked`, derived only through the canonical `ReconciliationPlan` lineage.
- Bounded process-local approval issuance, validation, revocation, expiry, idempotent retry, inactive-record reclamation, and replay tombstones with exact trusted-review binding.
- Control-owned authority time with rollback-safe monotonic progress so caller time and wall-clock rollback cannot revive expired authority or reopen replay identifiers.
- Authenticated human approver-class checks that reject self/non-human/under-strength approval while keeping D-Bus caller authentication distinct from approval authority.
- Experimental Control1/SDK/CLI plan-review surfaces, including `review-plan` and `explain-plan-review`, with semantic reason/origin provenance and explicit non-executable output.
- Fail-closed wire consistency checks for blocked decisions, exact reviewed-risk/approval-class strength, protected `allow`, and `change-proposed` reviews falsely claiming read-only risk.
- Exact-source Control1 VM acceptance extended through real daemon/CLI plan review and explanation while proving native Linux state remains unchanged.

### Changed
- Experimental portable machine profiles now preserve a required `machine_class` through `MachineProfile` and `portable-profile.v1`, enabling future cross-class adoption checks without implying current platform support.
- Policy review derives from the canonical non-executable planner lineage and binds authenticated principal, request/plan, authoritative evidence, provider/resource/capability, planned changes/findings, semantic provenance, trusted risk classification, policy identity/revision, and approval requirement.
- Removed the superseded Experimental `ActionPlan` / provider-owned planning / generic apply-runtime stack rather than retaining a competing authority path.
- Canonical `cargo xtask check` / `repo` enforce the v0.3 authority foundation and control-only policy orchestration.
- CLI review output now preserves the same semantic reason summary and intent/requirement/capability origin identities as plan-preview output.

### Boundaries
- v0.3 authority is review-only: policy allow, valid approval evidence, and reviewed-plan status are not execution authority.
- Approval/review retention is bounded and process-local, not durable authorization, prepare state, audit persistence, or crash recovery.
- A D-Bus-authenticated service caller, including UID 0, is not thereby a trusted human/admin approver.
- Risk classification is not mutation support: unknown future mutation semantics are blocked rather than guessed into a weaker approval class.
- No public apply/execute path, Polkit grant, privileged executor integration, durable prepare/commit, managed external mutation, post-effect verification, or complete eleven-stage mutation support is release-qualified.
- No supported Linux distribution, desktop, machine class, physical hardware profile, virtualization profile, natural-language/model authority, or production readiness is claimed.

## [0.2.0] - 2026-09-01

Experimental deterministic desired-state and non-executable planning milestone. Full release contract: [`docs/releases/v0.2.0.md`](docs/releases/v0.2.0.md).

### Added
- Typed declarative capability resource blueprints and deterministic capability resolution/conflict handling.
- Deterministic hand-authored semantic intent/requirements/capability-origin compilation into normalized desired resources.
- Evidence-bound deterministic reconciliation previews with `no-change`, `change-proposed`, and fail-closed `blocked` status.
- Exact authoritative evidence identity, ordered changes/findings, prospective risk, and explicit `execution_authorized=false` in the preview contract.
- Experimental Control1 `PlanDesiredState`, `GetPlanPreview`, and `ExplainPlanPreview` methods with matching checked D-Bus XML, SDK/client methods, CLI commands, and JSON contracts.
- Transport-neutral `linura-control::PlanPreviewControl` as the single orchestration owner for replay checks, authoritative observation, planning, retention, and retained preview lookup/explanation.
- Stable authenticated-principal replay/retention namespaces while preserving the first accepted transport actor as provenance.
- Bounded request decoding and process-local preview retention by entry count, per-entry bytes, and aggregate bytes with deterministic eviction.
- Exact-source `control1-plan-preview` disposable-VM acceptance proving change-proposed, exact retry replay, retained lookup/explanation, no-change, blocked unknown state, idempotency conflict, and unchanged native system state.
- v0.2.0 release qualification requiring both the authoritative-observation regression and Control1 plan-preview VM before release build/promotion.

### Changed
- Moved plan-preview authority orchestration out of `linura-dbus` into `linura-control`; D-Bus now authenticates credentials, adapts typed wire data, and delegates.
- Plan-preview VM path coverage now includes core, graph, control, planning, observation, protocol, SDK, D-Bus, interface, and acceptance/tooling dependencies so semantically relevant changes cannot bypass system qualification.
- Trusted Release Proof now requires both mandatory v0.2.0 VM scenarios before isolated release build and promotion.

### Boundaries
- Plan previews are non-executable and process-local; no public `apply` path exists.
- No policy approval, Polkit authority, durable prepare/commit, managed external mutation, post-effect verification/commit/audit/reconciliation, or complete eleven-stage lifecycle is claimed.
- No supported Linux distribution/profile or hardware tier is declared.
- No natural-language/model interpretation, First Boot, persistent Linura Library, or production readiness is release-qualified.

## [0.1.0] - 2026-08-31

Experimental authoritative-observation milestone. Full release contract: [`docs/releases/v0.1.0.md`](docs/releases/v0.1.0.md).

### Added
- Authenticated session D-Bus `org.linura.Control1` service with transport-derived caller identity.
- Deterministic `linuractl whoami`, `capabilities`, `observe`, `graph`, and evidence-only `explain` surfaces through the public SDK/protocol boundary.
- Provider health/capability discovery with explicit available, degraded, and unavailable states.
- Native read-only systemd and NetworkManager observation with provider/resource identity, authority, freshness, validity, sequence, and typed attributes.
- Projection of authoritative observations into the causal system graph with evidence/explanation linkage.
- Runtime D-Bus introspection lifecycle annotations matching the canonical checked interface contract.
- Historical Stable-contract enforcement against an accepted baseline, while v0.1.0 contracts remain Experimental.
- Repository-owned exact-source disposable-VM qualification using a dated SHA-256-pinned Ubuntu cloud image, ephemeral cloud-init/SSH identity, QEMU snapshot execution, and machine-readable VM evidence.
- Mandatory disposable-VM qualification in Trusted Release Proof before release build/promotion.

### Changed
- Explicit systemd observation resolves installed units through native `LoadUnit` before reading Unit properties, so inactive installed units remain observable after systemd garbage-collects their previous loaded-unit object without starting or rewriting the unit.
- VM acceleration selection now distinguishes `/dev/kvm` presence from usable KVM access; GitHub-hosted qualification uses deterministic TCG and fails immediately if QEMU exits before SSH readiness.
- Renumbered the originally planned `v0.0.1` implementation milestone to `v0.1.0` to follow Linura's pre-1.0 policy: new externally testable capability slices consume a minor version, while patch versions repair an already-published minor line.

### Boundaries
- No managed system mutation is claimed.
- No supported Linux distribution/profile or physical hardware tier is declared.
- No production persistence, migration, First Boot, agent interpretation, Polkit authority, or complete eleven-stage mutation lifecycle is release-qualified.

## [0.0.0] - 2026-08-30

Architecture/bootstrap release. Full release contract: [`docs/releases/v0.0.0.md`](docs/releases/v0.0.0.md).

### Added
- Rust workspace, canonical project layout, root/agent instructions, task-specific skill guides, issue/PR templates, code/security/community policies, and architecture/terminology/state/provider/permission/intent/update/recovery/First Boot/Library/Control Center/agent/packaging/test documentation.
- Shared domain crates for core IDs/reasons, intent/setup/profile objects, causal system graph, capability SDK, planner/policy/lifecycle/provenance/protocol/provider SDK/public SDK/agent runtime/update state, Linura Control, local D-Bus transport, Linux observers, narrow executor scaffolding, update guard, CLI/daemon entry points, First Boot/Control Center/agent UI placeholders, and packaging metadata.
- Versioned JSON schemas and D-Bus XML for intent/setup/profile/plan/audit/machine-profile/public Control1 contracts.
- Canonical eleven-stage mutation lifecycle and failure-aware state machine scaffold.
- Repository quality/security/release tooling including formatting, clippy, tests, docs, SPDX policy, dependency audit, CodeQL, release manifests, SHA-256 asset verification, SBOM generation, trusted release proof, promotion, independent verification, and repository hygiene checks.
- Architecture boundary governance through machine-checked layering rules, ADRs, contract-stability policy, release contracts, milestone/qualification documents, risk register, and threat model.

### Changed
- The originally planned patch-numbered roadmap was rebaselined to pre-1.0 minor releases for new capability slices; released milestone meanings remain immutable and future milestones require explicit rebaseline review.

### Boundaries
- Architecture and scaffolding only; no supported managed mutation, distro/profile, hardware tier, user-facing First Boot/Control Center, natural-language agent interpretation, persistent Library, fleet authority, or production-ready operating environment is claimed.
