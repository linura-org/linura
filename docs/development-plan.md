# Development plan

The development order proves the intent-native model **without depending on an LLM first** and preserves the canonical mutation lifecycle from the first supported managed effect.

The canonical version spine lives in [Roadmap](roadmap.md). This document explains implementation sequencing and proof dependencies; it must not independently redefine release meaning. Every implementation version is governed by a mutable milestone contract under `docs/milestones/`; before tagging, that milestone closes into a frozen `docs/releases/` contract with a bounded claim class and permanent acceptance evidence. See [Release contracts, claims and evidence](release-contracts.md).

## Phase 0 — Linura architecture lock (complete for v0.0.0)

Exit criteria:
- Linura naming is complete;
- product vision and trust boundaries are explicit;
- intent, reusable setup/Library, graph, capability, provenance, policy and provider contracts exist;
- portable setup/profile exports are self-contained and secret-safe by contract;
- the canonical eleven-stage mutation lifecycle is encoded in code and ADRs;
- first platform profile and recovery constraints exist;
- version-scoped milestone/release contracts and machine-readable release-evidence semantics exist;
- CI/repository checks reject legacy naming and validate frozen release contracts.

The v0.0.0 release contract remains an **Architecture** claim: the contracts and development foundation exist, but production authority backends and supported machine behavior do not.

## Phase 1 — observe and build the system graph (complete for v0.1.0)

This phase was completed by [v0.1.0](milestones/v0.1.0.md).

Implemented:
1. session D-Bus service `org.linura.Control1`;
2. caller credential extraction and actor binding;
3. provider registry/capability discovery;
4. systemd + NetworkManager read-only observers;
5. observation envelopes/freshness;
6. resource nodes/edges in the system graph;
7. `linuractl observe`, `graph`, `capabilities`, `explain` (observed evidence only).

No root authority is required by the observation surface.

## Phase 2 — deterministic intent → desired state → non-executable plan, no AI (complete for v0.2.0)

This phase was completed by [v0.2.0](milestones/v0.2.0.md).

Implemented with hand-authored intents and capability blueprints to prove:

```text
Intent → requirements → capability resolution → conflicts → desired state
→ authoritative observation → diff → structural validation → plan preview
```

The plan preview is deliberately non-executable. It binds the semantic origin and exact authoritative evidence used for planning, reports prospective risk and blockers, and always carries `execution_authorized = false`.

Use a constrained example such as a systemd service on a disposable VM. Prove both a proposed change and an already-satisfied no-change state, and prove that planning itself does not alter the machine. No model provider, executor, Polkit authority, prepare/commit or public `apply` operation exists in this phase.

`v0.2.0` includes the structural plan/risk/provenance foundations needed by the next phase, but it does not claim the policy/approval or mutation-authority parts of Phase 3.

## Phase 3 — policy-evaluated plan review + semantic provenance (complete for v0.3.0)

This phase was completed by [v0.3.0](milestones/v0.3.0.md).

Implemented on the canonical v0.2 plan lineage: Control-owned fail-closed trusted risk classification, deterministic policy outcomes, authenticated-principal-bound plan review, exact policy/risk/evidence/provenance binding, required approval classes, bounded process-local approval evidence with expiry/revocation/replay protection, and Experimental Control1/SDK/CLI review/explanation surfaces. Public review results remain explicitly non-executable.

The phase deliberately stops before durable `prepare`, persistent authorization/recovery state, privileged executor integration, Polkit authority, post-effect verification, commit/audit/reconciliation, or any supported managed external mutation. Those boundaries remain later milestones.

## Phase 4 — durable prepare/commit and recovery foundation (target v0.4.0)

Select local persistence via ADR and implement the transaction boundary required before any supported external mutation:
- request/plan idempotency;
- durable `prepare` intent-to-execute record;
- exact plan/evidence/authorization binding;
- indeterminate-operation recovery state;
- verified `commit` transaction model for desired state/graph/provenance;
- append-only success/failure audit foundations;
- migration, versioning and corruption-detection basics.

A crash after prepare must recover by re-observing authoritative state, never by blindly replaying an effect. Durable state alone does not grant mutation authority.

## Phase 5 — first narrow privileged executor and independent verifier (target v0.5.0)

Implement `linura-executor-systemd` over systemd D-Bus with strict unit validation and Polkit. No arbitrary command execution.

Implement verification as a separate boundary consuming post-execution authoritative observation. Executor success alone is never state proof.

The executor/verifier may be exercised against a deliberately narrow disposable test fixture to qualify component behavior, failure paths, timeouts and indeterminate outcomes. **Phase 5 remains qualification-only:** it must not expose a supported public `apply` path or claim Linura-managed external mutation as a product capability.

The first supported managed external effect is reserved for Phase 6, after these components are integrated with authorization, durable prepare/recovery, commit, audit and reconciliation through the complete canonical lifecycle.

## Phase 6 — first complete eleven-stage vertical slice (target v0.6.0)

Make one narrow capability traverse the entire canonical path:

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

Add denial tests, approval tests, failure injection, crash/indeterminate recovery, compensation where applicable, drift tests and VM acceptance evidence. A successful effect without successful verification/commit/audit is not a successful managed mutation.

Phase 6 is the first milestone allowed to publish a bounded Experimental supported managed external effect.

## Phase 7 — persistent intent lifecycle + local Linura Library (target v0.7.0)

Persist intents, requirements, desired state, graph, provenance, approvals, audit and reconciliation state. Implement suspend/supersede/retire and shared-ownership removal impact using the same canonical mutation lifecycle for resulting changes.

Implement the local-first reusable configuration layer:
- Setup revisions and composition;
- Setup → adopted-intent provenance edges;
- self-contained setup/profile export/import;
- same-device and cross-device dry-run adoption;
- missing secret-reference reporting/resolution;
- local Library listing/history/version retention;
- capture from Linura-managed causal state without blindly serializing installed packages.

Sync backends and signatures remain optional/later; local file/store export is sufficient for this phase.

## Phase 8 — agent interpretation (target v0.8.0)

Introduce model/provider adapters whose only authority output is `IntentProposal`. Add specialist advice and disagreement/conflict handling. Test prompt injection, malicious tool proposals, stale context and provider unavailability.

Agents may propose saving/adopting setups, but Library operations and adoption remain typed deterministic APIs. Imported setup text never becomes executable model output.

## Phase 9 — First Boot + supported Experimental reference environment (target v0.9.0)

Implement the signature flow: "What do you want this computer to become?" over the exact ADR 0029 Ubuntu 24.04 server/amd64/QEMU-TCG/headless QualificationEnvironment, while `arch-hyprland-v1` remains the first interactive workstation PlatformProfile.

Support interactive-owner, prepare-for-another-owner and unattended-local entry modes. Fresh intent, default profiles, local Library material, portable Setup/MachineProfile imports and bounded Provisioning Manifest input all remain declarative and converge on local QualificationEnvironment discovery, fresh authoritative observation, fresh planning, verified recovery readiness and a non-authorizing submission to Control. First Boot never accepts caller-manufactured policy approval or execution authority.

Make provisioning restart-safe and idempotent; keep remote access deny-by-default; separate bounded bootstrap networking from final managed networking; keep hardware adaptation typed/reviewable rather than script-authoritative; and qualify migration/backup/restore, update interruption, native recovery and exact guest-installed binary identity.

The v0.9 claim is Linura installation/adoption on the pinned Linux base, not a general bare-metal/full-disk/dual-boot OS installer or desktop experience. Declare the first Experimental reference support only when all version-specific acceptance evidence exists.

## Phase 10 — meaningful end-user Experimental Linura (target v0.10.0)

Integrate the proven trust core into a coherent external-user experience without prematurely claiming Stable support:

- First Boot, local Library and profile/setup workflows;
- initial Control Center and shell surfaces over the same typed control protocol;
- essential system domains required by the Experimental reference environment;
- manual operation that remains complete without AI;
- bounded agent-assisted `IntentProposal` workflows;
- explanation, diagnostics and audit surfaces;
- install/update/recovery flows exercised by user-facing system acceptance;
- explicit unsupported-domain/platform/compatibility boundaries.

Use v0.10 to discover and close product-level gaps under a truthful Experimental contract before the Stable threshold is attempted.

## Phase 11 — Stable support qualification (target v1.0.0)

`v1.0.0` is reserved by Linura's versioning policy for the first Stable supported end-user contract. Do not tag 1.0 merely because the product is usable or the feature list is large.

The declared Stable reference scope must qualify, at minimum:

- supported distribution/desktop/hardware profiles;
- install/bootstrap and First Boot behavior;
- migration, upgrade, backup/restore, rollback and recovery paths;
- canonical lifecycle and privilege boundaries for every Stable mutating path;
- failure injection, crash/restart, power-loss and indeterminate-operation recovery;
- security/threat-model review and documented support/security-response expectations;
- compatibility/deprecation guarantees for Stable public contracts;
- resource bounds, daemon resilience, corruption handling and soak testing;
- reproducible/attested release and rollback/recovery publication procedures;
- privacy-safe diagnostics/support evidence.

Experimental providers and extensions may coexist with v1.0 only if the Stable release contract clearly excludes them from the supported boundary.

## Phase 12 — broader system domains (post-v1 strategic expansion)

Expand network, Bluetooth, audio, power, storage, packages, firewall, updates/snapshots, displays, containers/virtualization and other system domains. Every managed domain uses the same eleven-stage mutation lifecycle rather than defining a domain-specific authority shortcut.

Provider breadth does not automatically inherit Stable status. Each capability advances independently through domain maturity and version-specific evidence.

## Phase 13 — personal operating environment, workflows and derived UI (post-v1 strategic expansion)

Add declarative workflow runtime, constrained derived surfaces, machine profile/personality composition, profile/setup capture from managed causal state, coherent shell/design-system behavior and accessibility/input parity.

Custom code uses isolated extensions only. Workflow steps still enter Linura Control through typed requests and cannot bypass the mutation lifecycle.

Reusable workflows can later be cataloged by the Linura Library, but portability contracts must stabilize before Stable support is claimed.

## Phase 14 — extension and sharing ecosystem (post-v1 strategic expansion)

Add capability-isolated extensions, signed manifests/update policy, canonical setup/profile serialization and digests/signatures, optional Git/user-owned/hosted Library synchronization, and UI/workflow extension points.

All hosted/model/sync providers remain optional. None becomes the source of local execution authority.

## Phase 15 — optional enterprise and fleet (post-v1 strategic expansion)

After local trust and the Stable reference contract are proven, add enrollment, mTLS, remote policy, audit export, enterprise setup/profile catalog controls, fleet desired intent/state, staged rollout and rollback, and enterprise model/provider controls.

Remote/fleet requests and synced setups enter the same local authority lifecycle. No remote catalog becomes the source of execution authority, and loss of enterprise connectivity must not destroy local recovery.
