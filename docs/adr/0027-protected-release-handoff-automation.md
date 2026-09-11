# ADR 0027: Protected release handoff automation

- Status: accepted

## Context

Linura's proof-first, tag-last release design intentionally separates implementation review, release preparation, metadata-only authorization, exact-source proof, promotion, immutable publication, independent verification, and terminal roadmap/branch closure. During v0.7.0, several transitions between those stages still required a human or ad-hoc helper to create the next branch/commit/workflow dispatch. A `GITHUB_TOKEN` push or PR mutation is also deliberately prevented by GitHub from recursively creating ordinary workflow events, so silently relying on token recursion can stop the chain even when the preceding job succeeds.

Automating these handoffs introduces repository-control authority with meaningful write capability. Treating that authority as generic release authority would collapse the trust boundaries the release architecture is intended to preserve.

## Decision

Linura uses an explicit, protected release-handoff control plane with the following boundaries.

### Explicit reviewed readiness

Ordinary feature merges never self-promote into a release. The automatic preparation edge begins only when protected `main` receives an exactly formatted, reviewed implementation-completion commit:

```text
release: ready vX.Y.Z — <implementation theme>
```

The readiness source must still be current `main`, match roadmap `next_release` and the milestone title, contain the milestone/release/qualification/security/release-review material, have publication-stable release wording, be associated with exactly one merged protected PR, have no unresolved source-review thread, and pass fresh-main CI/Security/CodeQL.

Automation does not author product claims or authority boundaries. It consumes already-reviewed release semantics and performs only deterministic mechanical handoffs.

### Deterministic preparation and retry identity

Release Preparation advances workspace-owned Cargo version metadata only. The candidate must be a single-parent child of the exact readiness source and differ only in `Cargo.toml` and `Cargo.lock`. Those files are regenerated deterministically from the readiness source.

If an automation PR already exists after a retry or interrupted run, its branch, head, parent, changed-path set, commit subject, and exact regenerated file bytes are re-proved before reuse and again immediately before merge. A modified or substituted candidate fails closed rather than being adopted because its PR title happens to match.

Release Preparation remains the semantic review boundary for the release candidate. It may require an exact-head human/Codex review because it contains actual release metadata changes and is the last place where reviewed release semantics are frozen before machine-only handoffs begin.

### Metadata-only authorization through protected main

Release authorization is represented by a zero-diff PR whose sole commit has exactly one parent—the reviewed release-preparation source—and exactly the same Git tree. Its message binds:

```text
release: vX.Y.Z — <implementation theme>
Reviewed-Source: <40-character preparation SHA>
Reviewed-Tree: <40-character tree SHA>
```

A reused authorization PR is re-proved for exact branch/head/base identity, zero changed files, one exact parent, identical tree, and exact authorization message before it may continue and again immediately before merge. The resulting protected-main squash commit is independently checked for the same tree, parent and trailers.

The authorization PR is a machine-only transport object, not a new semantic review surface. It does not require a conversational reviewer. Merge authority comes from the already-reviewed preparation source plus exact structural invariants, explicit exact-head CI/Security/CodeQL, zero unresolved review threads, current-main identity, and the repository ruleset.

No workflow directly updates protected `main`; preparation, authorization, and post-release bookkeeping merge only through the repository ruleset and exact-head checks.

### Repository-scoped operator and least privilege

Release handoff mutation jobs use the ephemeral repository `GITHUB_TOKEN`, with job-scoped `contents: write`, `pull-requests: write`, and `actions: write` only where those capabilities are required. Every mutation job proves those capabilities non-mutatingly before changing release state. Read-only qualification and proof jobs retain narrower permissions.

The operator may create/delete release-scoped branches, create PRs, merge an already-qualified protected PR, and explicitly dispatch the next exact-SHA workflow. It does **not** receive release-tag or GitHub Release publication authority outside the isolated Release workflow. Final tag creation and publication remain behind the release environment, exact proof/source checks, and tag-last invariant.

Promotion independently proves that the repository token can perform the later protected closure operations before immutable publication begins. Permission reduction or repository-policy drift blocks publication rather than allowing a release that cannot close safely.

### Event and replay semantics

GitHub intentionally suppresses recursive workflow triggering for many mutations authenticated by `GITHUB_TOKEN`. Linura therefore does not treat native-event recursion as a release primitive. After an automation-owned protected merge, the owning workflow explicitly dispatches CI, Security, and CodeQL on the exact resulting `main` SHA, waits for those exact workflow-dispatch runs to succeed, and then explicitly dispatches the next release stage.

Automation-authored PRs can also surface approval-gated or otherwise redundant ordinary `pull_request` workflow attempts. Those attempts are non-authoritative for release control. The authoritative machine evidence is the nonce-bound explicit `workflow_dispatch` run set, whose check contexts satisfy the protected-main ruleset and whose workflow path, ref, SHA, title and run ID are revalidated before merge.

Native push events remain valid evidence when a human or external GitHub App performs a protected merge. Exact-source validators accept only successful gates bound to the same SHA and to either the native `push` event or the explicit `workflow_dispatch` event. Missing, stale, cancelled, ambiguous, or failed gates remain hard failures.

Release handoffs are source-bound and fail closed when `main` moves. Existing version tags are rejected before new authorization. Deterministic branch/title namespaces make retries discoverable, but discovery never substitutes for exact candidate revalidation.

Trusted Release Proof, Release Promotion, and Release independently revalidate current-main source identity, frozen release contract, exact successful gates/proof, and tag conflicts. A replayed preparation/authorization dispatch cannot retarget a different release source.

### Review and machine-handoff invariant

Substantive candidate changes require review before merge. Machine-only handoffs do not invent a conversational-review dependency that the automation identity cannot satisfy.

Release Authorization is zero-diff and tree-identical to an already-reviewed preparation source. Post Release Closure is generated deterministically only after independent published-release verification, is constrained to terminal bookkeeping surfaces, preserves the frozen release contract byte-for-byte, and is re-proved immediately before merge. Both require zero unresolved review threads and exact-head protected checks. Any human review finding that is present remains blocking; absence of a conversational review is not itself a blocker for these structurally proven machine-only transitions.

This distinction avoids a circular dependency where `github-actions[bot]` must impersonate a connected human merely to ask another bot to approve a state transition that is already cryptographically and structurally constrained.

### One verification-to-closure path

Normal immutable publication explicitly dispatches `Verify published release` from the exact release tag. The verifier does not accept a manual `workflow_dispatch` from `main`; the workflow ref must equal the requested tag. The only alternative verifier trigger is the authenticated `verify-release/vX.Y.Z` emergency recovery branch.

A successful verifier dispatches `Release Closure Handoff`. The handoff waits until that exact verification run is terminal and successful, binds the tag to the source SHA proven from published evidence, validates exact-tag or authenticated recovery-ref identity, and then dispatches `Post Release Closure`. `Post Release Closure` is dispatch-only, so no competing `workflow_run` closure exists.

Terminal closure generates deterministic roadmap/qualification/current-release documentation, including the human-facing terminal release record, while preserving the frozen `docs/releases/vX.Y.Z.md` contract byte-for-byte. It opens a protected PR, explicitly dispatches exact-head CI/Security/CodeQL, requires zero unresolved review threads, re-proves the deterministic branch/parent/message boundary, merges through the normal ruleset using the exact head SHA, explicitly dispatches fresh-main gates, and only then removes obsolete release-owned and narrowly version-scoped temporary branches.

## Threat analysis

Compromise of a job-scoped repository token is constrained by GitHub's per-job permissions and short lifetime. A mutation job still cannot create a valid release authorization or publish a version without satisfying source/parent/tree/message identity, protected rules, exact-head checks, fresh-main gates, release-contract validation, Trusted Release Proof, Promotion readiness, Release source selection, and tag-last publication. Repository rules must not grant Actions protected-main bypass authority.

Permission or policy drift is detected by the non-mutating capability probe and stops release handoffs before immutable publication. No long-lived release credential is stored in repository secrets, release evidence, artifacts, logs, model context, or portable Linura state.

The release operator is repository delivery infrastructure only. It does not change Linura runtime principal, policy, approval, executor, systemd, agent/model, Library, or managed-mutation authority.

## Consequences

A future release requires an explicit reviewed readiness merge but no undocumented manual branch/commit/dispatch/review step after the reviewed preparation boundary. Review findings, source drift, permission drift, explicit-dispatch failure, candidate tampering, proof failure, publication failure, verification failure, or closure failure remain visible terminal failures rather than being silently bypassed.

The automation is intentionally more conservative than a conventional release bot: it can advance a release only by proving exact previously reviewed state through every existing protected trust boundary.
