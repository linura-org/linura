# ADR 0027: Protected release handoff automation

- Status: accepted

## Context

Linura's proof-first, tag-last release design intentionally separates implementation review, release preparation, metadata-only authorization, exact-source proof, promotion, immutable publication, independent verification, and terminal roadmap/branch closure. During v0.7.0, several transitions between those stages still required a human or ad-hoc helper to create the next branch/commit/workflow dispatch. A `GITHUB_TOKEN` push or PR mutation is also deliberately prevented by GitHub from recursively creating ordinary workflow events, so silently relying on token recursion can stop the chain even when the preceding job succeeds.

Automating these handoffs introduces a repository-control credential with meaningful write capability. Treating that token as generic release authority would collapse the trust boundaries the release architecture is intended to preserve.

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

### Metadata-only authorization through protected main

Release authorization is represented by a zero-diff PR whose sole commit has exactly one parent—the reviewed release-preparation source—and exactly the same Git tree. Its message binds:

```text
release: vX.Y.Z — <implementation theme>
Reviewed-Source: <40-character preparation SHA>
Reviewed-Tree: <40-character tree SHA>
```

A reused authorization PR is re-proved for exact branch/head/base identity, zero changed files, one exact parent, identical tree, and exact authorization message before it may continue and again immediately before merge. The resulting protected-main squash commit is independently checked for the same tree, parent and trailers.

No workflow directly updates protected `main`; preparation, authorization, and post-release bookkeeping merge only through the repository ruleset and exact-head checks/review.

### Dedicated credential and least privilege

`RELEASE_AUTOMATION_TOKEN` is required for preparation, authorization, and post-release closure mutations whose branch pushes, PR creation and protected-main merges must create native GitHub events. There is no `GITHUB_TOKEN` fallback for these mutation handoffs. The dedicated credential is exposed only to jobs that need repository/PR/Actions mutation. Read-only qualification and proof jobs continue to use narrower repository credentials.

The token may create/delete release-scoped branches, create PRs/comments, merge an already-qualified protected PR, and dispatch workflows as required by the handoff. It does **not** receive release-tag or GitHub Release publication authority. Final tag creation and publication remain isolated in the Release workflow behind its existing environment and exact proof/source checks.

Promotion independently requires the dedicated closure credential and proves its Contents, pull-request and Actions capabilities before immutable publication is allowed to begin. A missing, rotated or permission-reduced credential blocks publication rather than allowing a release that cannot close itself safely.

### Event and replay semantics

The dedicated credential is used because a `GITHUB_TOKEN`-authenticated push or PR creation cannot be treated as a reliable recursive workflow trigger. Release Preparation and Authorization require downstream push events to materialize. Post Release Closure is stricter: its PR must produce native `pull_request` CI/Security/CodeQL runs on the exact closure SHA so the repository ruleset sees the same check contexts as an ordinary protected PR.

Manually dispatched checks may be useful diagnostic evidence, but they are not a substitute for native PR-associated required checks. Missing downstream events are a hard failure, not an assumed success.

Release handoffs are source-bound and fail closed when `main` moves. Existing version tags are rejected before new authorization. Deterministic branch/title namespaces make retries discoverable, but discovery never substitutes for exact candidate revalidation.

Trusted Release Proof, Release Promotion, and Release independently revalidate current-main source identity, frozen release contract, exact successful gates/proof, and tag conflicts. A replayed preparation/authorization dispatch cannot retarget a different release source.

### Review-before-merge invariant

Every automation-authored PR that can change protected `main` requires review before merge. Preparation, Authorization, and Post Release Closure request an exact-head Codex review, require zero unresolved review threads, bind the review to the candidate head (or the connector's explicit clean reaction), and then re-prove the exact PR head immediately before merge.

A check becoming green is not permission to race a still-running review. A late review finding is a release blocker and must be fixed on a new exact head, rechecked and re-reviewed before merge.

### One verification-to-closure path

Normal immutable publication explicitly dispatches `Verify published release` from the exact release tag. The verifier does not accept a manual `workflow_dispatch` from `main`; the workflow ref must equal the requested tag. The only alternative verifier trigger is the authenticated `verify-release/vX.Y.Z` emergency recovery branch.

A successful verifier dispatches `Release Closure Handoff`. The handoff waits until that exact verification run is terminal and successful, binds the tag to the source SHA proven from published evidence, validates exact-tag or authenticated recovery-ref identity, and then dispatches `Post Release Closure`. `Post Release Closure` is dispatch-only, so no competing `workflow_run` closure exists.

Terminal closure generates deterministic roadmap/qualification/current-release documentation, including the human-facing terminal release record, while preserving the frozen `docs/releases/vX.Y.Z.md` contract byte-for-byte. It opens a native-event-producing protected PR, waits for exact-head CI/Security/CodeQL plus completed clean review, merges through the normal ruleset using the exact reviewed SHA, waits for native fresh-main gates, and only then removes obsolete version-scoped release branches.

## Threat analysis

Compromise of `RELEASE_AUTOMATION_TOKEN` could create release-scoped branches/PRs, post review comments, dispatch Actions, or attempt protected PR merges. It cannot by itself create a valid release authorization or publish a version because source/parent/tree/message identity, protected rules, exact-head checks/review, fresh-main gates, release-contract validation, Trusted Release Proof, Promotion readiness, Release source selection, and tag-last publication are independent gates. Repository rules must not grant this credential protected-main bypass authority.

A stolen token may cause denial of service or noisy invalid automation attempts. Invalid/replayed candidates fail closed, and rotation/revocation intentionally stops release handoffs before immutable publication rather than degrading to an unreviewed/manual bypass. Operators rotate or revoke the token through repository secret management; no credential material is stored in the repository, release evidence, artifacts, logs, model context, or portable Linura state.

The release credential is repository delivery infrastructure only. It does not change Linura runtime principal, policy, approval, executor, systemd, agent/model, Library, or managed-mutation authority.

## Consequences

A future release requires an explicit reviewed readiness merge but no undocumented manual branch/commit/dispatch step after that point. Review findings, source drift, token loss, event-recursion failure, candidate tampering, proof failure, publication failure, verification failure, or closure failure remain visible terminal failures rather than being silently bypassed.

The automation is intentionally more conservative than a conventional release bot: it can advance a release only by proving exact previously reviewed state through every existing protected trust boundary.
