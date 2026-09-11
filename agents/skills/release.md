# Release task guide

Linura treats a release as a bounded claim plus exact-source evidence. Build candidate bytes once, prove them, promote those same bytes, publish tag-last, independently verify the publication, then close bookkeeping and clean only exact release-owned temporary refs. Release handoff authority is defined by [ADR 0027](../../docs/adr/0027-protected-release-handoff-automation.md) and its [release-automation threat model](../../docs/threat-model-release-automation.md).

## One-time repository setup

The automatic release control plane requires a dedicated **Linura Release GitHub App** installed only on `linura-org/linura`. It is the identity that creates and merges machine-owned release PRs so GitHub emits ordinary native `pull_request` and `push` workflow events instead of approval-gating recursive repository-`GITHUB_TOKEN` activity.

Configure:

- repository variable `LINURA_RELEASE_APP_CLIENT_ID` = the GitHub App client ID;
- repository secret `LINURA_RELEASE_APP_PRIVATE_KEY` = the App private key;
- installation repository access = only `linura-org/linura`;
- repository permissions = **Actions: write**, **Contents: write**, **Pull requests: write**;
- no organization administration permission, no secrets permission, no environment permission, and **no ruleset bypass**;
- default-branch ruleset required approval count = **0** while App-created mechanical release PRs are part of the normal automatic path;
- `release` environment has **no required reviewer** in automatic mode. It may still restrict deployment to protected `main` and hold publication-scoped credentials.

The workflows mint short-lived installation tokens with `actions/create-github-app-token` pinned to an immutable commit. Cleanup requests a narrower token (`Contents: write`, `Pull requests: read`). The App private key is never passed to scripts or shell commands; only the token-minting action receives it.

Every machine mutation phase proves the minted token non-mutatingly before use. Missing, ambiguous or under-permissioned authority fails closed. The App never bypasses protected `main`.

## Semantic boundary

- Start each version with `docs/milestones/vX.Y.Z.md`; close implementation and semantic release material before release preparation.
- The final implementation-completion PR eligible to begin the release machinery must merge with subject `release: ready vX.Y.Z — <implementation theme>`.
- Before that merge, freeze `docs/releases/vX.Y.Z.md` with claim class, scope, security/authority boundary, migration/recovery compatibility, limitations and explicit non-goals, and complete the version qualification, security and release-review dossiers.
- **`release: ready` is the last semantic/manual review boundary.** Human/Codex findings on that PR remain blocking until resolved. Every later PR is mechanically or structurally constrained and is verified by exact source/tree/path/message contracts plus protected native GitHub checks.

A blanket approving-review requirement or a required reviewer on the `release` environment would contradict the automatic-after-readiness contract. If that policy is intentionally introduced later, the release contract must explicitly acknowledge the new manual boundary instead of silently stalling automation.

## Automatic machine handoff

After the reviewed readiness merge, the normal path is:

`release: ready` → Release Preparation → protected mechanical preparation PR → Release Authorization → protected zero-diff authorization PR → native exact-main gates → Trusted Release Proof → Promotion → tag-last Release → exact-tag independent Release Verification → Release Closure Handoff → protected deterministic Post Release Closure PR → native closure-main gates → terminal leased cleanup.

No conversational review, environment approval, workflow approval, branch push, proof dispatch, release dispatch, closure dispatch, or cleanup command is part of the normal path after the reviewed readiness boundary.

### Release Preparation

`Release Preparation` triggers from the exact `release: ready ...` merge on protected `main`.

- It first requires native `push` CI/Security/CodeQL on that exact readiness SHA.
- It deterministically runs `tools/prepare_release.py`; the candidate may change only `Cargo.toml` and `Cargo.lock` and must be a one-parent child of the readiness source.
- The Release App creates `automation/release-prep-vX.Y.Z-<full-candidate-sha>` and opens `release: prepare vX.Y.Z <implementation theme>`.
- The full candidate SHA in the branch name is part of cleanup authority: a branch whose tip does not equal the embedded SHA is never an automatic cleanup target.
- **Native `pull_request` CI/Security/CodeQL are the ruleset-authoritative gates.** The controller waits for those exact PR runs, zero unresolved review threads, and GitHub `mergeable_state=clean`.
- `workflow_dispatch` checks are supplemental evidence only; they do **not** substitute for native PR gates.
- Immediately before merge, the controller re-proves exact base/head/branch, one parent, the two permitted changed files and deterministic bytes, then squash-merges through the normal protected-main ruleset.
- A retry reuses only an exact open candidate passing the same proof. An orphaned SHA-addressed branch is safe to leave for terminal cleanup.

The Release App-originated merge produces a normal `push` event, which automatically starts Release Authorization.

### Release Authorization

`Release Authorization` triggers from the exact `release: prepare ...` main commit.

- It requires native `push` CI/Security/CodeQL on the exact prepared SHA.
- It constructs a single-parent, tree-identical metadata-only candidate carrying the exact `release: vX.Y.Z — <implementation theme>` message and `Reviewed-Source` / `Reviewed-Tree` trailers.
- The candidate branch is `automation/release-authorization-vX.Y.Z-<full-candidate-sha>`.
- The Release App opens a protected zero-diff authorization PR.
- The controller waits for native PR CI/Security/CodeQL, zero unresolved review threads and clean ruleset state. Native runs ending in `action_required` are hard failures; successful `workflow_dispatch` copies are not accepted as replacements.
- Immediately before merge, it re-proves the native gate state, protected-main source, branch head, one parent, identical tree and exact message/trailers, then squash-merges normally.
- It never PATCHes protected `main` and never uses ruleset bypass.

After authorization merge, ordinary main `push` CI/Security/CodeQL run. `Release Proof Dispatch` observes those native completions. Once all three exact authorization-source push gates are successful, it idempotently dispatches Trusted Release Proof. The permanent main CI workflow does not cancel an in-progress main run when a later main commit appears, so exact-source proof handoffs cannot lose their gate evidence through concurrency cancellation.

### Proof, promotion and publication

Trusted Release Proof binds the exact authorization source and all required qualification/build/reproducibility/provenance evidence. Promotion validates the successful proof run and exact source; it does not rebuild the release payload.

Before Promotion may dispatch the irreversible Release workflow, closure-readiness mints a fresh Release App installation token and proves the full closure authority contract. Missing or under-permissioned App configuration therefore fails **before** tag creation or GitHub Release publication.

Release remains tag-last:

- validate exact current-main release source;
- download and reverify the sealed proof payload;
- validate checksums, SBOM/provenance and release contract;
- create or verify the immutable version tag only after proof succeeds;
- publish the exact sealed assets and canonical `RELEASE_NOTES.md` body;
- dispatch independent verification from the exact immutable tag.

The `release` environment is an isolation boundary, not a second human gate in automatic mode. Required environment reviewers must be disabled for this mode.

### Independent verification and closure

`Verify published release` runs from the exact immutable tag in the normal path. The authenticated `verify-release/vX.Y.Z` branch is an emergency recovery mechanism only and is **not** pattern-deleted by terminal cleanup; exceptional recovery refs require an explicit exact-SHA ledger entry if cleanup is desired.

A successful verifier dispatches `Release Closure Handoff`, which binds the exact verification run/tag/source/event/ref and dispatches `Post Release Closure`.

Post Release Closure:

- re-proves immutable publication and exact successful proof/promotion/release/verification evidence;
- deterministically advances roadmap/current-next state and terminal qualification/publication documentation;
- preserves `docs/releases/vX.Y.Z.md` byte-for-byte;
- creates or reuses a single-parent `automation/post-release-vX.Y.Z-<full-candidate-sha>` commit;
- opens the PR with the Release App;
- waits for **native PR** CI/Security/CodeQL, zero unresolved review threads and clean ruleset state;
- re-proves the exact candidate immediately before protected squash merge;
- stops after merge. It does not perform cleanup inline.

Separating closure merge from cleanup is intentional: an already-successful irreversible merge must not be reported as a failed closure merely because a later cleanup/network step had trouble.

## Terminal cleanup

`Post Release Cleanup` is event-driven from native `push` CI/Security/CodeQL on the exact `chore: close vX.Y.Z release state` commit. It waits until all three native main gates are successful, then freezes cleanup authority to that immutable closure SHA. The closure SHA must still be an ancestor of current protected `main`; later development may advance `main` without retargeting the already-qualified cleanup transaction.

Cleanup reads `contracts/release-branch-cleanup.toml` from the exact qualified closure commit and may select only:

- SHA-addressed `automation/release-prep-vX.Y.Z-<40hex>` refs;
- SHA-addressed `automation/release-reprepare-vX.Y.Z-<40hex>` refs;
- SHA-addressed `automation/release-authorization-vX.Y.Z-<40hex>` refs;
- SHA-addressed `automation/post-release-vX.Y.Z-<40hex>` refs;
- exceptional/legacy refs only when the exact ledger records release + full branch name + reviewed 40-hex SHA.

The embedded/ledger SHA is the deletion lease. Branches referenced by open PRs are preserved. A ref whose current SHA differs from its lease is preserved. Deletion uses atomic Git `--force-with-lease=<ref>:<expected-sha>`; there is no REST read-then-unconditional-delete race. Exact absence is idempotent. Authentication/network/server or ambiguous lookup failures fail closed rather than being treated as absence.

Cleanup uses a narrower Release App token and is a separate retryable transaction. The immutable tag, Release body/assets, frozen release contract and protected main history are never cleanup targets.

## Ruleset and credential invariants

- Protected `main` remains the authority boundary. Do not add a release-bot ruleset bypass.
- Required native contexts remain `canonical-check`, `dependency-audit` and `analyze` from GitHub Actions under the repository ruleset.
- The automatic release-mode default-branch ruleset must not require approving reviews on machine-only post-readiness PRs. Semantic review is completed before the `release: ready` merge.
- Machine PRs must be created by the Linura Release GitHub App, not repository `GITHUB_TOKEN`, because `GITHUB_TOKEN`-created PR activity may produce approval-gated `action_required` native runs.
- Native PR checks are authoritative for PR merge. Explicit `workflow_dispatch` runs are supplemental exact-SHA evidence/recovery, never a substitute for the ruleset's native PR instances.
- Read-only qualification/proof jobs continue using the narrower repository `GITHUB_TOKEN` where recursion is irrelevant. Workflow-to-workflow `workflow_dispatch` is acceptable for proof/promotion/release/verification/closure handoffs.
- Every irreversible mutation is preceded by exact identity and evidence checks; retries re-prove state instead of assuming the previous attempt stopped before mutation.
- A changed head invalidates prior structural evidence.
- Permission drift, missing App configuration, unresolved findings, failed gates, source drift or policy drift stop the release rather than degrading to bypass or manual normal-path intervention.

Supported release claims additionally require system/profile/hardware/upgrade/recovery evidence appropriate to the declared claim class.
