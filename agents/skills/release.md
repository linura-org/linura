# Release task guide

Linura treats a release as a bounded claim plus exact-source evidence. Build candidate bytes once, prove them, promote those same bytes, publish tag-last, independently verify the publication, then close bookkeeping and clean only release-owned temporary refs. Release handoff authority is defined by [ADR 0027](../../docs/adr/0027-protected-release-handoff-automation.md) and its [release-automation threat model](../../docs/threat-model-release-automation.md).

## One-time repository setup

The automatic release control plane requires a dedicated **Linura Release GitHub App** installed only on the Linura repository. It is the identity that creates and merges machine-owned release PRs so GitHub emits ordinary native `pull_request` and `push` workflow events instead of approval-gating recursive `GITHUB_TOKEN` activity.

Configure:

- repository variable `LINURA_RELEASE_APP_CLIENT_ID` = the GitHub App client ID;
- repository secret `LINURA_RELEASE_APP_PRIVATE_KEY` = the App private key;
- installation repository access = only `linura-org/linura`;
- repository permissions = **Actions: write**, **Contents: write**, **Pull requests: write**;
- no organization administration permission, no secrets permission, no environment permission, and **no ruleset/bypass actor**.

The workflows mint short-lived installation tokens with `actions/create-github-app-token` pinned to an immutable commit. Cleanup requests a narrower token (`Contents: write`, `Pull requests: read`). The App private key is never passed to scripts or shell commands; only the token-minting action receives it.

Every machine mutation phase proves the minted token non-mutatingly before use. An identical base/head repository merge must return GitHub's no-op `204`, an identical base/head PR must return the exact same-head validation response, and a workflow dispatch against an impossible all-zero ref must return exact missing-ref validation. Missing or ambiguous authority fails closed.

## Semantic boundary

- Start each version with `docs/milestones/vX.Y.Z.md`; close implementation and semantic release material before release preparation.
- The final implementation-completion PR eligible to begin the release machinery must merge with subject `release: ready vX.Y.Z — <implementation theme>`.
- Before that merge, freeze `docs/releases/vX.Y.Z.md` with claim class, scope, security/authority boundary, migration/recovery compatibility, limitations and explicit non-goals, and complete the version qualification, security and release-review dossiers.
- **`release: ready` is the last semantic review boundary.** Human/Codex findings on that PR remain blocking until resolved. Every later PR is mechanically or structurally constrained and is verified by exact source/tree/path/message contracts plus protected native GitHub checks; the automation must not manufacture a bot-to-bot conversational-review dependency.

## Automatic machine handoff

After the reviewed readiness merge, the normal path is:

`release: ready` → Release Preparation → protected mechanical preparation PR → Release Authorization → protected zero-diff authorization PR → native exact-main gates → Trusted Release Proof → Promotion → tag-last Release → exact-tag independent Release Verification → Release Closure Handoff → protected deterministic Post Release Closure PR → native closure-main gates → terminal leased cleanup.

No manual approval, workflow approval, branch push, proof dispatch, release dispatch, closure dispatch, or cleanup command is part of the normal path after the reviewed readiness boundary.

### Release Preparation

`Release Preparation` triggers from the exact `release: ready ...` merge on protected `main`.

- It first requires native `push` CI/Security/CodeQL on that exact readiness SHA.
- It deterministically runs `tools/prepare_release.py`; the candidate may change only `Cargo.toml` and `Cargo.lock` and must be a one-parent child of the readiness source.
- The dedicated Release App creates/pushes `automation/release-prep-vX.Y.Z-<source-prefix>` and opens `release: prepare vX.Y.Z <implementation theme>`.
- **Native `pull_request` CI/Security/CodeQL are the ruleset-authoritative gates.** The controller waits for those exact PR runs, zero unresolved review threads, and GitHub `mergeable_state=clean`.
- `workflow_dispatch` checks may be used elsewhere as supplemental evidence, but they do **not** substitute for native PR gates.
- Immediately before merge, the controller re-proves exact base/head/branch, one parent, the two permitted changed files and deterministic bytes, then squash-merges through the normal protected-main ruleset.
- A retry must reuse only an exact candidate that passes the same proof. Title or branch name alone is never authority.

The Release App-originated merge produces a normal `push` event, which automatically starts Release Authorization. There is no explicit manual or token-recursion workaround.

### Release Authorization

`Release Authorization` triggers from the exact `release: prepare ...` main commit.

- It requires native `push` CI/Security/CodeQL on the exact prepared SHA.
- It constructs a single-parent, tree-identical metadata-only candidate carrying the exact `release: vX.Y.Z — <implementation theme>` message and `Reviewed-Source` / `Reviewed-Tree` trailers.
- The Release App opens a protected zero-diff authorization PR.
- The controller waits for native PR CI/Security/CodeQL, zero unresolved review threads and clean ruleset state. It explicitly rejects native runs ending in `action_required`; successful `workflow_dispatch` copies are not accepted as a replacement.
- Immediately before merge, it re-proves the native gate state, protected-main source, branch head, one parent, identical tree and exact message/trailers, then squash-merges normally.
- It never PATCHes protected `main` and never uses ruleset bypass.

After authorization merge, ordinary main `push` CI/Security/CodeQL run. `Release Proof Dispatch` observes those native completions. Once all three exact authorization-source push gates are successful, it idempotently dispatches Trusted Release Proof. This event-driven edge is deliberately separate from the merge job: if a runner dies after the merge, the GitHub event still owns the next transition.

### Proof, promotion and publication

Trusted Release Proof must bind the exact authorization source and all required qualification/build/reproducibility/provenance evidence. Promotion validates the successful proof run and exact source; it does not rebuild the release payload.

Before Promotion may dispatch the irreversible Release workflow, `closure-readiness` must mint a fresh Release App installation token and prove the full closure authority contract. Therefore a missing, rotated, unapproved or under-permissioned App fails **before** tag creation or GitHub Release publication.

Release remains tag-last:

- validate exact current-main release source;
- download and reverify the sealed proof payload;
- validate checksums, SBOM/provenance and release contract;
- create or verify the immutable version tag only after proof succeeds;
- publish the exact sealed assets and canonical `RELEASE_NOTES.md` body;
- dispatch independent verification from the exact immutable tag.

Do not generate an independent release narrative. Candidate payloads must include the canonical source/tag/notes/evidence/checksum/SBOM/provenance material required by the release contract.

### Independent verification and closure

`Verify published release` runs from the exact immutable tag in the normal path. The authenticated `verify-release/vX.Y.Z` branch is an emergency recovery mechanism only. Verification redownloads assets and validates tag/source binding, release metadata, checksums, release-body identity, release immutability and build provenance.

A successful verifier dispatches `Release Closure Handoff`, which binds the exact verification run/tag/source/event/ref and dispatches `Post Release Closure`.

Post Release Closure:

- re-proves immutable publication and exact successful proof/promotion/release/verification evidence;
- deterministically advances roadmap/current-next state and terminal qualification/publication documentation;
- preserves `docs/releases/vX.Y.Z.md` byte-for-byte;
- creates or reuses a single-parent `automation/post-release-vX.Y.Z-<verification-run>` commit;
- opens the PR with the Release App;
- waits for **native PR** CI/Security/CodeQL, zero unresolved review threads and clean ruleset state;
- re-proves the exact candidate immediately before protected squash merge;
- stops after merge. It does not perform cleanup inline.

Separating closure merge from cleanup is intentional: an already-successful irreversible merge must not be reported as a failed closure merely because a later cleanup/network step had trouble.

## Terminal cleanup

`Post Release Cleanup` is event-driven from native `push` CI/Security/CodeQL on the exact `chore: close vX.Y.Z release state` commit. It waits until all three native main gates are successful, then freezes cleanup authority to that immutable closure SHA. The closure SHA must still be an ancestor of current protected `main`; later development may advance `main` without retargeting the already-qualified cleanup transaction.

Cleanup reads `contracts/release-branch-cleanup.toml` from the exact qualified closure commit and may select only:

- release-owned `automation/release-prep-...` refs;
- `automation/release-reprepare-...` refs;
- `automation/release-authorization-...` refs;
- `automation/post-release-...` refs;
- `verify-release/vX.Y.Z` recovery refs;
- legacy `tmp/...` refs only when the exact ledger records release + branch + reviewed SHA.

Branches referenced by open PRs are preserved. Legacy refs whose SHA moved are preserved. Every automation-owned deletion first reads the target SHA, then re-reads it immediately before deletion; if it moved, it is preserved. Exact absence is idempotent. Authentication/network/server or ambiguous lookup failures fail closed rather than being treated as absence.

Cleanup uses a narrower Release App token and is a separate retryable transaction. The immutable tag, Release body/assets, frozen release contract and protected main history are never cleanup targets.

## Ruleset and credential invariants

- Protected `main` remains the authority boundary. Do not add a release-bot ruleset bypass.
- Required native contexts remain `canonical-check`, `dependency-audit` and `analyze` from GitHub Actions under the repository ruleset.
- Machine PRs must be created by the Linura Release GitHub App, not repository `GITHUB_TOKEN`, because `GITHUB_TOKEN`-created PR activity may produce approval-gated `action_required` native runs.
- Native PR checks are authoritative for PR merge. Explicit `workflow_dispatch` runs are supplemental exact-SHA evidence/recovery, never a substitute for the ruleset's native PR instances.
- Read-only qualification/proof jobs continue using the narrower repository `GITHUB_TOKEN` where recursion is irrelevant. Workflow-to-workflow `workflow_dispatch` is acceptable for proof/promotion/release/verification/closure handoffs.
- Every irreversible mutation is preceded by exact identity and evidence checks; retries re-prove state instead of assuming the previous attempt stopped before mutation.
- A changed head invalidates prior structural evidence.
- Permission drift, missing App configuration, unresolved findings, failed gates, source drift or policy drift stop the release rather than degrading to bypass or manual normal-path intervention.

Supported release claims additionally require system/profile/hardware/upgrade/recovery evidence appropriate to the declared claim class.
