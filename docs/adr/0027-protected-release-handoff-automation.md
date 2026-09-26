# ADR 0027: Protected release handoff automation

- Status: accepted

## Context

Linura's proof-first, tag-last release design separates implementation review, deterministic preparation, metadata-only authorization, exact-source proof, promotion, immutable publication, independent verification, terminal bookkeeping and branch cleanup.

v0.8 exposed an important GitHub boundary. Machine PRs created with repository `GITHUB_TOKEN` can cause ordinary `pull_request` workflows to enter `action_required`. Explicit `workflow_dispatch` copies of CI/Security/CodeQL may pass on the same head, but GitHub's strict protected-main merge gate can still treat its required native PR checks as expected. Therefore “green dispatched evidence” is not equivalent to “GitHub considers this protected PR mergeable.”

A release controller that assumes those are interchangeable can prove its own evidence while still being rejected by the repository ruleset. The controller also needs durable handoffs across irreversible merges: a job that merges successfully and then dies before dispatching the next stage must not strand the release.

## Decision

Linura uses a protected, event-driven release-handoff control plane with a dedicated repository-scoped mutation identity.

### Explicit reviewed readiness

Ordinary feature merges never self-promote into a release. The automatic edge begins only when protected `main` receives an exactly formatted reviewed implementation-completion commit:

```text
release: ready vX.Y.Z — <implementation theme>
```

The readiness source must match roadmap `next_release` and milestone title, contain release/milestone/qualification/security/release-review material, preserve publication-stable wording, originate from a merged protected PR with no unresolved review threads, and pass native protected-main gates.

This readiness merge is the **last semantic review boundary**. Automation does not author product claims or authority boundaries after it. Later PRs are deterministic mechanical/structural transports. The normal path after readiness contains no reviewer approval gate. GitHub Environments may exist only as non-interactive credential-identity boundaries with zero required reviewers; they do not add semantic approval.

### Deterministic preparation

Release Preparation changes workspace-owned Cargo version metadata only. The canonical `linura` crate is workspace-versioned as well: its manually published `0.0.1` is a bootstrap reservation release, while all subsequent crate versions advance with `workspace.package.version` before proof, tagging, or publication. Its candidate is a single-parent child of the exact readiness source and differs only in `Cargo.toml` and `Cargo.lock`, deterministically regenerated from that source.

A retried candidate is re-proved for branch/head/base/parent/path/byte identity before reuse and again immediately before merge. New machine branches are content-addressed as `automation/release-prep-vX.Y.Z-<full-candidate-sha>`; the full SHA is later also the cleanup deletion lease.

The machine preparation PR does not require a conversational reviewer: release semantics were reviewed at `release: ready`; the PR is constrained to deterministic version metadata and must satisfy native protected PR gates.

### Metadata-only zero-diff authorization

Release Authorization constructs a single-parent candidate with exactly the reviewed preparation tree and no changed files. Its exact message binds:

```text
release: vX.Y.Z — <implementation theme>
Reviewed-Source: <40-character preparation SHA>
Reviewed-Tree: <40-character tree SHA>
```

Its branch is `automation/release-authorization-vX.Y.Z-<full-candidate-sha>`. The authorization PR is a zero-diff machine transport, not a semantic review surface. It is re-proved before reuse and immediately before merge for exact branch/head/base, one parent, identical tree, zero changed files and exact message/trailers. The protected-main squash result is independently checked for the same parent/tree/trailers.

No workflow PATCHes protected `main`; preparation, authorization and terminal closure merge through normal repository rules.

### Repository-scoped operator: Linura Release GitHub App

The **Linura Release GitHub App** is the Repository-scoped operator for machine-owned release PR mutations.

Repository configuration is:

- `LINURA_RELEASE_APP_CLIENT_ID` repository variable;
- `LINURA_RELEASE_APP_PRIVATE_KEY` repository secret;
- installation access only to `linura-org/linura`;
- repository permissions Actions write, Contents write and Pull requests write;
- no protected-main ruleset bypass.

Workflows mint short-lived installation tokens with a pinned `actions/create-github-app-token`. The private key is never passed to shell or release tools. Read-only qualification/proof stages retain ordinary narrow repository `GITHUB_TOKEN` permissions where recursion is irrelevant. Terminal cleanup requests a narrower App token than PR mutation.

Every mutation phase probes its App token non-mutatingly: an identical base/head repository merge must return the no-op `204` through the Contents-write endpoint; an identical-base/head PR must return exact validation; and an all-zero-ref workflow dispatch must return exact missing-ref validation. Any missing or ambiguous capability fails closed.

The operator may create release-scoped branches, create protected PRs and merge already-qualified PRs. It has no special runtime authority and no ruleset bypass. Tag and GitHub Release publication remain isolated in the Release workflow behind exact Trusted Release Proof, Promotion and tag-last validation.

Promotion independently proves full App closure authority before immutable publication can begin. Permission drift therefore blocks publication rather than producing an immutable release that already needs manual bookkeeping recovery.

### Native PR checks are merge authority

For machine-owned PRs, native GitHub `pull_request` CI, Security and CodeQL are the ruleset-authoritative checks. The controller binds them to exact PR number, head branch and head SHA; requires successful terminal conclusions; requires zero unresolved review threads; and requires GitHub's ruleset/mergeability state to be clean.

A native run with `action_required`, failure, cancellation or ambiguity is blocking. A successful `workflow_dispatch` run on the same SHA does **not** replace the native PR instance. Explicit dispatch remains supplemental evidence/recovery, but not a protected-PR merge substitute.

This is why the App—not repository `GITHUB_TOKEN`—must originate machine branch/PR mutations. App-authenticated writes produce ordinary GitHub events without the token-recursion suppression/approval behavior that broke the old model.

The default-branch ruleset must not impose a blanket approving-review requirement on the machine-only PRs that occur after the reviewed readiness boundary. If such a policy is later required, the ruleset must explicitly separate semantic-development PRs from constrained release handoffs rather than granting the Release App a bypass.

### Durable event-driven main transitions

Irreversible protected merges and their next stage are separated by persisted GitHub events rather than a fragile same-job tail.

- App-authenticated readiness/preparation merges emit normal `push` events that start the next controller workflow.
- Authorization merge emits native main push CI/Security/CodeQL.
- `Release Proof Dispatch` observes those `workflow_run` completions and, after all exact authorization-source push gates succeed, idempotently dispatches Trusted Release Proof.
- Terminal closure merge emits native main push CI/Security/CodeQL.
- `Post Release Cleanup` observes those completions and, after all exact closure-source gates succeed, performs cleanup as a separate retryable transaction.

The canonical CI workflow does not cancel in-progress `main` runs when a later main commit appears. Exact-source push evidence therefore remains durable for proof and cleanup handoffs.

A runner may disappear after a successful merge without losing the next transition because GitHub already persisted the merge/push/check event.

Source drift remains fail-closed. Existing version tags are rejected before new authorization. Deterministic SHA-addressed branch namespaces make retries discoverable and safely leaseable but never authoritative by themselves.

### Review and machine-handoff invariant

A human review finding remains blocking until resolved. Machine-only preparation, authorization and deterministic closure do not manufacture a mandatory bot-to-bot conversational-review dependency.

Preparation is deterministic two-file metadata. Authorization is tree-identical zero-diff. Closure is generated only from independently verified immutable publication evidence, is restricted to terminal bookkeeping surfaces and preserves the frozen release contract byte-for-byte. All three still require exact structural proof, native protected checks and zero unresolved review threads.

The GitHub tag/Release publication job has no GitHub Environment dependency in automatic mode. Trusted Release Proof plus Promotion/closure-readiness remain the machine-verifiable GitHub publication boundary. Registry publication uses narrowly scoped, non-interactive GitHub Environments only as OIDC identity boundaries:

- `pypi` is attached only to the minimal PyPI upload job in `release.yml`; the no-OIDC preflight and no-OIDC post-upload verifier remain separate jobs. The upload job has no repository checkout or repository script execution and receives the only PyPI-capable `id-token: write` permission in that workflow.
- `crates-io` is attached only to the minimal crates.io Trusted Publishing job after independent GitHub/PyPI release verification.

Both environments store no registry secret and have no required reviewer. Adding an environment reviewer, widening OIDC to build/test jobs, or attaching either environment to a broader job is a release-contract change and invalidates the automatic-after-readiness claim.

### One-time PyPI namespace bootstrap

Before the first PyPI project exists, a Pending Trusted Publisher does not reserve
the `linura` name. A narrowly bounded bootstrap exception is therefore permitted
inside the already-trusted `release.yml` workflow for `linura==0.0.1` only.

The bootstrap is not a Linura release and grants no tag, GitHub Release, crates.io,
release-verification, or closure authority. It must bind to exact protected
`main`, require native main push CI/Security/CodeQL, build only the dependency-free
Python package under the hash-locked Python toolchain, independently reproduce the
wheel byte-for-byte, and reuse the same single minimal `pypi` OIDC upload job plus
a no-OIDC registry verifier. Immediately before authentication/upload, that minimal
job revalidates live protected `main` through a SHA-pinned GitHub API action.
Because bootstrap and canonical publication share the `release.yml` workflow
identity, canonical promotion and closure additionally bind acceptable publication
runs to the exact `Release — release @ <source-sha>` display identity and reject
bootstrap run identities. A pre-existing exact version is verified and reused; any
conflicting filename set or bytes fail closed. This exception is removed after the
first verified namespace claim.

### Registry publication boundaries and one verification-to-closure path

The canonical Python wheel is produced only inside Trusted Release Proof from the exact release source under the hash-locked Python build toolchain, sealed into the proof payload, independently reproduced byte-for-byte and attested. Release performs a no-OIDC PyPI preflight against that exact sealed wheel. If the version is absent, only the minimal `pypi` environment job may exchange GitHub OIDC for PyPI publication authority; if the version already exists, its complete distribution set and bytes must exactly match the sealed artifact or the release fails closed. A no-OIDC post-upload job re-downloads/verifies PyPI before downstream release verification is dispatched. A failure after GitHub Release publication but before PyPI verification leaves the lifecycle incomplete and retryable; it does not authorize verification, crates.io publication or closure.

Normal immutable publication explicitly dispatches `Verify published release` from the exact release tag only after GitHub publication and the PyPI handoff have both been independently verified. The only alternate verifier trigger is the authenticated `verify-release/vX.Y.Z` emergency recovery branch.

A successful verifier persists a bound verification-evidence artifact and terminates. That verification includes a fresh PyPI lookup/download whose complete filename set and SHA-256 bytes must match the sealed proof artifact, so the verifier cannot treat a merely successful upload action as publication evidence. The canonical crates.io workflow starts only from GitHub's persisted terminal `workflow_run` event for `Verify published release`; it authenticates the completed run plus exact tag/source/event/ref, including the marker-only `verify-release/vX.Y.Z` recovery shape, before qualification. Qualification runs without OIDC authority; only the dependent `crates-io` environment job may obtain a short-lived Trusted Publishing credential. It rejects stale-main/tag drift and requires any existing immutable crate version to have the exact qualified checksum. After independent registry checksum and non-yanked availability verification succeeds, the crates.io workflow persists a publication-evidence artifact binding its exact run ID, source, release tag, verification identity, crate version and checksum. It dispatches `Release Closure Handoff` with that exact crates.io run ID; both the handoff and `Post Release Closure` authenticate the successful crates.io run plus artifact and live non-yanked registry state before terminal mutation. There is one durable verification-to-registry-to-closure path; direct closure dispatch without matching registry evidence fails closed.

Closure deterministically advances roadmap/qualification/current-release documentation, creates a Release App-owned protected PR on `automation/post-release-vX.Y.Z-<full-candidate-sha>`, waits for native PR gates and merges normally. It does not clean branches inline.

`Post Release Cleanup` begins only after native CI/Security/CodeQL succeed on the closure merge. It freezes cleanup authority to that immutable closure commit, requires that commit to remain in protected `main` ancestry, and reads its exact `contracts/release-branch-cleanup.toml`.

Normal automatic cleanup may select only full-SHA-addressed release-owned preparation, re-preparation, authorization and closure refs. Older or exceptional refs are eligible only through an exact release + branch name + reviewed 40-hex SHA ledger entry. Open-PR refs are preserved. Each deletion is an atomic Git `--force-with-lease=<ref>:<expected-sha>` operation, so a concurrent branch move cannot be deleted by stale evidence.

## Threat analysis

### Credential compromise

A Release App installation token is short-lived and repository-scoped. Its permissions are explicitly requested per phase. The App has no ruleset bypass and cannot produce a valid publication without exact structural checks, native rules, Trusted Release Proof, Promotion readiness, tag-last validation and independent publication verification.

PyPI and crates.io publication credentials are short-lived OIDC exchanges, not stored API tokens. Their blast radius is constrained by exact Trusted Publisher identity, dedicated GitHub Environment identity, job-local `id-token: write`, and minimal upload jobs that do not execute repository-controlled build/test code. A compromised or misconfigured registry publisher can still cause denial of service or an irreversible conflicting version, so existing-version identity is checked before publication and registry bytes are independently re-downloaded and verified afterward.

The long-lived App private key exists only as a GitHub repository secret and is passed only to the pinned token-minting action. It is not written to artifacts, logs, model context, release evidence or portable Linura state.

### Candidate substitution and retry tampering

A discovered branch or PR is not trusted by name/title. Exact source/base/head/tree/parent/path/message and deterministic bytes are re-proved. Native gates are bound to the exact candidate. Any head mutation invalidates prior evidence.

### Event-recursion failure

The controller does not depend on repository `GITHUB_TOKEN` recursively producing PR/push events. Mutation PRs are App-originated. Cross-workflow proof/promotion/release/verification/closure dispatches use supported `workflow_dispatch`, while post-merge transitions use persisted native App-originated push/check events.

### Rotation, revocation and permission drift

Every future release preflights App authority before mutation, and Promotion preflights closure authority before publication. Revocation, missing installation approval or permission drift fails closed. There is no fallback to ruleset bypass, long-lived PAT, manual normal-path approval or repository-token PR creation.

### Cleanup TOCTOU

The exact successful closure-source main gates create an immutable cleanup authorization commit point. Cleanup policy is read from that commit and the commit must remain in protected-main ancestry.

Each normal automation target carries its expected 40-character SHA in the branch name; exceptional legacy targets carry the same lease in the reviewed ledger. Open-PR targets are preserved. The cleanup tool confirms the current ref still equals the lease and deletes with an atomic Git `--force-with-lease` push. If the ref moves concurrently, Git rejects the deletion and the tool preserves/reports the moved branch. Exact absence is idempotent; ambiguous API/authentication/network failure is not treated as absence.

The exact release tag, immutable GitHub Release, published assets, frozen release contract, protected main history, recovery verifier refs unless explicitly ledgered, and unrelated user branches are never pattern cleanup targets.

## Consequences

A future release requires one explicit reviewed readiness merge and the one-time Release App repository configuration. After that semantic boundary, the normal path contains no undocumented manual branch creation, review request, workflow approval, dispatch, merge, environment approval, release or cleanup step.

The automation remains intentionally conservative: unresolved findings, source drift, native check failure, ruleset mismatch, credential drift, proof failure, publication failure, verification failure or cleanup ambiguity remain visible fail-closed states rather than being silently bypassed.
