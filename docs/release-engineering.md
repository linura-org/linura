# Release engineering

Linura separates **what a version claims**, **which exact reviewed source is proven**, **which system qualifications that claim requires**, **how candidate bytes are constructed**, **how proof is promoted**, **when the immutable version tag is created**, **how publication is independently verified**, and **when terminal bookkeeping/cleanup may mutate repository state**.

See [Release contracts, claims and evidence](release-contracts.md), [Trusted release build boundary](release-build-trust.md), [ADR 0015](adr/0015-isolated-reproducible-release-build.md), [ADR 0023](adr/0023-build-once-promote-exact-bytes.md), [ADR 0027](adr/0027-protected-release-handoff-automation.md), and [Release automation threat model](threat-model-release-automation.md).

The control plane is repository-owned. It uses GitHub Actions plus a repository-scoped **Linura Release GitHub App** as the mutation identity for machine-created PRs. No external release orchestrator or branch-protection bypass is required.

## Repository automation identity

Machine-owned preparation, authorization and closure PRs must not be created by repository `GITHUB_TOKEN`. GitHub can place native `pull_request` workflows caused by `GITHUB_TOKEN` PR activity into `action_required`, which makes strict required checks remain “expected” even when separately dispatched copies pass. Linura therefore treats native GitHub PR events as the ruleset authority and uses a dedicated App installation token to create/push/merge machine PRs.

The repository must configure:

- variable `LINURA_RELEASE_APP_CLIENT_ID`;
- secret `LINURA_RELEASE_APP_PRIVATE_KEY`;
- App installation scoped only to `linura-org/linura`;
- App repository permissions: Actions write, Contents write, Pull requests write;
- no ruleset bypass actor;
- zero blanket required approving reviews on the default-branch ruleset while machine-only post-readiness PRs are in the automatic path;
- no required reviewer on the `release` environment in automatic mode.

The private key is consumed only by `actions/create-github-app-token`, pinned by immutable action SHA. Jobs request the narrowest installation-token permissions needed for that phase. Terminal cleanup requests Contents write plus Pull requests read, not the full mutation permission set.

Before mutation, the controller proves the token's required capabilities without changing repository state: an identical `main`/`main` merge must return GitHub's no-op `204`, an identical-base/head PR request must return exact same-head validation, and a workflow dispatch against an impossible all-zero ref must return exact missing-ref validation. Missing or ambiguous authority fails closed.

## Release documentation lifecycle and semantic boundary

Every planned version begins with a mutable `docs/milestones/vX.Y.Z.md`. Before release machinery starts, implementation closes into a frozen `docs/releases/vX.Y.Z.md` contract declaring claim class, supported/unsupported scope, authority/security boundaries, migration/recovery constraints, mandatory qualification and explicit non-goals. Qualification dossiers under `docs/qualification/` map implementation to those claims without inventing future evidence.

The final semantic/reviewed transition is a protected-main merge whose exact subject is:

```text
release: ready vX.Y.Z — <implementation theme>
```

That **readiness merge is the last semantic review boundary**. Human or Codex findings are resolved there. Everything after it is deterministic/mechanical and must be provable by source/tree/path/message invariants plus native protected GitHub checks. Machine-only PRs do not create a bot-to-bot conversational-review requirement, and publication must not add an environment-review approval after readiness.

The later release-intent source still has exact subject:

```text
release: vX.Y.Z — <implementation theme>
```

That commit does not itself create the version tag. It is the unpublished exact source that Trusted Release Proof is allowed to prove.

## Native protected checks are authoritative

The `main` ruleset requires GitHub Actions contexts `canonical-check`, `dependency-audit`, and `analyze` under strict up-to-date checking. For a protected PR, the controller waits for the **native `pull_request` executions** of CI, Security and CodeQL associated with the exact PR/head, requires each to conclude `success`, requires zero unresolved review threads, and requires GitHub to report the PR ruleset state as clean.

A native run ending `action_required` is a hard release-control failure. A separately successful `workflow_dispatch` run on the same SHA is not accepted as a substitute for the native PR gate. Dispatch runs remain useful for explicit qualification/recovery and exact-SHA evidence elsewhere, but they do not impersonate GitHub's PR merge-gate instances.

For event-driven transitions after a protected merge, the controller waits for exact native `push` CI/Security/CodeQL on the resulting protected-main SHA. The canonical CI workflow does not cancel in-progress `main` runs when later main commits appear, so exact-source transition evidence remains durable.

## Release Preparation

`Release Preparation` starts automatically when the exact reviewed readiness merge reaches `main`.

It:

1. binds the exact readiness source and reviewed readiness PR;
2. requires native exact-main push CI/Security/CodeQL;
3. deterministically runs `tools/prepare_release.py`;
4. allows changes only to `Cargo.toml` and `Cargo.lock`;
5. creates/reuses a single-parent `automation/release-prep-vX.Y.Z-<full-candidate-sha>` candidate with the Release App;
6. opens `release: prepare vX.Y.Z <implementation theme>` using the Release App;
7. waits for native PR CI/Security/CodeQL, zero unresolved review threads and clean ruleset state;
8. immediately before mutation re-proves exact base/head/branch/parent/path/byte identity;
9. squash-merges through the normal protected-main ruleset.

The full candidate SHA embedded in the branch name is part of terminal cleanup authority. A branch whose current tip differs from the embedded SHA is not a valid automatic cleanup target. Retries may reuse only an exact open candidate; an orphaned exact-SHA branch may remain until terminal cleanup.

Because the merge is App-authenticated, GitHub emits the normal protected-main `push` event. `Release Authorization` therefore starts naturally; no explicit recursion workaround or manual dispatch is needed.

## Release Authorization

`Release Authorization` binds the exact prepared source and creates a single-parent tree-identical authorization candidate. The candidate branch is:

```text
automation/release-authorization-vX.Y.Z-<full-candidate-sha>
```

The candidate has zero changed files and exact message/trailers:

```text
release: vX.Y.Z — <implementation theme>

...
Reviewed-Source: <40-hex preparation SHA>
Reviewed-Tree: <40-hex reviewed tree SHA>
```

The Release App opens the zero-diff protected authorization PR. The controller requires native PR CI/Security/CodeQL, zero unresolved threads and clean ruleset state. Immediately before merge it re-proves native gates, protected-main source, branch head, one exact parent, identical tree and exact message/trailers. It then squash-merges normally and verifies the resulting protected-main commit. It never PATCHes `main` and never bypasses the ruleset.

## Durable post-merge proof handoff

The authorization merge is an irreversible transaction boundary, so the same job does not own a fragile “merge then dispatch proof” tail. Native main push CI/Security/CodeQL run independently. `.github/workflows/release-proof-dispatch.yml` observes their `workflow_run` completions, binds the exact `release: v...` main SHA, waits until all three push gates have succeeded, rejects source/tag drift, and idempotently dispatches Trusted Release Proof.

If an Actions runner disappears immediately after the authorization merge, GitHub's persisted merge/push/check events still own the next transition. This is the release controller's durable handoff principle.

## Trusted Release Proof

Trusted Release Proof is `workflow_dispatch`-only and read-only with respect to repository contents. It requires `github.sha`, checkout `HEAD` and `origin/main` to equal the exact release-intent SHA; validates the frozen release contract; and re-verifies permanent exact-SHA CI/Security/CodeQL evidence.

It then executes the mandatory claim/version-scoped qualification graph before construction. Only after qualification succeeds may the reusable trusted builder construct the release once with locked dependencies. The proof payload contains canonical source/tag/notes/build environment/SBOM/release evidence/checksums/proof receipt and build provenance. A fresh runner reproduces distributable binary bytes. Promotion and publication consume those sealed bytes; they do not rebuild.

Any SHA change invalidates exact-source evidence. History cleanup/rebase/amend therefore occurs before final release gates.

## Release Promotion and pre-publication closure readiness

Promotion validates the exact successful Trusted Release Proof, source SHA, version, frozen contract and current-main identity. It cannot tag or publish.

Before Promotion can dispatch Release, an isolated `closure-readiness` job mints a fresh Release App installation token and non-mutatingly proves Actions/Contents/Pull-request authority. This verifies that the future terminal closure is automatable **before** an immutable tag or Release can exist.

If App configuration is missing, its installation permissions were not approved, the private key was rotated incorrectly, or permission drift occurred, Promotion fails closed before publication. The final Release-dispatch job returns to narrow repository `GITHUB_TOKEN` permissions (`actions: write`, `contents: read`) and never inherits the App private key or token.

## Release validation and tag-last publication

Release validation requires the exact promoted current-main source, exact successful proof run, frozen contract, permanent exact-SHA gates, sealed proof payload, checksums and provenance. Success is the release source-selection commit point.

Only the final `publish` job receives `contents: write`, behind the `release` GitHub Environment. In automatic mode that environment is an isolation/protection boundary, **not a reviewer gate**; required reviewers must be disabled. It:

1. rechecks exact selected source;
2. redownloads and reverifies the sealed proof;
3. creates `refs/tags/vX.Y.Z` only after proof succeeds, or proves an existing tag already points to the same source;
4. creates/resumes the GitHub Release with title `Linura vX.Y.Z` and the exact sealed `RELEASE_NOTES.md` body;
5. reconciles the asset set to the sealed proof payload and verifies every digest;
6. publishes only after the remote set is exact.

The immutable tag is an output of successful proof, never the trigger that grants proof authority.

## Independent publication verification

Release explicitly dispatches verification from the exact immutable tag. The verifier downloads published assets afresh and verifies tag/source binding, evidence, checksums, canonical Release body, immutable Release state, per-asset release verification and build provenance. Downloaded files are treated as content blobs; executable mode is not a portable publication-integrity property.

Normal verification runs from the exact tag. `verify-release/vX.Y.Z` is an authenticated emergency recovery namespace only for an already-immutable release whose frozen verifier is defective; it is not part of the normal path and is not wildcard-selected for cleanup.

Publication is not terminal until independent verification succeeds.

## Post-release closure

A successful verifier dispatches `Release Closure Handoff`, which waits for exact verification terminal success, binds tag/source/event/ref identity, and dispatches `Post Release Closure`.

On pending state, Post Release Closure:

1. verifies immutable publication and exact successful proof/promotion/release/verification runs;
2. deterministically synchronizes roadmap/current-next state, terminal qualification/publication evidence and documentation indexes;
3. preserves frozen `docs/releases/vX.Y.Z.md` bytes;
4. creates/reuses a single-parent `automation/post-release-vX.Y.Z-<full-candidate-sha>` closure commit using the Release App;
5. opens/reuses the exact protected closure PR;
6. waits for native PR CI/Security/CodeQL, zero unresolved review threads and clean ruleset state;
7. immediately before merge re-proves native gates, base/head/branch/parent/message/tree identity;
8. squash-merges through the normal `main` ruleset.

Closure is a deterministic machine handoff, not a second semantic-review phase. An already-closed release is idempotent: state is verified without generating a duplicate mutation.

The closure workflow deliberately stops after its protected merge. Cleanup is not an inline tail of the irreversible merge transaction.

## Event-driven terminal cleanup

`.github/workflows/post-release-cleanup.yml` observes native CI/Security/CodeQL completions for protected-main `chore: close vX.Y.Z release state` commits. It waits for all three exact closure-source push gates to succeed and then establishes the immutable closure SHA as the cleanup authorization commit point.

The cleanup transaction fetches current protected `main`, requires the qualified closure SHA still to exist in its ancestry, and reads `contracts/release-branch-cleanup.toml` from that exact commit. Later development may advance `main`; it cannot retroactively change this transaction's cleanup policy.

Normal automatic cleanup selects only SHA-addressed release-owned refs matching these shapes:

- `automation/release-prep-vX.Y.Z-<40hex>`;
- `automation/release-reprepare-vX.Y.Z-<40hex>`;
- `automation/release-authorization-vX.Y.Z-<40hex>`;
- `automation/post-release-vX.Y.Z-<40hex>`.

Older or exceptional refs are eligible only from an exact release + branch name + reviewed 40-hex SHA ledger entry. Branches referenced by open PRs are preserved. Each candidate must still point to its embedded/ledger SHA. Deletion is performed atomically with Git `--force-with-lease=<ref>:<expected-sha>`; a concurrent move therefore cannot be deleted by a stale check. Exact absence is idempotent, while authentication/network/server/ambiguous lookup failures fail closed.

Cleanup uses a narrower Release App token (`Contents: write`, `Pull requests: read`) and never targets protected main, immutable tags, frozen contracts or published assets.

## Timeout and retry model

A short-lived App installation token bounds machine-PR mutation jobs. Their timeouts are intentionally below the token lifetime and their gate waits have explicit bounds. More importantly, irreversible boundaries are separated by persisted GitHub events:

```text
readiness merge
  → native main gates
  → preparation PR + merge
  → native main gates / authorization trigger
  → authorization PR + merge
  → native main gates / proof-dispatch observer
  → proof → promotion → Release
  → verification → closure handoff
  → closure PR + merge
  → native closure-main gates / cleanup observer
  → atomic leased cleanup
```

A retry re-proves current state and reuses exact artifacts when safe. It does not assume where a previous attempt stopped.

## Traceability and claim-scoped qualification

PR links are default human change provenance. Full 40-character commit URLs are used when immutable provenance materially improves security, migration, recovery or release-control review. Provenance references are not acceptance evidence; exact-source tests remain authoritative.

A release must not claim stronger platform support than its version contract. Experimental milestones prove their bounded authority/security/recovery behavior without manufacturing unsupported platform evidence. Future supported platform/profile/hardware claims additionally require corresponding VM/profile/hardware/upgrade/recovery evidence. The generic release-readiness checklist supplements the version-specific frozen contract; it never replaces it.
