# Release automation threat model

This document extends the canonical [`threat-model.md`](threat-model.md) for the repository release-control automation defined by ADR 0027. It does not change Linura runtime authority or the product threat boundary.

## Assets

- protected `main` history and repository ruleset integrity;
- reviewed readiness source, frozen release contract and reviewed source/tree identity;
- Trusted Release Proof and sealed build/provenance evidence;
- exact release tag and immutable GitHub Release assets/body;
- canonical PyPI `linura` distribution version, complete filename set, artifact SHA-256 and Trusted Publisher identity;
- canonical crates.io `linura` package version, package checksum and Trusted Publisher identity;
- independent GitHub Release, PyPI and crates.io verification evidence;
- terminal roadmap/publication bookkeeping and release-owned branch hygiene;
- the Linura Release GitHub App identity, installation permissions and private key;
- short-lived App installation tokens and job-scoped repository `GITHUB_TOKEN` dispatch/read authority.

## Adversaries and failures

- compromise or accidental disclosure of the Release App private key or a short-lived installation token;
- compromise of a job-scoped repository `GITHUB_TOKEN`;
- replay of an old readiness/preparation/authorization/closure workflow run;
- Candidate substitution and retry tampering on an already-open automation PR;
- stale-source races where `main` or a candidate ref advances between qualification and mutation;
- Event-recursion failure caused by relying on repository-token mutations to create native workflow events;
- native `pull_request` runs becoming `action_required` while unrelated dispatched copies pass;
- treating a successful `workflow_dispatch` run as equivalent to the native PR check expected by the strict ruleset;
- a merge racing an unresolved review thread or late candidate mutation;
- stale/wrong-ref/wrong-event/wrong-workflow check evidence;
- duplicate verification/closure/cleanup triggers racing the same terminal state;
- forged titles/comments intended to look like release authority;
- cleanup target refs moving between provenance validation and deletion;
- cleanup reading policy from mutable current `main` instead of the exact qualified closure commit;
- authentication, rate-limit, network or server errors being mistaken for absent cleanup refs;
- bot-to-bot conversational-review dependencies deadlocking mechanically proven handoffs;
- blanket branch-approval or deployment-environment reviewer policy silently reintroducing a human gate after reviewed readiness;
- ruleset bypass or over-broad GitHub App permissions;
- Rotation, revocation and permission drift during a release;
- a runner disappearing immediately after an irreversible protected merge;
- a later protected-main push cancelling exact-source CI evidence needed by a release handoff;
- a parallel PyPI or crates.io publication path bypassing the reviewed release lifecycle;
- PyPI Trusted Publisher identity being scoped only to workflow identity instead of the dedicated `pypi` environment;
- OIDC publication authority being available while repository-controlled build/test code executes;
- compromise or substitution of Python build-backend bytes despite version pins;
- a PyPI race where an immutable version appears after preflight but before upload;
- reuse of an existing PyPI version with extra, yanked or byte-mismatched distributions;
- partial publication where GitHub Release succeeds but PyPI publication or post-upload verification fails;
- stale-main publication after a correction lands while registry publication is queued;
- reuse of an existing immutable crates.io version whose checksum differs from the qualified package.

## Trust boundary

The **Linura Release GitHub App** is repository delivery infrastructure, not product/runtime authority and not autonomous publication authority. It is installed only on `linura-org/linura`, is not a protected-main bypass actor, and has only Actions write, Contents write and Pull requests write at installation level. Each workflow requests the narrowest short-lived subset needed by that phase.

The App private key is stored only as `LINURA_RELEASE_APP_PRIVATE_KEY` in GitHub repository secrets. `LINURA_RELEASE_APP_CLIENT_ID` is a non-secret repository variable. The private key is consumed only by the pinned token-minting action and is not exposed to shell steps, artifacts, evidence, model context or Linura state.

Machine preparation, authorization and closure mutations reach `main` only through the normal PR ruleset and GitHub-native PR checks. The App cannot bypass required checks. Tag/GitHub Release publication remains isolated in the Release workflow behind exact-source Trusted Release Proof, Promotion/closure-readiness and tag-last validation. The GitHub Release publication job itself has no GitHub Environment dependency.

PyPI is a separate registry trust boundary. Its Trusted Publisher identity is bound to repository `linura-org/linura`, workflow `release.yml` and GitHub Environment `pypi`. That environment is non-review-gated and stores no registry secret. Only the minimal upload job receives `id-token: write`; it has no repository checkout or repository script execution. Preflight and post-upload verification are separate no-OIDC jobs. The existing `crates-io` environment follows the same credential-isolation principle after terminal release verification.

Repository `GITHUB_TOKEN` remains appropriate for read-only qualification and supported workflow-to-workflow dispatches. It is not the identity used to create machine PRs or to authenticate to PyPI/crates.io.

## Mitigations

### Explicit semantic readiness

Automation begins only from a reviewed protected-main commit whose exact subject is `release: ready vX.Y.Z — <implementation theme>`. The source must match roadmap `next_release` and milestone title, include the required release/qualification/security/review documents, pass publication-stability validation, map to a merged protected PR with zero unresolved review threads, and pass native main gates.

This is the last semantic review boundary. Automation never invents or broadens product claims after it. Release Preparation changes only deterministic Cargo version metadata; Release Authorization is zero-diff; terminal closure is generated from immutable publication evidence.

The default-branch ruleset must therefore not impose a blanket approving-review requirement on these machine-only post-readiness handoffs. If future organizational policy requires enforced reviews elsewhere, the policy must distinguish the semantic boundary from constrained machine transports rather than granting the Release App a bypass. The normal publication path similarly carries no required deployment-environment reviewer.

### Candidate substitution and retry tampering

A machine PR is never trusted by branch name/title alone.

Preparation must be a one-parent child of the exact readiness source, change exactly `Cargo.toml` and `Cargo.lock`, and contain exact deterministic regenerated bytes. Authorization must have one exact preparation parent, identical tree, zero changed files and exact `release: v...` message plus `Reviewed-Source`/`Reviewed-Tree`. Closure must be a one-parent deterministic bookkeeping tree, preserve the frozen release contract and stay inside approved terminal surfaces.

New machine candidates use full-SHA-addressed branch names:

- `automation/release-prep-vX.Y.Z-<40hex>`;
- `automation/release-reprepare-vX.Y.Z-<40hex>`;
- `automation/release-authorization-vX.Y.Z-<40hex>`;
- `automation/post-release-vX.Y.Z-<40hex>`.

The embedded SHA is not sufficient authority for merge, but it provides a stable exact cleanup lease. Any reused candidate is re-proved before reuse and immediately before merge. A changed head invalidates previous structural and gate evidence.

### Native PR gate substitution attack

Native PR CI/Security/CodeQL are the protected-merge authority. `tools/release_native_gates.py` binds runs to exact `pull_request` event, PR number, branch and head SHA. It requires `success`, zero unresolved review threads, `mergeable=true` and clean GitHub ruleset state.

A native conclusion of `action_required`, failure or cancellation is blocking. Successful `workflow_dispatch` copies cannot substitute. This prevents a controller from declaring its own evidence green while GitHub still considers the required native contexts expected.

### Event-recursion failure

Repository `GITHUB_TOKEN` is deliberately not used to originate machine PR mutations. The Release App creates branches/PRs and protected merges, producing ordinary native `pull_request` and `push` events.

Irreversible merges are followed by event-driven observers instead of same-job fragile tails:

- preparation merge push starts authorization naturally;
- authorization merge push starts native main gates; `Release Proof Dispatch` observes their completion and idempotently dispatches proof;
- closure merge push starts native main gates; `Post Release Cleanup` observes their completion and performs terminal cleanup.

Workflow-to-workflow proof/promotion/release/verification/closure transitions use supported `workflow_dispatch` calls. The verification-to-crates.io transition deliberately uses the persisted terminal `workflow_run` event, so registry authority is never requested while the verifier is still running. If a runner dies after a successful merge or after terminal verification, the persisted GitHub event remains the durable next-stage authority.

The permanent CI workflow keeps stale-run cancellation for topic/PR refs but disables cancellation for `refs/heads/main`. A later main push therefore cannot erase the exact closure or authorization gate run needed by an already-started transition.

### Stale source and replay

Before each mutation, the controller rechecks exact protected-main source and candidate ref. Trusted Release Proof, Promotion and Release independently revalidate current source, frozen contract and tag conflicts. Replayed old runs cannot retarget a later source.

After terminal closure merge, cleanup has a deliberate immutable commit point: successful native CI/Security/CodeQL on the exact closure SHA authorizes cleanup policy from that commit. Cleanup fetches protected `main`, requires the closure SHA still to exist in ancestry, and reads `contracts/release-branch-cleanup.toml` from the exact closure object. Later main commits do not retarget the already-authorized transaction.

### Semantic review vs deterministic machine handoff

Conversational review is required where release semantics are authored, not where already-reviewed state is mechanically transported.

Preparation is constrained to deterministic two-file version metadata. Release Authorization is zero-diff and tree-identical to the prepared source. Post Release Closure is generated only after independent verification, preserves the frozen release contract byte-for-byte and is constrained to terminal bookkeeping.

All machine PRs still require native protected checks and zero unresolved review threads. Any actual human finding remains blocking. Eliminating mandatory bot-authored `@codex review` requests removes an authentication deadlock without weakening the semantic boundary.

### PyPI bootstrap namespace capture

The one-time `bootstrap-pypi` operation exists only to convert the Pending Trusted
Publisher into the initial `linura==0.0.1` project before the next full Linura
release. Its main threats are stale-main publication, silently broadening the
bootstrap into a product release path, build-dependency substitution, and obtaining
OIDC authority before artifact qualification.

Mitigations are deliberately redundant: exact supplied source must equal workflow
SHA, checkout HEAD and live protected main; native main push CI/Security/CodeQL must
already be successful; project identity/version/dependency and wheel-surface
constraints are hard checked; the hash-locked wheels-only Python toolchain is used
with disabled build isolation and a fixed wheel epoch; a separate runner must
reproduce the wheel byte-for-byte; PyPI preflight occurs without OIDC; and the
artifact is handed to the existing minimal `pypi` Environment job, which remains
the workflow's only `id-token: write` job and executes no repository scripts.
Fresh-download verification is again no-OIDC. Immediately before the OIDC
publisher action, the minimal publisher job uses an immutable-SHA-pinned GitHub API
action to require live protected `main` still equals the qualified bootstrap SHA;
source drift therefore fails before authentication/upload. Canonical-release
consumers bind `release.yml` runs to the explicit `Release — release @ <sha>`
display identity so a bootstrap run cannot satisfy or suppress canonical release
evidence. The bootstrap creates no Git tag, GitHub Release, crates.io handoff or
release closure, and is removed after the first verified namespace claim.

### PyPI publication identity, races and partial publication

Trusted Release Proof builds the Python wheel under exact Python, a wheels-only SHA-256 hash lock for pip and all PEP 517 build dependencies, disabled build isolation and a fixed wheel epoch. The lockfile digest and wheel-specific epoch are recorded in build evidence, and an independent runner must reproduce the wheel byte-for-byte before it can enter the sealed payload.

Release validation checks PyPI before irreversible GitHub publication. An existing Python version is accepted only when the complete remote filename set equals the sealed set, no file is yanked, advertised SHA-256 values match and fresh downloads match the sealed bytes. Absence permits the later registry handoff but does not itself grant credentials.

After GitHub Release publication, a no-OIDC preflight re-verifies the sealed wheel and persists only that wheel as the handoff artifact. The `pypi` environment job receives the only PyPI-capable OIDC authority and performs no repository-controlled computation before the pinned publish action. A race that creates the version after preflight causes the upload to fail rather than silently accepting unknown bytes. The following no-OIDC verifier then requires the live PyPI release to exactly match the sealed artifact. Verification dispatch is blocked until that succeeds.

Therefore a partial state in which GitHub Release is immutable but PyPI is missing or mismatched is explicitly non-terminal. Retrying re-proves the existing GitHub publication and PyPI state; it does not rebuild or broaden authority. crates.io publication and terminal closure cannot begin from that partial state.

### Credential compromise

A compromised short-lived App token can attempt repository writes/PR operations during its lifetime and can create noise or denial of service. It cannot alone satisfy exact parent/tree/message/path invariants, native protected rules, unresolved-thread policy, Trusted Release Proof, Promotion source/closure-readiness checks, tag-last publication, immutable asset verification or independent verification.

A compromised private key is more serious because new installation tokens could be minted until rotation/revocation. GitHub platform controls, secret access controls, audit logs and prompt rotation are therefore required. The App remains repository-scoped and has no ruleset bypass, limiting blast radius.

The release operator has no Linura runtime principal, policy, approval, executor, agent/model, Library or managed-mutation authority.

### Rotation, revocation and permission drift

Every machine mutation phase mints a fresh token and probes effective authority. The non-mutating probe requires:

- identical-main merge endpoint no-op `204` for Contents write;
- exact same-head PR validation for Pull requests write;
- exact missing-ref dispatch validation for Actions write.

Promotion repeats full closure-authority proof before immutable publication. Missing repository variable/secret, revoked installation, unapproved GitHub App permission changes, key rotation mistakes or reduced permissions stop release before publication.

There is no fallback to long-lived PAT, PyPI/crates.io API token, ruleset bypass, manual normal-path approval or `GITHUB_TOKEN` PR creation. PyPI publication uses the `pypi` GitHub Environment-bound Trusted Publisher and fails closed on identity, sealed-byte, complete-set, yanked-file or post-upload verification drift. crates.io publication uses its dedicated GitHub OIDC Trusted Publisher and fails closed on identity, source, tag or checksum drift.

### Verification and closure duplication

Normal Release explicitly dispatches verification from the exact immutable tag. Emergency verification is accepted only from the authenticated `verify-release/vX.Y.Z` recovery branch under marker-only/single-parent/workflow-definition constraints.

There is exactly one terminal handoff: sealed GitHub Release publication → exact PyPI handoff and no-OIDC registry verification → successful independent GitHub/PyPI Release verification persists bound evidence and completes → a terminal `workflow_run` authenticates the exact normal-tag or marker-only recovery verifier → crates.io qualification/publication/checksum verification → `Release Closure Handoff` → dispatch-only `Post Release Closure`. The crates.io qualification job has no OIDC permission; only its dependent publish job has `id-token: write`, and that job executes no crate build/test code before authentication. Existing crate versions are accepted only when their registry checksum matches the qualified package exactly and the version is not yanked. The crates.io workflow persists exact run/version/checksum/availability evidence; both closure handoff and final Post Release Closure authenticate that evidence, so manually dispatching a closure endpoint cannot bypass failed or absent registry publication. Closure is idempotent if terminal state is already present.

Cleanup is a separate transaction rather than an inline tail of closure merge. Multiple `workflow_run` wakeups are safe because branch absence is idempotent and every target deletion is exact-SHA leased.

### Cleanup TOCTOU and ownership

Terminal cleanup is ownership-scoped and fail-closed. Pattern selection is limited to full-SHA-addressed release-owned preparation/re-preparation/authorization/closure namespaces. `verify-release/vX.Y.Z`, generic `tmp/...`, `fix/...`, `release/...`, protected `main`, tags and unrelated user branches are not wildcard-selected.

Older or exceptional refs are eligible only when `contracts/release-branch-cleanup.toml` binds the exact release tag, complete branch name and reviewed 40-character SHA. A moved ledger ref is preserved.

Before deletion, open-PR use is checked and the current ref must exactly equal the embedded/ledger SHA. Deletion is then performed as an atomic Git `push --force-with-lease=<ref>:<expected-sha> :<ref>`. If a concurrent writer advances the ref after the check, the lease rejects deletion; the tool re-reads the ref and reports/preserves the moved branch. Exact 404 absence is idempotent. Authentication, network, rate-limit or server failures raise an error rather than masquerading as absence.

The exact release tag, protected main, frozen release contract, immutable Release body/assets and unrelated branches are outside cleanup authority.

### Ruleset bypass and policy drift

The Release App must not appear as a ruleset bypass actor. If repository policy grants bypass or broader publication authority than this model expects, the threat assumptions no longer hold and repository policy must be corrected.

Native required contexts remain GitHub Actions `canonical-check`, `dependency-audit` and `analyze`. Strict required-check policy remains enabled. The automatic-mode ruleset uses zero blanket required approvals after readiness so structurally constrained App-created PRs do not acquire a second human boundary.

## Residual risk

The Release App private key is a high-value repository automation secret. A compromised GitHub organization/repository administrator can change app installation permissions, secrets, workflows or rulesets; those platform-administration threats require GitHub account security, audit and organizational controls beyond Linura runtime authority.

GitHub itself remains part of the release trust base for ruleset evaluation, workflow event delivery, App token issuance, OIDC claims, Environment identity, immutable Release state and attestations. PyPI and crates.io remain part of the registry trust base for immutable version storage and registry metadata; Linura mitigates registry drift with exact preflight and independent fresh-download verification but cannot eliminate compromise of those external services.

No release-automation credential or GitHub event is accepted as evidence about Linux system state, user intent, policy approval, executor authority, agent authority, Library adoption or managed mutation.
