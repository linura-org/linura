# Applicable qualification gates

Linura's pull-request qualification policy is owned by
`contracts/qualification-gate-matrix.toml`. The matrix is exhaustive for the
current execution-envelope lane inventory, repository components, top-level
TOML contracts, and every public contract registered by `contracts/stability.toml`,
including registered JSON schemas.

GitHub's current Actions path-filter diff limit is **3,000 changed files**
(previously 300); the GitHub PR-files endpoint is likewise capped at 3,000
entries. For PRs with **more than 3,000** changed files, this validator
publishes an explicit **failure** requiring the PR to be split, rather than
selecting gates from an incomplete path inventory or waiting for a workflow
that GitHub did not trigger. A PR containing exactly 3,000 files is read
through all 30 API pages; other paginated API endpoints fail closed when
completeness cannot be established.

Every native or specialized PR workflow must retain its protected
`run-name` expression derived from the original GitHub PR number and
`github.sha` event value.
For `pull_request`, GitHub records the synthetic test-merge SHA in the
workflow run's persisted PR-number and merge-SHA display title. The verifier independently fetches
that commit and requires its ordered parents to equal the **current**
protected-main base and contributor head. GitHub's mutable
`workflow_run.pull_requests[*].base` association is never accepted as
historical base proof; missing or stale merge-SHA titles deny qualification.
The native workflows keep their dispatch-nonce support for release tooling,
but only the literal event `github.sha` qualifies for PR-native admission.

The three native PR gates always apply:

- `canonical-check` from CI;
- `dependency-audit` from Security, using fresh RustSec data;
- `analyze` from CodeQL.

Specialized gates are selected from the exact ordered path rules recorded in the
matrix. Repository validation requires those rules to equal the corresponding
GitHub workflow `pull_request.paths` rules. Where specialized qualification
also runs on protected `main` pushes, static validation additionally requires
the full ordered `push.paths` list to match its PR routing (including release
evidence and Codex environment inputs). The matrix therefore describes the
same executable routing rather than maintaining a second approximate map.

Use:

```bash
python3 tools/applicable_qualification.py validate
python3 tools/applicable_qualification.py plan --paths-file /tmp/changed-paths.txt
```

The read-only `decision-head` evaluator validates the policy once per
batch and reuses one freshly queried workflow-run snapshot per head. PR-file
and attempt-specific job inventories are shared only inside each decision
round; the positive second pass always starts new API snapshots.
A candidate success is re-evaluated against a second independent run
snapshot and newly fetched PR identities; it does not reuse earlier-source
or earlier-base successes. The App additionally enforces a hard 120-second
subprocess limit and an internal 115-second read budget, reserving five
seconds for cleanup. Excessively slow GitHub API responses deny approval,
never grant an unverified check.

GitHub PR metadata must provide a non-negative integer `changed_files` count,
and the complete PR-files inventory must contain exactly that many unique
paths. Missing or inconsistent counts deny qualification, including a purported
zero-diff PR. This prevents API truncation or pagination drift from silently
downgrading specialized coverage.

The validator fails if an execution lane, component, top-level TOML contract, or
stability-registered contract is not classified; if a native-only declaration
unexpectedly acquires a specialized route; if a workflow route differs from the
matrix; if a routing authority file starts triggering a specialized gate; or if a
shared execution substrate is not routed to every lane that consumes it.

## Trusted workflow execution and safe path changes

A successful GitHub Actions run does not by itself prove that it executed the
reviewed test implementation: `pull_request` can execute workflow YAML from
the PR merge ref. The trusted, default-branch reconciler rejects changes to registered
gate workflows, local GitHub actions, and the **transitive first-party script
and Python-import closure** of reviewed gate executables (including the CI
cache-policy checker and Rust `xtask` implementation). This closure includes
Python `unittest` targets invoked by dotted module names and modules imported
by those tests; both discovered tooling tests and Python bindings test sources
are protected even if a changed module is newly added to the PR. This prevents
a PR from replacing a qualification suite with an empty, falsely green one.
**Every file in `qualification/` and `tests/acceptance/` is also executable qualification authority,**
including QEMU/Hyprland/Quickshell harness programs, hardware-capture scripts
and test fixtures. Locally called reusable workflows are read as part of the
protected-base dependency inventory. These subtrees are protected so renamed/new runners, JSON acceptance
scenarios, systemd units, udev rules and fixtures cannot escape through a
missing historical filename. Root-level Python modules and package initializers, modules under
`tools/` and `scripts/`, implicit package initializers, native extension
modules (`.so`/`.pyd`), sourceless bytecode (`.pyc`), and Python startup
hooks in qualification search paths are likewise protected even when newly
added: a protected-base import graph cannot discover code that did not exist
at review time. A green PR-authored job name is never an independent gate proof.

An executable-authority upgrade requires **a separate ledger-only PR**, merged
through the protected-main ruleset before the code-changing PR can qualify.
The trusted reconciler binds the **entire code PR diff** (changed path, status,
destination blob SHA, rename source, and the **previous Git tree entry** at
every changed path and the original source of renamed/copied files), together with the **code PR
number**, to the SHA-256 digest recorded in the reviewed protected-main
ledger. The digest deliberately does **not** bind the contributor head SHA:
the separately approved ledger PR advances protected main, and strict
up-to-date protection requires refreshing the code PR head. Binding the head
would require yet another ledger PR after every refresh, deadlocking approval. The digest uses a versioned v2 payload and
resolves the live PR base's immutable commit SHA to its distinct Git tree SHA,
then reads and verifies the complete, non-truncated tree. Missing, contradictory,
ambiguous, or truncated base-tree
evidence denies admission. A prior A→B approval cannot be replayed after
main fixes A to C merely because a different PR produces the same B blob.
The base commit SHA itself is not included in the digest: merging the
required separate ledger-only approval PR advances main, and unrelated base
updates with identical old file identities must not invalidate that exact
review. A changed prior blob/mode or amended whole-PR diff requires a new protected-ledger
approval; a refreshed contributor head with the exact same reviewed diff
does not. Native qualification independently requires the final exact head. Approval PRs must change only
that ledger and must not edit gate workflows or helper scripts. The reconciler
checks the approval PR's merge status, exact reviewed ledger snapshot and
provenance.

There are two explicit modes:

- `approval_mode = "independent-review"`: an approving repository collaborator
  must be different from **both** the ledger PR author **and** the executable
  code PR author. An old or dismissed review is not accepted.
- `approval_mode = "solo-operator"`: for the single-maintainer repository,
  the configured `solo_operator` account must author both the code and
  separate ledger PRs. **No independent human review is claimed.** Instead,
  the ledger PR must have all three original native checks independently
  executed and proven successful against its own exact PR head and base.
  The candidate code PR must independently satisfy its applicable gates;
  it cannot certify itself merely by returning successful job names.
  Manual adversarial review findings and risk acceptance belong in the
  approval rationale and PR discussion, with immutable SHA traceability.

Both modes retain required `canonical-check`, `dependency-audit`, and
`analyze`, GitHub's strict up-to-date base policy, and the distinct merge
boundary. An account without access to protected `main` cannot add its own
approval in the candidate PR. Never disable native gates, use dispatched
results as native evidence, or treat solo authorization as a second person's
review. The trusted executable authority additionally includes Cargo's
`.cargo/` configuration, root `Cargo.toml` and `Cargo.lock`, Rust toolchain, and the actual
`tools/xtask/` crate, preventing a changed alias or workspace from turning
`cargo xtask check` into a no-op.

```bash
GITHUB_TOKEN=... python3 tools/applicable_qualification.py authority-bundle \
  --repository linura-org/linura --pr-number <proposed-code-pr>
```

The protected-main ledger is a maintainer-controlled authorization decision,
not a substitute for adversarial independent validation and review of the
proposed source. Do not turn off branch checks or substitute
`workflow_dispatch` for required native PR checks.

GitHub path filters evaluate renamed files at their new destination. For
safety, the validator also independently classifies the removed *source* path.
If a rename requires a specialized gate that GitHub's destination-only
filter did not trigger, the PR is explicitly failed with instructions to
split its source deletion and destination addition for full qualification.
A meaningful code removal must never masquerade as a guidance-only change.

## Protected status-publisher identity: activation prerequisite

**Do not add `applicable-qualification` to the active `main` ruleset
while GitHub Actions' `GITHUB_TOKEN` is its status publisher.** A
same-repository PR can add a workflow requesting `statuses: write` and
forge the identical context using the same GitHub Actions integration.
Even a perfect default-branch evaluator cannot distinguish that forged
success at branch protection when the publisher identity is shared.

PR #208 provides the disabled-by-default independent **GitHub App Check Run
publisher** outside all PR-accessible workflow execution and secrets.
It must be deployed separately, with its credentials isolated from Actions.
Its private key must not be stored in repository/organization Actions
secrets accessible to contributor workflows. The App must independently
verify current PR/head/base and gate results against protected policy;
it must never accept a PR-authored success receipt or a GitHub Actions
status as its authority. Configure the ruleset-required
`linura/applicable-qualification` Check Run with the **specific dedicated App
integration ID**, not `Any source` or GitHub Actions. Prove that a
same-repository malicious `statuses: write` job cannot satisfy the
required check, and test key rotation, outage/reconciliation, revocation,
base updates and rollback before enabling enforcement.

The Actions-based status writer in this PR is **diagnostic infrastructure
only** until that independent publisher and ruleset are established.
Neither green existing GitHub Actions checks nor this PR alone completes
the required-summary acceptance criterion of issue #196. Keep the
existing three native required gates and strict updated-base policy
intact. This is a hard deployment blocker, not a waiver to be signed by
the code-changing PR or an automatically resolvable review comment.

## Exact-head reconciliation

`.github/workflows/applicable-qualification.yml` is event-driven rather than
a long-lived polling job. A read-only event-discovery job identifies the
affected contributor heads for `pull_request_target` (including `closed`),
native `workflow_run` events and **pushes to protected `main`**. All jobs
check out **only reviewed default-branch code**, never PR-head scripts.
No privileged workflow runs on arbitrary feature-branch pushes. On a `main`
base update, the discovery job enumerates open PRs targeting `main` and
emits their unique head SHAs; a PR closure similarly causes the remaining
open PRs sharing that head to be reevaluated. A PR `synchronize` event
schedules both the new SHA and GitHub's validated previous `before` SHA,
so PRs still using the old SHA do not retain obsolete aggregate status.
Malformed/missing synchronization identities are rejected rather than
silently dropping old-head reconciliation.

Head discovery groups arbitrary-sized sets of open PR heads into at most
**16 deterministic writer shards** by their leading SHA hex digit, avoiding
GitHub's 256-job matrix ceiling. Each shard has one shared concurrency group
across **all** event kinds and runs without in-progress cancellation.
The writer sets `concurrency.queue: max` to retain up to 100 pending events.
The pinned actionlint version predates this supported GitHub syntax; the
canonical and Codex preflight checks share `scripts/lint_github_workflows.sh`:
it first validates the actual workflow's required queue setting, then passes a
projection omitting only that independently checked key to actionlint while
fully linting all other workflow files. Dropped
events above GitHub's queue capacity remain a liveness risk, not an
authorization success. A shard
writer first attempts to publish `pending` for **every event-affected head
in that shard**, then performs **at most one expensive full reconciliation**
per shard job, bounding its GitHub REST requests and runtime. Other heads stay
pending, never receiving an inferred pass. A workflow-run `in_progress`
event performs invalidation only; the completion event can fully reconcile.
A trusted scheduled event runs at 17 minutes past each hour and rotates over
open PR heads. Scheduled retries invalidate **only the selected head**, rather
than revoking the successes of all previously requalified heads. This drains
stable backlogs across GitHub token quota windows while preserving the single
writer per SHA prefix. A transient error still fails that job, leaving
published pending status intact and eligible for hourly retry. No check is
weakened or bypassed; a large base update may leave affected PRs temporarily
pending while the bounded queue drains. The discovery job remains
read-only; only the serialized shard writer receives `statuses: write`.
The PR inventory is paginated past 3,000 heads without silently truncating.
Status publication retries transient GitHub errors up to three times with
bounded delays, but a depleted token or GitHub outage cannot be assumed to
revoke an existing commit status. GitHub commit statuses do not offer an
atomic compare-and-swap. Native merge gates and strict up-to-date-branch
protection must remain independently required. Before enabling the **App-owned** required Check Run on `main`, verify
operational alerting for long-pending decisions,
API-write failures and missed schedules; periodic schedules can be delayed or
dropped and are **not a guaranteed delivery queue**.

GitHub native PR checks are normally attached to the contributor **head SHA**.
The Actions summary publishes its **diagnostic-only** `applicable-qualification`
status to that SHA. It never satisfies the separately required App-owned
`linura/applicable-qualification` Check Run, which #208 publishes only on a
freshly verified PR-specific synthetic test-merge SHA.
Two open PRs can share one head SHA, so the reconciler enumerates **all**
currently open PRs associated with that commit, computes the applicable
qualifications separately, and publishes one shared status. A head shared
by more than eight open PRs receives an explicit fail-closed status instead
of performing unbounded REST work; these PRs must be separated. It succeeds only
when **every** associated PR qualifies. One failed PR fails the shared status;
one still-running/absent gate keeps it pending. The reconciler publishes
`pending` **before** any fallible lookup of associated PRs or their metadata.
If a newly opened shared-head PR temporarily lacks a merge SHA, reconciliation
cannot leave the head's earlier success usable; the pending status remains
until a later event can revalidate all associated PRs.
A tree-identical release-authorization PR legitimately has an empty GitHub
changed-files inventory: this selects all three native mandatory gates and no
path-routed specialized gates. The empty list is **not** missing evidence;
API errors or malformed file entries still fail closed.

The trust-boundary validator accepts native `pull_request` workflow runs only
when their associated PR **number, exact head SHA, base branch ref, base commit
SHA, and base repository ID** match GitHub's current PR. A historical run on
a different base cannot be reused following PR retargeting or a base update.
The protected-base push trigger explicitly refreshes the shared status even
when GitHub emits no `synchronize` event for the unchanged contributor head.
**It cannot manufacture new native PR checks.** GitHub does not generate
`pull_request` runs when the target branch advances alone. Re-running a
historical check (or substituting `workflow_dispatch`) cannot authorize
the new base identity. If a required gate has attributable earlier-base
native runs but no current-base run, the reconciler publishes an explicit
**failure** with a branch-refresh instruction rather than an ambiguous,
unbounded `pending`. The contributor or maintainer must update the PR
branch against current `main` (preferably by rebase for a clean history)
or close/reopen the PR to cause a fresh native `pull_request` event.
Once new exact-head/current-base native runs complete, the normal event
reconciliation can restore success. This matches the repository's
`strict_required_status_checks_policy` and does not grant the trusted
status writer source-branch mutation privileges.
An empty `workflow_run.pull_requests` array can still trigger discovery
through the commit-to-PR API, but the run itself is never accepted as
qualification without independently verifiable base identity. This deliberately
fails closed for fork runs lacking sufficient GitHub association metadata.

Immediately before publishing any aggregate success, the reconciler
reevaluates all required runs and rechecks the complete set of open PRs and
their head/base/merge identities. Concurrent gate reruns therefore cause
pending instead of authorizing a stale earlier pass. As GitHub statuses and
events have no atomic compare-and-swap, this is an event-driven consistency
boundary, not a claim of transactional merge authorization: strict required
native checks and repository branch protection remain independent.

For each PR, the gate matrix resolves native and specialized workflows from
the current GitHub changed-file `filename` values. For renames, that is the
new destination path; `previous_filename` is informational and **not** used to
select a workflow GitHub never triggered. Deleted-file `filename` values
remain eligible for path matching. A
run is accepted only when it has the reviewed workflow path (with an optional
valid `@ref` suffix), event `pull_request`, exact current head and base
identity, newest run attempt, conclusion `success`, and all required job
identities successful. An in-progress rerun supersedes older success. A
workflow-dispatch run, wrong-base run, skipped job, cancelled run, or absent
evidence cannot satisfy qualification.

v0.9 additionally derives `full` versus `regression` from
`contracts/v09-qualification-routing.toml`, checking the corresponding
nested required jobs. Unlike GitHub workflow *applicability*, its mode must
match the workflow's `git diff --no-renames` classification: for a rename,
both the previous and destination paths are included. Moving an update or
recovery implementation file into a regression-only destination therefore
**still requires full v0.9 qualification**; a missing rename source fails
closed rather than silently downgrading coverage. Routing-authority edits are statically verified by
canonical CI rather than fanning out to every specialized lane. Execution
substrate changes still trigger the dependent VM/visual gates.

After this workflow is merged, test the protected read-only `decision-head`
interface with the separately deployed App from PR #208; validate real merge-ref
identity, App-source pinning, journal revocation, failure recovery and stale
success during API outages. **Only then** add `linura/applicable-qualification`
as a required App-owned Check Run alongside the three original native gates.
Path-filtered specialized workflows must not be globally required. A base
advance without fresh PR-native gates is an actionable failure rather than
reusing earlier-base evidence. Issue #196 remains open until real ruleset
acceptance; the Actions diagnostic status is never qualifying authority.

## Boundary

This layer answers only "which PR gates were applicable and did the exact-head
native runs succeed?" It does not accept qualification evidence, mint execution
envelopes, authorize a release, publish evidence, or fabricate maintained
hardware qualification. Those authorities remain in their existing layers.
