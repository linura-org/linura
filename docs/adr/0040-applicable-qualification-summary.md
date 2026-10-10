# ADR 0040: Centralize PR qualification routing and exact-head gate admission

**Status:** Accepted

## Context

Linura already has three unfiltered native merge gates, specialized path-routed
qualification workflows, immutable execution envelopes, and independent
qualification-evidence admission. Those layers still leave one authority gap:
no single reviewed contract says which specialized gates are applicable to a
particular pull request, and no unfiltered required check proves that every
applicable gate completed successfully for the exact pull-request head.

Duplicated path lists are also an anti-drift risk. A new component, contract, or
qualification lane can otherwise become active without being represented in a
complete component-to-gate inventory.

## Additional qualification-authority constraints

The default-branch reconciler does not accept green job-name metadata for
a PR editing registered gate workflows, local actions, local reusable workflows,
any qualification harness/fixture under `qualification/`, or direct/transitive
first-party executable dependencies of canonical gate orchestration. The
protected-main source graph, including Rust xtask, determines trust-sensitive
paths. Exact whole-PR bundles bind the code PR number, changed path/status/destination
blobs, and each changed or renamed/copied
source's immutable previous Git tree identity (blob, mode and type). They do not bind
the entire base commit SHA or contributor head SHA because the mandatory
separate ledger-only approval merge advances main and strict updated-base
protection then changes the code head; binding either would cause repeated
reapproval. Any changed *prior file identity* or changed whole-PR diff
nevertheless invalidates an old approval. A missing/truncated prior Git tree denies.
Bundles can be admitted only via a separate, merged ledger-only PR to
protected main, **before** the executable code PR qualifies. Two authorization modes are explicit: independent human review
(excluding both the code and ledger authors), or a solo-maintainer operator
decision authenticated to the protected-main configured operator account
and conditioned on independent exact-head/base proof of all three original
native checks on the ledger PR. The latter does **not** claim independent
human review. Approval data from the code PR is ignored, and its own
successful job names cannot replace the protected-main decision. Cargo's
workspace manifest, alias configuration and `tools/xtask/` entrypoint
are treated as executable qualification-authority inputs. Source-path
deletions hidden by renaming to an unscoped destination also fail closed
because GitHub would not start the historical source's specialized gate.

Writers use GitHub's maximum pending concurrency queue with no in-progress
cancellation. This queue is bounded (100), not durable; hourly inventory
recovery remains best effort and must be monitored. Per-head shared PR
evaluation is limited to eight PRs, and transient status writes are retried
without treating failed API calls as successful invalidation. GitHub does not
provide atomic status compare-and-swap, so native merge gates and strict
up-to-date-branch protection must remain independent and operational.

## Security gate on branch-protection activation

The native `GITHUB_TOKEN` used by the diagnostic reconciler cannot
exclusively own the `applicable-qualification` status context: another
same-repository PR workflow can request `statuses: write` and publish the
same context. Therefore **the summary must not become a required check
from GitHub Actions**. A separately operated GitHub App must independently
evaluate/verify exact-head qualification and publish using a dedicated
installation identity unavailable to PR-controlled workflows, with the
ruleset pinned to that App's integration ID. This is an unmet external
deployment prerequisite of #196; no security exception or relaxation of
existing required gates is authorized. A GitHub Actions success for this
context is not evidence of the final trusted publishing model.

## Decision

Adopt `contracts/qualification-gate-matrix.toml` as the canonical reviewed
pull-request routing inventory. It classifies every execution-envelope lane,
every component, every top-level machine-readable contract, every public
contract registered by `contracts/stability.toml`, the three mandatory native
gates, specialized PR gates, release workflows, and the maintained physical
lane.

Specialized workflow path filters remain executable GitHub routing, but the
matrix stores their exact ordered rules and repository validation requires them
to match, including both PR and protected-main push lists where present. An explicitly tree-identical release-authorization PR has no
changed paths, so it requires exactly the three mandatory native gates;
API failures and malformed path inventories remain errors. The Actions
path-filter diff and PR-files API both cover at most 3,000 files in the
current GitHub documentation (raised from 300 in July 2026). PRs exceeding
that bound are explicitly denied as too large to qualify reliably, rather
than leaving an inapplicable filtered workflow pending forever. The v0.9 mode decision separately follows the real no-renames Git diff:
source and destination names of renamed files must both be classified for
the `full` versus `regression` nested-job selection, even though ordinary
workflow applicability matches only the destination path.

The matrix, its verifier, its adversarial tests, and the summary
workflow are routing-authority inputs: canonical static validation must cover
them, while those files alone must not fan out to every specialized PR gate.
Shared execution/evidence substrates still trigger every lane that consumes
them.

Add one unfiltered `Applicable qualification` pull-request workflow. Its
`applicable-qualification` job derives required gates from exact changed paths,
using the GitHub changed-file `filename` (destination path for renames),
then queries GitHub's workflow-run metadata. A renamed-away old path must not
require a specialized check that GitHub's `pull_request.paths` cannot trigger.
A gate counts only when its stored event-derived merge SHA identifies an
immutable GitHub commit whose two parents match the live PR base and head.
The workflow's protected run-name contract binds both its original PR
number and synthetic-merge SHA; a mutable
`workflow_run.pull_requests` association identifies the PR but never proves
the historical base. Old-base runs remain invalid even if GitHub updates
that association to describe the current base. The protected run-name must
not be removed or changed without the separate authority-approval process.
The read-only App verifier caches only per-round PR-file and attempt-specific
job inventories; positive decisions fetch independent second-round snapshots.
The 115-second API deadline and 120-second App subprocess bound fail closed.
A gate counts only when the newest matching run belongs to the same PR, exact
head SHA and base identity, exact workflow path, and `pull_request` event and concludes
`success`. Missing, pending, skipped, cancelled, failed, timed-out, stale, or
workflow-dispatch runs cannot satisfy the summary. Every applicable workflow
also binds reviewed job names. For v0.9, the summary invokes the same path-impact
classifier used by the workflow and requires the full VM/adversarial job group
or the bounded regression job group accordingly; an overall successful workflow
with a skipped expected job is not sufficient.

The Actions summary publishes a diagnostic-only `applicable-qualification`
status on the contributor head, alongside the native required checks. This
status is forgeable by same-repository PR workflows and **is not the required
qualification authority**. The independent App merged in ADR 0039 consumes
the read-only `decision-head` receipt and is the only intended publisher of
the `linura/applicable-qualification` Check Run, on a verified PR-specific
test-merge SHA after real-App acceptance. GitHub's synthetic test-merge
commit can lack those check contexts, so publishing only on that commit can
block all required gates. Multiple PRs can share a contributor head: the
reviewed default-branch reconciler consequently inventories *every* open PR
associated with that head, and publishes success only if all of them qualify.
One failing or pending PR blocks the shared status.

Native workflow-run evidence is bound to the current PR number, head SHA, and
base branch ref, base commit SHA and base repository ID; older-base runs are
never promoted to current qualification. If the run lacks a verifiable PR/base
association it is not accepted. A read-only discovery job handles
`pull_request_target` (including `closed`), PR `workflow_run` start/completion,
and protected `main` pushes. A base update enumerates open PRs targeting the
updated `main` and schedules each unique contributor head for reconciliation,
even when the PR head has not changed. This invalidates previously authorized
checks but **does not trigger** replacement native PR workflow runs: GitHub
has no base-advance `pull_request` event. The reconciler explicitly fails
an attributable stale-base-only gate with an update/reopen-PR remediation,
never reinterpreting older-base results, dispatch runs, or main-push checks
as qualification of the current base. An operator must trigger a real new
native PR event (such as updating/reopening the PR), after which exact-base
native check admission proceeds. The protected reconciler deliberately has
no permission to rewrite contributor branches or mutate PRs. A closed PR causes reevaluation of the
remaining open PRs sharing its head. When a PR synchronizes to a different
head commit, the event's verified `before` and `after` SHA identities each
enter reconciliation: old-head PRs are not left stranded behind stale statuses. Untrusted feature-branch pushes cannot
run the privileged status writer. Every event kind funnels through at most
16 deterministic SHA-prefix writer shards, regardless of the number of PRs,
with one shared concurrency key per shard and no in-progress cancellation.
On ordinary events, each shard invalidates all event-affected heads to pending
before potentially fallible PR identity reads, but fully requalifies only one
head per invocation. In-progress workflow-run events invalidate without
expensive requalification. An hourly protected-default-branch scheduler
rediscovers open PR heads and deterministically rotates the selected SHA,
retrying previously deferred or rate-limited qualification without disturbing
unselected heads' already valid statuses. This bounds expensive GitHub REST
work and duration per shard while preserving fail-closed pending for deferred
heads. No automatic success, stale evidence acceptance, or bypass is allowed.
A missing GitHub API response cannot prevent attempts to invalidate other
heads; any unsuccessful write/reconciliation fails the job. Discovery retains
read-only credentials. Publication starts pending **before** associated-PR discovery or other
fallible identity reads; incomplete merge metadata and transient API failures
therefore never retain previously published success. It rechecks all applicable
runs before any success, and verifies every open PR's head/base identity has
remained unchanged. GitHub events and statuses are not an atomic transaction;
branch protection and native checks remain independent mandatory controls.

The default-branch ruleset must eventually require the independent App-owned
`linura/applicable-qualification` Check Run **pinned to the App integration ID**,
in addition to `canonical-check`, `dependency-audit`, and `analyze`. It must
**never** require the GitHub Actions-authored `applicable-qualification`
commit-status context, which remains diagnostic and is forgeable by PR code.
App enforcement requires separate deployment, real PR-specific merge-ref,
revocation, recovery, and spoofing acceptance under ADR 0039 before activation.
Individual path-filtered specialized workflows remain non-required globally
so unrelated pull requests cannot deadlock on intentionally absent jobs.

This summary grants no execution, evidence-acceptance, publication, release, or
physical-qualification authority. Trusted release proof and maintained hardware
qualification remain separate boundaries.

## Consequences

A path-filter drift, newly unmapped component/contract, stale SHA, dispatched
substitute, cancelled applicable lane, or missing expected native job fails
closed. Guidance-only exclusions remain possible, but a mixed functional
change selects the functional gate set. Release proof still executes its full
inherited qualification independently.
