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

The original Actions commit-status writer is now dormant: OFF publishes
nothing and manual SHADOW writes an advisory JSON receipt only. The independent
App-owned check remains undeployed and unenforced until operational acceptance.
Neither green existing GitHub Actions checks nor this PR alone completes
the required-summary acceptance criterion of issue #196. Keep the
existing three native required gates and strict updated-base policy
intact. This is a hard deployment blocker, not a waiver to be signed by
the code-changing PR or an automatically resolvable review comment.

## Activation lifecycle: OFF, SHADOW, ENFORCED

This activation contract implements [ADR 0041](../adr/0041-applicable-qualification-activation.md), which supersedes only the diagnostic event-writer behavior of ADR 0040.

Protected `contracts/qualification-activation.toml` declares `mode = "off"`
until the independent GitHub App and #196 operational acceptance are complete.
`tools/applicable_qualification.py validate` checks the activation contract
and the Actions workflow's strictly manual, read-only execution boundary.

| Mode | GitHub Actions workflow | Merge authority |
| --- | --- | --- |
| `off` | No automatic PR, workflow-run, push or scheduled qualification reconciliation. Manual dispatch only validates the trusted policy. | No new diagnostic status and no App Check Run |
| `shadow` | Maintainer may explicitly dispatch the workflow with a 40-character contributor-head SHA; reviewed protected `main` runs a read-only `decision-head` verification. | Advisory JSON in job logs only; never a commit status or merge authorization |
| `enforced` | Remains manual-only and read-only. No GitHub Actions publisher credentials. | Only the independently deployed GitHub App may issue `linura/applicable-qualification`, pinned as required to its specific integration ID after real acceptance |

The workflow's **only event** is `workflow_dispatch`, its job checks out
protected `main`, and it has no `statuses: write` or `checks: write`
permissions. A green manual shadow job means the command completed, **not**
that its JSON decision was accepted. Historical red diagnostic commit statuses
on earlier heads remain recorded; OFF does not fabricate new successful checks.
Previously event-driven reconciliation functions remain as dormant,
test-covered implementation; they are no longer wired to automatic Actions
events. Normal native and specialized CI workflows still run on their own
reviewed triggers, and release qualification remains unchanged.

OFF → SHADOW requires a reviewed protected-main activation change. Moving to
ENFORCED additionally requires independently recorded #196 acceptance of real
App deployment, source/credential isolation, forged-status and same-name-check
attacks, exact PR-specific test-merge identity, restart/recovery and outage
behavior, and operator evidence. An evidence URL in the declaration is not
proof of App installation or real branch enforcement. Only after passing that
acceptance may the operator change branch protection to require the App-owned
check, preserving `canonical-check`, `dependency-audit`, `analyze`,
strict up-to-date protection and applicable specialized gates.

Do not close #196 or claim ENFORCED merely because a workflow or a model test
passes. An already activated required App check must never be bypassed by
changing this mode to OFF on an outage. Independent verification and incident
freeze procedures remain part of the enforcement contract.

## Boundary

This layer answers only "which PR gates were applicable and did the exact-head
native runs succeed?" It does not accept qualification evidence, mint execution
envelopes, authorize a release, publish evidence, or fabricate maintained
hardware qualification. Those authorities remain in their existing layers.
