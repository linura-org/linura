# ADR 0041: Explicit activation of independent applicable qualification

**Status:** Accepted

**Supersedes:** ADR 0040 (automatic GitHub Actions diagnostic publication and reconciliation only)

## Context

ADR 0040 established the complete reviewed qualification matrix, exact
PR/head/base and execution-evidence checks, and an automatically triggered
diagnostic GitHub Actions status writer. That writer was not a trusted
required check: a same-repository PR workflow can forge the same
`applicable-qualification` commit status with `statuses: write`.
The separately operated publisher from ADR 0039 has not yet completed the
installation, credential-isolation, spoofing, restart, outage, and
merge-ruleset acceptance required by issue #196.

Automatically publishing failing diagnostic statuses before the independent
App is operational introduces avoidable runner fan-out and misleading red
checks, including on PRs that legitimately modify qualification authority.
It does not improve branch protection because the diagnostic is not required.

## Decision

Separate the repository's qualification implementation from its operational
activation. `contracts/qualification-activation.toml` declares an explicit,
reviewed three-state lifecycle, initially `off`:

- **OFF:** No automatic Applicable qualification event, scheduled recovery,
  commit-status writer, or App-owned Check Run. A manual workflow dispatch
  may validate the protected-main policy; it never authorizes merges.
- **SHADOW:** A maintainer must manually dispatch an exact-head read-only
  decision from protected `main`. The result is an advisory JSON receipt
  in the workflow log. Neither the CLI's success exit code nor a JSON receipt
  becomes a commit status, a check run, or acceptance evidence.
- **ENFORCED:** The GitHub Actions workflow remains manual-only and
  read-only. A separately deployed GitHub App is the **sole** possible
  producer of the `linura/applicable-qualification` required Check Run,
  pinned to that distinct App integration ID. A declaration is not proof of
  App installation, verification, or ruleset activation.

The reviewed GitHub Actions workflow has only `workflow_dispatch` and
read-only permissions, and its complete source is validated against an
immutable expected template. Inline YAML event mappings, alternate jobs,
writer permissions, and repository-controlled execution substitutions
are rejected by canonical validation. The independent App's source,
deployment and keys never enter a PR-accessible Actions context.

Promoting OFF to SHADOW requires reviewed protected-main policy. Promoting
to ENFORCED requires distinct operator-owned acceptance for issue #196:
live App operation and isolated credentials, PR-specific synthetic
merge-commit admission, spoofing and shared-head tests, strict up-to-date
branch protection, outage/fail-closed behavior, and a required check pinned
to the App's integration ID. An evidence URL in a repository contract
cannot activate those external controls.

The pre-existing `canonical-check`, `dependency-audit`, and `analyze`
checks retain their required status and pinned provenance. All applicable
specialized VM, guest, release, and workstation qualifications continue
to run on their own paths. Do not interpret disabling the additional
diagnostic as permission to merge a code change with failed or missing
native or applicable qualification. Do not switch OFF to bypass an already
required independent App check during an outage.

## Relationship to previous decisions

This ADR supersedes **only** ADR 0040's automatic Actions-based diagnostic
status publishing and event-driven reconciliation strategy. It preserves
ADR 0040's routing inventory, negative/fail-closed qualification rules,
independent evidence boundaries, and admission semantics as the eventual
App's reviewed verifier. ADR 0039's isolated App remains a prerequisite
for trusted enforcement. ADR 0040 stays an immutable historical record.

## Consequences

Pre-activation PRs no longer generate redundant Applicable qualification
workflows or fresh diagnostic commit statuses after this decision and
workflow reach protected `main`. Historical statuses remain recorded,
and an unmerged branch cannot change current protected-main triggers.
Manual shadow results cannot satisfy branch protection. Activation must
be proved on the live App and ruleset, not inferred from code tests.

Issue #196 remains open until operator-side independent App acceptance is
complete, with immutable evidence and a validated rollback/incident plan.
