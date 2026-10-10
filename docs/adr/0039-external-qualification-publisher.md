# ADR 0039: Independent GitHub App authority for qualification checks

**Status:** Accepted

## Context

Issue #196 requires one reviewed, branch-protection-required aggregate qualification gate. GitHub Actions `GITHUB_TOKEN` is not an exclusive identity for a trusted PR reconciler because a same-repository PR can modify workflow permissions and publish the same commit-status context. A branch rule that accepts GitHub Actions as the expected publisher cannot distinguish that forgery.

## Decision

Introduce a separately operated GitHub App that owns an exclusive check-run name, `linura/applicable-qualification`. The App's RSA key, installation token, webhook secret, trusted default-branch policy source, deployment permissions and execution host are **outside** GitHub Actions and all untrusted PR code. The App only reads live GitHub head/base/PR metadata and a bounded decision from verified default-branch code. It publishes only its own check run, never an Actions commit status, and starts with publication disabled. **Success attaches to a PR-specific synthetic test-merge commit** verified against the current PR number's merge ref and the exact base/head parents, never to the shareable contributor head SHA. Otherwise a newly opened PR could inherit an unrelated earlier success before any webhook can revoke it.

After #206 implements a read-only independent decision interface and all adversarial acceptance tests pass, `main` branch protection must require the new check **from the dedicated App integration ID**, not from Any Source, GitHub Actions, or a shared OAuth credential. Canonical CI, RustSec and CodeQL remain separate required checks. No PR-controlled output, job name, workflow dispatch or mutable downloaded artifact is authority.

The dedicated App check is covered by mandatory canonical CI Node adversarial tests and by JavaScript CodeQL analysis in the existing required CodeQL job, without dropping Rust coverage. A new `services/` implementation root is explicitly registered in the topology contract.

The check service uses short-lived repo-scoped installation credentials, HMAC-authenticated webhook triggers, immutable source deployment, bounded API/verification operations, per-process serialized decisions, and independent periodic reconciliation. The publisher rechecks live PR metadata before accepting a success. Reconciliation is a series of bounded steps (at most four heads per step), not one multi-wave deadline. An ephemeral cursor checkpoints completed heads; restarts or new evidence discard unfinished positions. A routine periodic tick does not starve a running multi-step reconciliation. Before an epoch grants any new approval, it revokes all journaled successes and invalidates every contributor-head check. Only the potentially successful merge SHA approval journal is durable; it is revoked before rebuilding unfinished work after a crash. Admission remains at most 16 distinct contributor heads **and at most 16 total PR-specific merge targets**, with four verification workers. The target bound includes shared contributor heads and matches the durable journal's worst-case approval count. A host-private approval journal is durably written **before** each successful check publication and cleared only after GitHub confirms invalidation. Previously authorized heads are invalidated first, independently of the size of a newly discovered PR inventory. Over-capacity admission rejects every new approval after revoking at most 16 journaled head checks; it never tries thousands of slow App writes to unapproved spam heads. Missing or corrupt journal state prevents startup. Inventories above the verification capacity must first invalidate all **journaled potential successes**, including closed and retargeted PRs, then deny all new approvals. The journal records test-merge SHA identities; unapproved spam heads never require an App status write. An unavailable GitHub API may prevent invalidation, which remains an explicitly documented residual stale-success risk. Trusted verifier subprocess failures are sanitized to prevent leaked installation credentials from being persisted in logs. Required canonical CI step integrity is enforced by an exact pinned-runtime and complete publisher-test command contract. Any per-head infrastructure error degrades service readiness even if the Check Run is denied. Existing App-owned check runs are invalidated and updated rather than issuing a fresh duplicate check every recovery sweep. Failed, incomplete, stale or unavailable verification cannot publish success. The incident and activation runbooks are in `docs/qualification/trusted-publisher.md`.

## Tradeoffs and residual risks

This adds an independently provisioned App and managed host. Source-controlled code alone cannot attest that a GitHub App is installed, credentials isolated, the host deployed or the ruleset updated; those require an operator and end-to-end verification. Webhooks and periodic scans cannot guarantee atomic revocation against GitHub API outages; strict up-to-date base rules and independently required native gates remain mandatory. Cached previous successes and remote API failures must be observed and investigated: GitHub cannot atomically revoke a previously successful check during a total API outage. This is an explicit deployment acceptance risk, not a guaranteed fail-closed state; deployment must stay disabled if the threat model cannot tolerate it. Checks for exact SHA are not reusable for another SHA or base without live revalidation.

## Rollout

1. Merge standalone test-only infrastructure without changing current ruleset.
2. Complete read-only exact-head decision interface and integration in PR #206.
3. Provision the independently operated App/host, validate adversarial bypass attempts, enable publisher.
4. Pin required check to its App integration ID and verify branch-protection accept/reject behavior.
5. Close #196 only after operational enforcement and complete exact-source gate evidence.

This ADR is intentionally separate from PR #206's pending qualification-gate ADR. After this PR becomes `main`, #206 must use the next unused ADR number rather than colliding with `0039`.


## Admission invariant for shared contributor heads

A GitHub required check on a contributor head SHA is reusable by an arbitrary PR that later points at that commit. The independent publisher therefore creates non-passing contributor-head checks for immediate fail-closed visibility but publishes success **only on GitHub's PR-scoped synthetic test-merge SHA** from `refs/pull/N/merge`, after independently checking its parents and current PR identity. Distinct PRs must have distinct merge SHAs, or publication fails closed. The reviewed merge-ref behavior must be proved end-to-end using the installed App and active ruleset before activation; protected source code alone cannot guarantee GitHub's external-check precedence. Mandatory native gates and strict-up-to-date behavior are preserved. The source-head TOCTOU is not claimed to be solved through additional polling.


The mandatory publisher test step in canonical CI must clear inherited `BASH_ENV`, `ENV`, and `NODE_OPTIONS` at step scope. The protected validator requires this exact unconditional override and adversarial tests prevent workflow/job/GITHUB_ENV shell startup hooks from silently turning mandatory Node tests into successful no-ops.


The mandatory canonical publisher suite has adjacent, immutable SHA-pinned
Node setup and protected test execution; a step inserted between them can
shadow the Node binary through GitHub Actions' `GITHUB_PATH` and is rejected
by the static gate validator. The publisher rejects inconsistent filtered App
check inventories rather than treating them as absent, and independently
confirms the exact App, check ID, head SHA, completed status and conclusion on
terminal Check Run updates. Unknown remote results degrade readiness instead
of being treated as proof.

The canonical CI publisher tests execute after only SHA-pinned checkout and Node setup, before any repository-controlled command. The validator rejects earlier or reordered steps and modified checkout inputs, since hosted runners permit passwordless sudo and earlier steps could replace absolute system executables. This complements but does not replace the externally operated App trust boundary.

The canonical publisher gate additionally pins the complete job-level property set to the reviewed Ubuntu hosted runner and steps, excluding attacker-selected job containers, services, matrices or alternative runner images. Restricting preceding steps alone does not secure an untrusted execution environment.
