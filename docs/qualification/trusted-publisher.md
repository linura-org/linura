# Trusted qualification publisher: operator runbook

## Trust boundary and rollout

`services/qualification-publisher/` is a **separately operated GitHub App check-run publisher**. The GitHub Actions publisher-specific workflow performs tests only; required canonical CI runs the publisher adversarial suite immediately after pinned checkout and Node setup, before any repository-controlled command. The canonical job also pins its exact hosted runner and rejects job containers, services and alternate job-level configuration; this prevents an attacker-controlled container from replacing system tools before any step begins. This prevents prior passwordless-sudo steps from replacing absolute system tools; CodeQL scans JavaScript as well as Rust: no private key, webhook secret, installation token, App deployment or check publication is permitted in Actions. PR-controlled workflows must have no path to publisher credentials, host filesystem, deployment control, or runtime inputs. Never use a repo/organization Actions secret for the private key, even with environment approvals.

There are two independent policies: (1) GitHub's existing `canonical-check`, `dependency-audit`, and `analyze`, which remain required and unchanged, and (2) the reviewed default-branch qualification policy in #206. The publisher **does not accept an Actions commit status** named `applicable-qualification` as proof of (2); that status is diagnostic only. The producer's check is named **`linura/applicable-qualification`**, deliberately different from the Actions status. The only way to obtain a successful producer check is a fresh, bounded, exact-head decision from `tools/applicable_qualification.py decision-head` executed from a protected host checkout of reviewed `main`. This read-only command is implemented by PR #206 and must be merged, installed
from reviewed protected `main`, and exercised against a real App installation
before publication is enabled. Missing command, malformed result, changed PR/base or unavailable GitHub API fails closed; a pending decision leaves the check running.

**Default is `PUBLISHER_ENABLED=false`.** The independent publisher from
#208 is already merged, but it has **not** thereby been deployed or enabled.
Merge #206 only after its exact-head review and checks; install its reviewed
read-only verifier from protected `main` on the isolated App host. Complete
diagnostic-mode provisioning, provenance, spoofing, shared-head, outage and
recovery acceptance **before** enabling publication and pinning the required
Check Run to the dedicated App integration ID. Keep #196 open until the
real operational/ruleset evidence is collected and accepted.

## GitHub App provisioning (requires maintainer actions)

1. Register a private Linura-owned GitHub App and install **only on `linura-org/linura`**. Give it **Checks: write**, **Actions: read**, **Contents: read**, **Pull requests: read**, plus GitHub's implicit metadata access. Do **not** grant administration, workflow, organization secrets, repository contents write, or Actions write permissions.
2. Subscribe to `pull_request`, `push`, `workflow_run`, `check_run`, `installation` webhooks. Use a long random webhook secret, HTTPS ingress and an authenticating reverse proxy. Set `POST /github/webhook` as the webhook endpoint. The Node listener itself deliberately binds only loopback. Only the trusted host's HTTPS ingress can reach it.
3. On a dedicated managed host outside GitHub Actions runners, deploy a reviewed immutable snapshot from protected `main` into `/opt/linura/qualification-publisher/current`. Use an OS-pinned Node **22.23.3** or compatible reviewed upgrade; record deployment commit, Node binary checksum and operator identity. Neither PR branches nor the app's token may update that host or its code. **Every directory component from `/` through the canonical trusted checkout, every descendant directory, and every source/configuration file must be root-owned and not group/world-writable. Symlinks and non-regular objects anywhere within the deployed checkout are forbidden.** The publisher checks this complete tree at activation and again immediately before every read-token-bearing verifier invocation, so writable intermediate directories (such as `tools/`) or imported Python helpers cannot redirect execution. A root-owned `current` deployment pointer may be resolved at startup only when all resolved parents also satisfy these invariants. A read-only systemd view alone is insufficient because other host users might have a writable view. Treat any violation as an activation or qualification-denial event; do not fix it by granting the publisher broad filesystem permissions. The host needs only outbound `api.github.com` TLS, an authenticated reverse-proxy inbound webhook and a monitored clock.
4. Provision the App RSA PEM and webhook secret under `/etc/linura/qualification-publisher/` with owner root and `0600` or stricter permissions. `systemd LoadCredential` makes them available to the service's DynamicUser; no credential is placed in environment variables or process arguments. Rotate by replacing the credential files, restarting the service and verifying a fresh installation token. Immediately revoke compromised App private keys/installations.
5. Create `/etc/linura/qualification-publisher.env` (not a repository file) containing only nonsecret fields:

```ini
PUBLISHER_REPOSITORY=linura-org/linura
PUBLISHER_APP_ID=<numeric-app-id>
PUBLISHER_INSTALLATION_ID=<numeric-installation-id>
PUBLISHER_TRUSTED_REPO=/opt/linura/qualification-publisher/current
PUBLISHER_ENABLED=false
# Opt in only during one-time bootstrap for a new App with no previous green checks:
PUBLISHER_LEDGER_INIT=false
PUBLISHER_HOST=127.0.0.1
PUBLISHER_PORT=8787
```

6. **One-time durable approval journal bootstrap:** the systemd unit creates an owner-private `StateDirectory=linura-qualification-publisher` (mode `0700`). **Only with a newly created App that has never published successful checks**, set `PUBLISHER_LEDGER_INIT=true` and `PUBLISHER_ENABLED=false`, start the service once to initialize its empty `approved-heads.json`, verify ownership and mode, then remove `PUBLISHER_LEDGER_INIT` and restart. A missing/corrupt journal on any subsequent startup is a hard failure, not a reason to create an empty replacement. Restore and reconcile the genuine journal or independently prove that every earlier successful App check is revoked before a fresh bootstrap. Preserve the state directory across deployments, VM migrations, restore and rollback; never operate two App publishers against one installation identity.

7. Review `services/qualification-publisher/deploy/linura-qualification-publisher.service`, adapt the Node location to the host's independently pinned binary, install to `/etc/systemd/system/`, run `systemctl daemon-reload && systemctl enable --now linura-qualification-publisher`, and confirm `/health/live`. Readiness remains false while disabled; when enabled, `/health/ready` is an operational signal, **not a merge qualification proof**. The service serializes reconciliation and rescans all open main-targeting PRs on startup and every ten minutes to recover dropped webhooks. Check Runs are revalidated and updated in place when the dedicated App already owns an exact-head run; repeated scheduled sweeps must not create unbounded duplicate check names. Reconciliation is incremental, not one 33-minute transaction. Each step is independently bounded to **14 minutes 15 seconds** (with a 6-minute-30-second per-head limit), globally invalidates previous journaled approvals and contributor-head checks when starting an epoch, and then processes at most four heads. An epoch admits at most 16 *PR-specific merge targets* (including multiple PRs sharing one head), with four parallel verification workers. Subsequent steps resume the already-invalidated contributor-head inventory, but every head always receives fresh live GitHub evidence and PR-specific merge validation. New evidence supersedes an unfinished epoch, which restarts with journal-first revocation; routine ten-minute polling does not interrupt active batches, but skipped ticks are coalesced into a fresh scan after the epoch finishes. New evidence also aborts in-flight verifier/API work where supported, while the approval journal retains ambiguous remote publication attempts. In-memory cursors are never treated as durable authorization. On restart, the publisher revokes its persisted write-ahead approval journal and reconstructs unfinished work from live GitHub evidence. Each step retains 120 seconds for each verifier, 15 seconds per API request, two independent three-request PR-merge identity passes, bounded App-owned check publication, and a final safety margin. Step deadlines do not grant approvals on incomplete or expired results; they avoid denying valid decisions solely because later API calls have no time left. Readiness stays degraded while any reconciliation or queued/incomplete epoch is in progress, and returns only after successful completion of every batch. This is an operational availability signal, not an authority bypass. First it invalidates **all previously successful or potentially successful checks recorded in a durable write-ahead approval journal**, including now-closed/retargeted PRs. Since the journal tracks at most 16 PR-specific test-merge SHA approvals and is updated *before* every success publication, an untrusted 3,200-head PR flood cannot starve revocation. An inventory with more than 16 distinct heads **or more than 16 PR-specific merge targets** denies all new approvals before running verifiers, without wasting thousands of App API calls on never-authorized heads; it reports degraded readiness. Missing/corrupt journal state and failed revocations prevent authorization. When GitHub is unreachable, an older check cannot be atomically revoked; the real-App outage procedure and original required native gates remain essential. All recorded prior approvals are invalidated before any new verification starts. Per-head errors remain a degraded service even if the associated check is successfully denied. An absent successful sweep or a scan older than two recovery intervals makes readiness unhealthy; alerts must detect missing sweeps and API failures. All publication remains disabled until independent App activation.

## Read-only verifier contract for #206

The **only** accepted trusted process invocation is:

```text
python3 <trusted-main>/tools/applicable_qualification.py decision-head \
  --repository linura-org/linura --head-sha <40-lowercase-hex> \
  --token-env GITHUB_TOKEN
```

Its stdout must be a single JSON object with exact fields:

```json
{"schema_version":1,"repository":"linura-org/linura","head_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","state":"pending","prs":[{"number":206,"head_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","base_ref":"main","base_sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","required_gate_ids":["canonical-ci","security-rustsec","codeql"],"accepted_gate_ids":[]}]}
```

The verifier binds native `pull_request` runs through their event-derived
original PR number and synthetic test-merge SHA recorded in the protected
workflow `run-name`. The
immutable merge commit's base/head parents must match the live PR identity;
mutable `workflow_run.pull_requests` base metadata is not trusted as proof.
The Python verifier reserves an internal 115-second API deadline inside the
App's 120-second subprocess limit. One request batch reuses only immutable
run-attempt job and PR-file inventories; a candidate success must fetch an
independent second batch. API timeouts or exhausted budget deny approval.
The verifier is bounded to 120 seconds. It must independently enumerate *all* open PRs sharing the head, use the reviewed matrix and exact PR-native runs/base association, validate all required gate jobs, and return no `success` while anything is stale/skipped/missing. Its protected source may not be patched by an incoming PR. The publisher additionally re-fetches live PR head/base identities after the verifier responds and verifies the mandatory gate set. **It never publishes a successful check on the shared contributor head.** On an accepted decision it fetches each PR's `refs/pull/<number>/merge` from GitHub, verifies that the synthetic test-merge commit has exactly the current base and contributor head as its parents, detects duplicate merge SHAs, and publishes an independent App check only on that PR-specific test-merge commit. GitHub's branch protection evaluates test-merge checks when present. The contributor-head check remains non-passing; a subsequently opened PR sharing the head does not inherit the earlier PR's merge-ref approval. The App journal records the potentially successful **merge SHA**, not the shared contributor head. The publisher never reads JSON attached to PR comments, artifacts, Actions statuses, event payloads, or issue text as its decision.

## Activation acceptance / red-team proof

Before editing `main` ruleset `21831344`:

- [ ] The GitHub App is installed, and the private key, webhook secret, installation tokens, host checkout and host deployment control are unreachable from PR workflows and fork workflows.
- [ ] Publisher source and verifier source are pinned to reviewed protected `main`, and the exact read-only command from #206 is implemented and tested.
- [ ] An unauthorized same-repository workflow with `statuses: write` can forge the *diagnostic* commit status but **cannot produce a check run from the dedicated App**.
- [ ] A same-named check created by GitHub Actions cannot satisfy the rule after the required check is pinned to the dedicated App **integration ID**, and the malicious change remains unmergeable.
- [ ] Stale base, skipped required job, in-progress run, renamed protected gate file, shared head with failing PR, forged HMAC, duplicate delivery, expired App token, revoked key and missing verifier all fail closed.
- [ ] Real source update after base change, correctly qualified PR, webhook loss plus scheduled recovery, maintenance outage, restart, rollback and credential rotation are proved end to end.
- [ ] Existing required native gates stay required, strict up-to-date protection remains active, and an operator verifies the independent App check's identity on the exact **PR-specific test-merge SHA**, with no successful App check on the shared contributor head.

Never treat green mock tests or GitHub Actions as proof of completion of
#196. The merged #208 publisher and the pending #206 verifier are repository
implementations, **not** a deployed App, private key, external host, DNS
configuration, ruleset integration-ID pinning, or real-App acceptance proof.
#206 may merge when its code, documentation, adversarial review, and exact-head
gates are complete, but operational acceptance must remain explicitly open
under #196.

## Incident response

On suspected key compromise or a spoofed success: disable required-check activation via the reviewed break-glass governance path if and only if maintaining an unusable requirement would block emergency patching; preserve the native required gates, revoke the App key, suspend the installation, archive audit evidence, rotate secrets and restore independently reviewed code. Never substitute a PR-authored check or self-reported receipt to restore green. On publisher outage, checks stay missing/running/failing; investigate authenticated host and API failures. Notify maintainers of lost sweeps; do not fabricate qualification from stale success.


### Check Run rerequests

An App-authored `check_run` `rerequested` webhook triggers a fresh review of
live GitHub evidence. Self-generated `created`, `in_progress`, and
`completed` check-run events are ignored to avoid an infinite feedback loop.
The periodic recovery sweep remains authoritative when GitHub omits a webhook.


## Residual stale-success risk and operator controls

GitHub Check Runs are durable: there is no TTL or atomic conditional update
of a previously successful check when the GitHub API or publisher is offline.
**Neither a watchdog nor an HTTP readiness check can revoke a stale green
result when GitHub is unreachable.** A prior success may remain visible while
an outage prevents an invalidation. Native canonical CI, RustSec, CodeQL and
strict up-to-date branch protection must remain independently enforced. Before
activating this App as a required gate, exercise a forced outage after a
successful check and measure exactly what the actual GitHub ruleset permits.
If the deployment threat model cannot tolerate that stale-success window,
**do not activate** this check as the authorization authority. The authorized
operator must initiate the documented maintenance/freeze procedure, verify
actual branch ruleset state, and retain evidence. Never assert unconditional
fail-closed revocation based solely on the publisher's local health.

The host must use the exact verified Node.js **22.23.3** runtime, whose official
Linux x64 tarball is SHA256
`df450af89261115ef9f9e3830c3eeb2cc9213b63c720b1af623cb5dcbe2e02de`.
Provision it from the authenticated official release or an internally mirrored,
checksum-verified image; pin `ExecStart` to that reviewed executable rather than
assuming `/usr/bin/node` is the verified version. The service refuses startup
with any different Node version. Keep application files and the trusted
verifier root-owned and not writable by the dynamic service user. Secrets are
loaded through systemd `LoadCredential`, atomically opened with `O_NOFOLLOW`,
validated using their open file descriptors and checked against trusted parent
ownership and permissions.

## Required operator-side integration tests

In a disposable, separately provisioned GitHub App installation (never using
production signing keys in CI), exercise Check Run `completed` to `in_progress`
updates, manual `rerequested` events, fork-branch head SHAs, shared PR heads,
base updates, authorization conflicts, permission revocation, GitHub secondary
rate limits, token expiration and outages during invalidation. Save check IDs,
App IDs, exact SHA/base IDs, rule source IDs and measured timings. The checked-in
mock API tests are necessary regression evidence but **not** a substitute for
real integration proof. Do not enable enforcement until these tests pass.


## Security review regression guards

The required unfiltered `canonical-check` uses the pinned Node `22.23.3` setup and the complete publisher syntax/adversarial test suite. Its first repository-controlled step explicitly selects `/usr/bin/bash --noprofile --norc -euo pipefail {0}`, rather than inheriting a workflow/job `defaults.run.shell`; this prevents an attacker-selected success-only shell from skipping the checker itself. The validation contract pins this exact step shell and the regression suite rejects missing, replaced, or duplicate shells. `tools/check_validation_gates.py` guards the **exact unconditional setup and execution steps** against being deleted, made conditional, changed to `continue-on-error`, or replaced by a no-op. The publisher-specific path-filtered workflow is supplementary; it is not the security authority for a CI-only workflow change. The subprocess receives a live installation token through its environment, so errors from `execFile` are classified using a fixed, sanitized message. Raw child `stdout`, `stderr`, `error.message` and error causes must never reach logs, check summaries or alerts. The adversarial suite checks both overflow-head invalidation and deliberate subprocess-token emission.


## Required-check identity and shared-head race acceptance

The trusted check is deliberately **only successful on `refs/pull/<number>/merge`**, never on the shareable contributor head SHA. The service independently resolves the merge ref and validates its two parents (current `main` base and contributor head); missing, conflicting or duplicate merge identities fail closed. A new PR using the same contributor commit must have its **own** independently verified test-merge check. Maintain the existing strict-up-to-date ruleset and original native required checks. Before enabling the App check as required, independently demonstrate GitHub's exact test-merge-required-check selection using two real PRs sharing one contributor SHA, opening the second both before and immediately after the first gets a green merge check. Confirm neither PR inherits the other's App check, including synthetic-merge identity collision attempts and fork cases. If the actual GitHub ruleset does not enforce PR-specific test-merge checks, do not activate: use a separately reviewed merge-queue/final-merge authorization architecture instead. The checker still cannot atomically revoke green results during a GitHub API outage; that limitation remains explicitly an operator-gated risk.

CI's required publisher-test step explicitly sets empty `NODE_OPTIONS`, `BASH_ENV`, and `ENV` at **step scope**, overriding inherited workflow, job or prior-step values that could cause `node --test` to report a vacuous green with `--test-only` or execute a hostile Bash startup script before tests begin. The protected validation-gate contract requires the exact override; a missing or altered override fails canonical CI. The sanitizer regression must actually execute a real child and require the fixed `trusted verifier process failed` message; a rejection from the privileged source-tree attestation is not sufficient.


### Merge-target capacity and shell-startup controls

The approval journal is bounded by **PR-specific synthetic merge commits**, not merely contributor heads. One contributor head can be reused by multiple PRs; therefore the 16-target ceiling applies to the total open main-targeting PR inventory that could be approved. After revoking earlier journaled approvals, any inventory exceeding 16 distinct heads **or 16 PR merge targets** is rejected before any new App check becomes successful. An accepted 16-target inventory may include multiple PRs sharing the same head; each receives its own verified merge-check identity. Regression tests cover both sides of this boundary. Deployment monitoring must report sustained over-capacity denial rather than automatically enlarging the journal or revocation budget.

The unfiltered canonical CI publisher step clears `BASH_ENV`, `ENV` and `NODE_OPTIONS` at step scope to block inherited noninteractive Bash startup hooks and Node test-mode manipulation. Static anti-drift tests reject removal or tampering; upstream steps must not be able to restore a startup hook through inherited environment state.


## CI executable provenance and remote completion validation

The required unfiltered canonical publisher contract now checks that the pinned
`actions/setup-node` step is followed **immediately** by the protected
publisher suite. A separate workflow step inserted between them could write a
counterfeit `node` executable into `$GITHUB_PATH` and shadow version, syntax,
and test commands despite byte-identical protected step bodies. Any missing,
duplicate, malformed or intervening step is rejected by the validation-gate
checker, with adversarial tests. The publisher suite still clears inherited
Bash and Node startup options and executes the protected validator itself.
It invokes the policy checker as `/usr/bin/python3 -I -S tools/check_validation_gates.py`,
not through `PATH`, so an earlier CI step cannot replace the interpreter using
`$GITHUB_PATH` or alter Python module startup through `PYTHONPATH`/`PYTHONHOME`.
The unfiltered canonical publisher step first checks the live checkout against
`GITHUB_SHA` using an inline Python attestor. With an absolute OS interpreter
and Git executable under a restricted environment, it verifies the Git commit
identity and raw blob digests of all publisher implementation/test files, the
CI workflow, and its Python policy checker and regression tests. Altered,
missing, symlinked, or extra source files deny before running Node. It reads
actual file bytes rather than trusting Git's index flags, and CI regressions
prove denial for replaced/stale publisher code, unexpected modules, mutated
gate sources, and poisoned Git settings/PATH. This protects the tested
source snapshot from preceding workflow steps, but is not an independent
security boundary against a malicious same-repository workflow author.

The attestor is embedded in the byte-for-byte validated mandatory step rather
than loaded from a mutable repository file.
The publisher's Node commands execute via `/usr/bin/env -i` rather than
Bash command lookup. This removes imported `BASH_FUNC_node` impersonation and
other inherited Node runtime environment state while keeping the pinned
`setup-node` binary first on the setup-provided PATH; adversarial tests cover
that distinction.

The exact interpreter flags are asserted by the validator and a subprocess
regression with a counterfeit `python3` and poisoned startup variables. This
protects an in-repository test gate against these bypasses; it is **not** an
independent authority against arbitrary malicious same-repository workflows.
Only the separately hosted GitHub App and source-pinned ruleset can provide
that merge-authorization trust boundary.

GitHub App Check Run list responses must match **all** expected exact-App,
check-name and head identities. An unexpected filtered inventory is not treated
as an empty list. After creating or reusing a check, the publisher also binds
its returned check ID to the exact head SHA; a terminal success or denial is
accepted as confirmed only when GitHub's response reports the matching ID,
head, dedicated App, check name, completed status and intended conclusion.
Ambiguous, omitted, or inconsistent API responses degrade publisher readiness
and preserve prior durable potential-success entries for recovery. This does
not remove the unavoidable remote API outage/stale-success limitation.
