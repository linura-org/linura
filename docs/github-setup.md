# GitHub repository setup

Apply these settings before accepting implementation PRs.

## Repository

- Default branch: `main`.
- Canonical repository: `linura-org/linura`.
- Canonical organization: `linura-org`.
- Canonical project domain: `linura.org`.
- Enable Issues and private vulnerability reporting.
- Enable the dependency graph, Dependabot alerts and security updates, secret scanning, push protection, and code scanning where available.
- Disable force-push and branch deletion on `main`.
- Prefer squash merge for normal feature PRs; preserve an explicit release/history policy if later changed by ADR.
- Delete merged feature branches automatically unless a documented workflow requires otherwise.

## Main branch ruleset

Target the default branch (`main`) and require:

- a pull request before merge;
- all permanent required status checks to pass;
- resolution of all review conversations;
- **zero repository-wide required approving reviews** in the default-branch ruleset while Linura uses App-created mechanical release PRs;
- these exact required status-check contexts, proven by the permanent workflows:
  - `canonical-check`;
  - `dependency-audit`;
  - `analyze`;
- the branch to be up to date before merge for trust-boundary, security, packaging, and release changes;
- linear history unless a documented release process requires otherwise;
- signed commits and tags when the organization signing policy is established;
- force-pushes and branch deletion disabled.

The zero approval count is deliberate, not a relaxation of release review. Linura's semantic review boundary is the user-authored `release: ready vX.Y.Z — <theme>` PR. That PR must receive the required human/Codex review under the release policy before a maintainer merges it. After that merge, Release Preparation, Release Authorization, publication, terminal closure, and cleanup are structurally constrained machine handoffs and must not acquire a second hidden human-approval gate.

If the organization later wants repository-enforced approving reviews for ordinary development, use a ruleset design that explicitly excludes or separately handles the mechanically constrained release handoff PRs. Do not turn on a blanket approval count that makes App-created release PRs wait for a human after the reviewed readiness boundary. Do not grant the Release App a ruleset bypass merely to work around that contradiction.

Do not add one-time/bootstrap workflow checks to the ruleset. Required checks must be produced by permanent workflows on both pull requests and the protected branch where appropriate. Keep bypass permissions restricted to deliberate recovery/administration rather than ordinary development or normal releases.

Protect these paths with CODEOWNERS ownership metadata once teams exist:

- `executors/**`
- `polkit/**`
- `interfaces/**`
- `SECURITY.md`
- `docs/security-model.md`
- `docs/threat-model.md`
- `.github/workflows/**`

Prefer organization teams as CODEOWNERS once they exist, for example `@linura-org/maintainers` for ordinary ownership and `@linura-org/security` for security-sensitive paths. CODEOWNERS may request the appropriate reviewers, but do not enable a repository-wide required CODEOWNER approval rule that blocks structurally constrained post-readiness release PRs unless those PRs have an explicit automatic-safe exception path.

## Actions

- Set workflow permissions to read-only by default; grant writes per job only when the job requires them.
- Do not allow unreviewed forks to obtain repository or App private-key secrets.
- Keep every third-party action pinned to an immutable full commit SHA. Repository validation fails if a workflow introduces a floating action ref.
- The automatic Release job deliberately has **no GitHub Environment dependency**. This prevents a repository-environment reviewer from becoming a hidden manual gate after reviewed readiness.
- If a future publication credential requires an Environment, introduce it only together with an explicit release-contract change proving the environment has no human reviewer in automatic mode, or acknowledge that the lifecycle is no longer automatic after readiness.

## Dedicated Linura Release GitHub App

Create and install a dedicated repository-scoped **Linura Release GitHub App** for machine release handoffs.

Required repository configuration:

- repository variable `LINURA_RELEASE_APP_CLIENT_ID` = the App client ID;
- repository secret `LINURA_RELEASE_APP_PRIVATE_KEY` = the App private key in PEM form;
- install the App only on `linura-org/linura` unless a later ADR deliberately widens scope;
- App repository permissions: **Actions: write**, **Contents: write**, **Pull requests: write**;
- do not add the App as a ruleset bypass actor.

The App identity is required because PRs created by the repository `GITHUB_TOKEN` produce approval-gated native `pull_request` workflow runs. App-created PRs must receive the ordinary native CI/Security/CodeQL runs that the `main` ruleset recognizes. Explicit `workflow_dispatch` runs may provide additional exact-SHA evidence, but they must never substitute for the ruleset-authoritative native PR runs.

## Security features

Enable, where the GitHub plan supports them:

- dependency graph;
- Dependabot alerts;
- Dependabot security updates;
- secret scanning;
- push protection;
- code scanning / CodeQL;
- private vulnerability reporting.

Treat findings as gates for supported releases. Do not weaken a failing security gate merely to produce a release.

## Releases

Before any public Linura release:

- in repository **Settings**, scroll to **Releases** and select **Enable release immutability**; this is a repository/organization administration prerequisite and GitHub applies it only to releases published after the setting is enabled;
- confirm the release workflow uses the draft-first publication pattern so all sealed assets are uploaded and verified before the draft is published and becomes immutable;
- trusted candidate proof must succeed on the exact commit SHA;
- SBOM generation must succeed;
- checksums must cover the sealed payload;
- artifact signing or provenance attestation must succeed;
- independent published-asset verification must succeed;
- `gh release verify` must prove the GitHub Release is immutable and its release attestation is valid;
- each downloaded asset must pass `gh release verify-asset` in addition to Linura's own checksum/evidence and build-provenance checks;
- the release tag must remain bound to the verified candidate source;
- rollback/recovery acceptance testing must satisfy the version's declared claim class;
- there must be no environment/reviewer approval between Promotion and automatic publication.

Do not treat successful upload/publication as release completion. If GitHub reports the published release as non-immutable, or independent verification does not complete successfully, the version has not satisfied Linura's publication contract.

If a **non-immutable, non-qualified** publication must be requalified under the same version before that version is accepted, enable release immutability first, then deliberately remove both the superseded GitHub Release and its Git tag, verify that neither identity remains, and only then merge a fresh release-intent commit. This exception applies only to a publication that never satisfied Linura's immutable-release contract. Never attempt to reuse a tag that belonged to an immutable GitHub Release; GitHub permanently prevents reuse of such tag names after immutable publication.

The repository already contains workflows and tooling for candidate construction, promotion, and independent verification. A registry or package publication must not begin until product naming/trademark clearance and the corresponding registry ownership strategy are settled.
