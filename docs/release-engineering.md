# Release engineering

Linura separates **what a version claims**, **which exact reviewed source is proven**, **which system qualifications that claim requires**, **how candidate bytes are constructed**, **how proof is promoted**, **when the immutable version tag is created**, and **how publication is independently verified**.

See [Release contracts, claims and evidence](release-contracts.md) for the version-scoped documentation/evidence model and [Trusted release build boundary](release-build-trust.md) / [ADR 0015](adr/0015-isolated-reproducible-release-build.md) / [ADR 0023](adr/0023-build-once-promote-exact-bytes.md) for the build/promotion trust model.

The release control plane is repository-owned. Linura does not require another repository or external release orchestrator at release time.

## Release documentation lifecycle

Every planned version starts with a mutable milestone contract at `docs/milestones/vX.Y.Z.md`.

Before release proof starts, implementation closes into a frozen release contract at `docs/releases/vX.Y.Z.md`. That contract is mandatory input to proof/publication and declares:

- claim class and exact capability boundary;
- supported/unsupported platform scope;
- security/authority boundary;
- migration/recovery boundaries;
- mandatory qualification workflows/evidence;
- known unsupported states;
- human PR/commit traceability where useful.

Qualification dossiers under `docs/qualification/` explain how the implementation maps to the milestone and what evidence is required/obtained. They do not fabricate future run IDs or turn an unexecuted workflow into proof.

The GitHub Release body is not independently generated. The exact `RELEASE_NOTES.md` sealed during Trusted Release Proof is published verbatim from the frozen release contract/notes.

### Release presentation convention

- Git tag: `vX.Y.Z`.
- GitHub Release title: `Linura vX.Y.Z`.
- Frozen release-note first heading: `# vX.Y.Z — <implementation theme>`.

The Git tag stays product-name-free for SemVer-compatible tooling. The product name belongs in the GitHub Release title; the frozen note heading carries version + concise implementation theme.

## Protected release intent

The normal release path begins with a commit merged into protected `main` whose subject is:

```text
release: vX.Y.Z — <implementation theme>
```

That commit does **not** create a tag. It expresses an unpublished release intent for the exact current `main` SHA.

The semantic review boundary precedes that intent: Release Preparation freezes the mechanical version metadata on top of already-reviewed readiness. Release Authorization then transports that reviewed state through protected `main` as a zero-diff, tree-identical machine handoff. Authorization does not require a conversational reviewer; it requires exact parent/tree/message identity, zero changed files, zero unresolved review threads, explicit exact-head canonical checks, and the repository ruleset.

After the protected Release Authorization merge creates the exact `release: vX.Y.Z — <implementation theme>` source, the owning `Release Authorization` workflow explicitly dispatches `CI`, `Security` and `CodeQL` for that exact protected-`main` SHA, binds acceptance to the current dispatch attempt, waits for all three to succeed, rechecks that `main` is unchanged, and then directly dispatches `Trusted Release Proof` for that source.

`Release Proof Dispatch` remains a non-authoritative compatibility observer for independently emitted native `push`-driven permanent-gate events. When such events exist it may wake and duplicate-safely dispatch proof only after independently revalidating exact source, contract, version, gate success, tag absence and current `main`. It is **not** a mandatory edge of the job-scoped `GITHUB_TOKEN` normal path, because token-authored mutations are not relied on to recursively emit native push workflows. If either the direct handoff or compatibility observer sees source drift, it exits without release authority.

Automation-authored PRs may also surface approval-gated or otherwise redundant ordinary `pull_request` runs. Those are not release-control evidence. The authoritative machine evidence is the nonce-bound explicit `workflow_dispatch` set, whose workflow path, exact SHA/ref, display title and immutable run ID are recorded and revalidated. Their check contexts satisfy the protected-main ruleset.

## Release-stage timeout budget

Release mutation jobs must reserve more wall-clock time than the sum of their explicit bounded waits. Candidate-gate resolution/wait, any semantic preparation-review polling, deterministic structural re-proofs, and post-merge exact-main gates must fit before the job deadline with operational margin. A job timeout must never be able to strand the lifecycle after a protected-main merge but before the next durable handoff is dispatched. The executable tooling contract pins the current release-preparation, release-authorization, and post-release-closure budgets accordingly.

## Trusted Release Proof

`Trusted Release Proof` is `workflow_dispatch`-only and begins with `github.sha` as the candidate source. Its authorization job is read-only with respect to repository contents.

It first:

1. proves checkout `HEAD`, `github.sha` and `origin/main` are the same exact SHA;
2. validates the `release: vX.Y.Z — …` subject and frozen release contract;
3. re-verifies successful exact-SHA `CI`, `Security` and `CodeQL` runs.

It then runs the **mandatory exact-source system qualification graph** before construction. The exact graph is version/claim scoped; for v0.6 it includes:

- authoritative observation acceptance;
- Control1 plan-preview acceptance;
- v0.4 durability fault qualification;
- v0.4 real filesystem/ENOSPC recovery qualification;
- v0.5 isolated executor/verifier qualification;
- v0.6 complete managed-lifecycle disposable-VM qualification.

The v0.6 workflow proves the bounded `Authority1 → linura-authorityd → Control → executor → systemd → independent verifier` path on a disposable real system and runs the deterministic eleven-case v0.6 fault/recovery matrix. Earlier milestone gates remain inherited evidence where the v0.6 design depends on their qualified invariants.

Only after every required qualification succeeds may Trusted Release Proof delegate construction to the repository-owned reusable trusted builder.

The build/proof phase then:

1. constructs release binaries once with locked dependencies inside the pinned deterministic build envelope;
2. constructs `SOURCE_SHA`, `RELEASE_TAG`, frozen `RELEASE_NOTES.md`, `BUILD-ENVIRONMENT.json`, SPDX SBOM and `RELEASE-EVIDENCE.json`;
3. seals the payload with `SHA256SUMS` and a machine-readable proof receipt;
4. verifies the complete contract and creates GitHub/Sigstore build-provenance attestations;
5. keeps the tracked source tree immutable throughout construction;
6. uses a separate fresh runner to rebuild the exact source and reproduce every distributable binary byte-for-byte.

For v0.6 the distributable binary set includes `linura-authorityd` and excludes the future `linura-firstboot` scaffold, as governed by `contracts/components.toml` and [ADR 0025](adr/0025-component-maturity-and-milestone-activation.md).

A successful CI run, an earlier PR-head VM run, or a reproducible build cannot individually substitute for the exact-source qualification graph.

Canonical-gate discovery binds CI, Security and CodeQL evidence by the immutable workflow file path plus exact source SHA, event and terminal conclusion. GitHub's run `name` is display metadata and may be replaced by `run-name` (including the nonce-correlated titles used by release-owned dispatches), so it is never treated as workflow identity.

### SHA changes invalidate exact-source evidence

Rebase, history compaction, amend, force-update or any other content/history change that produces a new candidate SHA invalidates exact-source release evidence for the old SHA.

This is why final history compaction must occur **before** final exact-head gates and Trusted Release Proof. Old development runs can diagnose behavior, but they are not proof for the compacted source.

## Reusable trusted builder

`.github/workflows/reusable-release-build.yml` is a least-privilege construction capability, not publication authority. It cannot write repository contents, create tags or publish a GitHub Release.

The promotable bytes are produced once in the trusted build and later stages consume those same sealed bytes rather than rebuilding them. See [Trusted release build boundary](release-build-trust.md).

After build/reproduction succeeds, a narrow dispatch job receives only the permissions needed to recheck that the proven SHA is still current `main` and explicitly dispatch `Release Promotion` with the exact source SHA and proof run ID.

## Release Promotion

Promotion is `workflow_dispatch`-only and cannot create a tag or GitHub Release.

It is split into three authority stages:

1. a read-only validation job verifies the exact proof run identity, event, terminal status, success conclusion and source SHA;
2. validation requires the proven SHA still equals current `main`, validates version/frozen contract again, and refuses a version tag already bound to another source;
3. an isolated closure-readiness job obtains only the write permissions needed to model future closure (`contents: write`, `pull-requests: write`, `actions: write`) and uses the exact same credential selection as closure;
4. readiness proves Contents/write through GitHub's merge endpoint using identical `main` base/head and accepts only the no-op `204` response, covering the write capability needed for release-scoped branch push, protected PR merge and branch cleanup without creating repository state;
5. readiness probes pull-request creation with identical `main` base/head and accepts only GitHub's exact same-head validation response, so the probe cannot create repository state;
6. readiness probes Actions dispatch using an impossible all-zero ref and accepts only a missing-ref validation response, so no workflow run can be created by the probe;
7. missing Contents, PR, or Actions capability—or any ambiguous response—fails closed before publication;
8. only after validation and readiness succeed does a separate narrow dispatch job avoid duplicate active Release runs, recheck current `main`, and dispatch `Release` with exact source SHA, proof run ID and version.

The readiness job isolates the broader credential from actual Release dispatch: it does not publish, create a tag, push a branch, open/merge a PR, or dispatch a valid workflow. The final dispatch job returns to the repository `GITHUB_TOKEN` with only `actions: write` and `contents: read`.

If `main` moves while the handoff is being resolved, or if future protected closure is not currently automatable, the Release request fails closed rather than publishing an immutable version that already requires manual bookkeeping recovery.

## Release validation and source-selection commit point

The final `Release` workflow begins read-only. Before tag/publication authority is used, validation:

1. requires the workflow dispatch on `main` at the exact promoted source SHA;
2. requires `origin/main` still equals that source SHA;
3. validates release-intent subject, requested version and frozen contract;
4. re-verifies permanent exact-SHA gates;
5. verifies the exact successful Trusted Release Proof run;
6. downloads the exact proof artifact;
7. verifies proof receipt and every sealed payload digest;
8. reruns release-contract/payload verification;
9. verifies build provenance for every payload file;
10. refuses an existing version tag bound to another source.

Successful completion is the release source-selection commit point. Later ordinary `main` development does not retarget that already-promoted release attempt.

If a correction is required **before** validation succeeds, merge the correction and let the stale proof/promotion path fail closed. If a correction is discovered after validation succeeds, cancel before publication or publish a subsequent version; never retarget an immutable version tag.

## Tag-last publication

Only the final Release `publish` job receives `contents: write`, behind the `release` GitHub Environment.

Publication:

1. checks out the exact selected source again;
2. redownloads the exact Trusted Release Proof artifact;
3. reverifies sealed bytes and attestations;
4. creates `refs/tags/vX.Y.Z` only if absent, or proves an existing tag points to the same selected source;
5. creates/resumes a draft GitHub Release with title `Linura vX.Y.Z` and frozen `RELEASE_NOTES.md` body;
6. reconciles the draft asset set to the sealed proof payload;
7. verifies every uploaded asset digest;
8. publishes only after the remote asset set is exact.

Promotion/publication never rebuild the payload. The immutable version tag is a publication result of successful proof, not a trigger that grants proof authority.

## Independent publication verification

Release explicitly dispatches `Verify published release` after publication rather than depending on recursive event behavior.

Independent verification:

1. resolves/checks out the published tag;
2. downloads published assets afresh;
3. proves tag commit equals published `SOURCE_SHA`;
4. verifies `RELEASE-EVIDENCE.json`;
5. verifies `SHA256SUMS`;
6. compares GitHub Release body byte-for-byte with published `RELEASE_NOTES.md`;
7. verifies GitHub Release immutability and every published asset attestation;
8. verifies build provenance for every published payload asset;
9. verifies the version-specific expected binary/artifact set, including `linura-authorityd` for v0.6.

GitHub Release downloads are treated as content blobs. Executable mode is not a portable publication property and is not used as release-integrity evidence; file membership, digests, canonical contract verification, release/asset verification and provenance are authoritative.

Publication is incomplete until this independent verification succeeds.

### Emergency verification recovery

The normal release path does not create or require a `verify-release/vX.Y.Z` branch. That namespace is an authenticated emergency path only for an already-immutable release whose frozen verifier is defective after publication.

A recovery run must come from a single-parent marker-only commit under `.github/release-verification-recovery/`, must be based on protected-main ancestry, and must use the verifier definition unchanged from its protected-main recovery base. Post-release closure validates those conditions before accepting recovery verification as terminal evidence and deletes the recovery branch after closure.

Creating or pushing a recovery marker is an explicit repair action; the subsequent workflow run is automatic, but the recovery trigger itself must never be described as automatically created unless repository automation actually created it.

## Post-release closure

Roadmap/current-release state must advance only after immutable publication and independent verification exist. Post-release closure may update machine-readable roadmap status and clean release-temporary branches, but it must not rewrite the published source or tag.

Publication evidence and roadmap closure are therefore ordered:

```text
proof → promotion/readiness → tag-last publication → independent verification → roadmap/cleanup closure
```

On a pending release state, closure re-proves repository-token capability before mutation, generates one deterministic closure tree, verifies that the frozen release contract is byte-identical and that only approved terminal documentation surfaces change, creates or re-proves a single-parent release-scoped closure commit, opens or reuses the exact protected PR, explicitly dispatches/awaits exact-head CI/Security/CodeQL, requires zero unresolved review threads, and immediately before merge re-proves base/head/branch/parent/message identity. It then squash-merges through the normal `main` ruleset, explicitly dispatches/awaits fresh-main CI/Security/CodeQL on the resulting SHA, and only then removes obsolete release-owned and narrowly version-scoped temporary branches not referenced by an open PR.

Post Release Closure is therefore a deterministic machine handoff, not a second semantic review phase. Any human review finding remains blocking if present, but the automation does not depend on a bot-authored `@codex` request that cannot authenticate as the connected human reviewer.

If the release is already terminally closed, the workflow remains idempotent: it skips state regeneration and still performs fresh-main qualification plus safe obsolete release-branch cleanup.

## Traceability policy

Release notes use PR links as default human change provenance. Security-sensitive, migration, recovery, release-control or trust-boundary claims may also include a full-SHA URL where immutable provenance materially improves review.

PR/commit references are provenance, not acceptance evidence. Required exact-source tests remain authoritative for correctness/support claims.

## Claim-scoped qualification

A release must not apply a generic “supported” checklist more strongly than its claim class.

v0.6 remains Experimental and explicitly claims no supported distribution, machine class or hardware profile. Therefore it must prove its bounded authority/security/recovery behavior but must **not** manufacture platform-support evidence it does not claim.

Later releases that declare supported platform/profile/hardware scope additionally require the corresponding VM/profile/hardware, upgrade, recovery and privilege-boundary evidence. The generic [release readiness checklist](operations/release-readiness.md) supplements the version-specific frozen release contract; it never replaces it.
