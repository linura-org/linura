# Trusted release build boundary

Linura separates release authorization, exact-source system qualification, construction of promotable bytes, promotion, immutable publication and independent post-publication verification.

See [ADR 0015 — Isolated and independently reproducible release builds](adr/0015-isolated-reproducible-release-build.md) for the durable builder trust-boundary decision, and [ADR 0023 — Build once, promote exact release bytes](adr/0023-build-once-promote-exact-bytes.md) for the byte-promotion invariant.

## Deterministic stage graph

The release control plane uses one permanent-gate observation boundary followed by explicit authenticated release-stage dispatches:

```text
protected main release intent
  → exact-SHA CI / Security / CodeQL
  → Release Proof Dispatch              # workflow_run observer only
  → Trusted Release Proof               # explicit workflow_dispatch
       → exact-source observation acceptance
       → exact-source Control1 plan-preview acceptance
       → exact-source v0.4 durability qualification
       → exact-source v0.4 real ENOSPC qualification
       → exact-source v0.5 executor/verifier qualification
       → exact-source v0.6 managed-lifecycle qualification
       → Reusable Trusted Release Build # typed workflow_call
       → independent byte reproduction
  → Release Promotion                   # explicit workflow_dispatch
  → Release                             # explicit workflow_dispatch
  → Verify published release            # explicit workflow_dispatch
```

The v0.6 gate is mandatory only for a source/release contract that includes the v0.6 managed-lifecycle claim; on the v0.6 release path it is a direct dependency of the trusted builder and promotion handoff.

`workflow_run` is used only to observe independently completed permanent gates (`CI`, `Security`, `CodeQL`) and wake Release Proof Dispatch. It is not an implicit message bus between release-authority stages. After proof authorization begins, each receiver gets an explicit typed handoff and independently validates source SHA, parent run identity, release contract and current repository state before granting the next capability.

## Exact-source qualification before build

A release artifact is not trustworthy merely because it was built reproducibly. The source's claimed system behavior must first be qualified at the exact release authorization SHA.

For v0.6, Trusted Release Proof must successfully execute the repository-owned permanent system gates, including `.github/workflows/v06-managed-lifecycle-vm.yml`, before the build job can start. That workflow qualifies the bounded `Authority1 → linura-authorityd → Control → root executor → systemd → independent verifier` path plus the deterministic eleven-case fault/recovery matrix.

Development evidence from an earlier PR head does not satisfy this gate after rebase, history compaction or any other SHA change.

## Reusable trusted builder

`.github/workflows/reusable-release-build.yml` is the canonical release builder. The calling proof workflow validates authorization/qualification and delegates build instructions with only the exact source SHA, release tag and version.

The reusable builder:

- runs on the explicit `ubuntu-24.04` runner family rather than moving `ubuntu-latest`;
- installs the repository-pinned Rust toolchain and explicit release target;
- builds with locked dependencies and disabled incremental compilation;
- derives `SOURCE_DATE_EPOCH` from the source commit;
- normalizes timezone and locale;
- remaps the workspace path from Rust debug/build metadata;
- records runner, OS, Rust/Cargo and build-envelope details in `BUILD-ENVIRONMENT.json`;
- constructs the release payload once;
- generates SPDX SBOM and machine-readable release evidence;
- seals all payload bytes with checksums and a proof receipt;
- creates GitHub/Sigstore build-provenance attestations;
- asserts the tracked source tree remains unchanged throughout construction.

This is **repository-owned reusable-workflow provenance hardening**, not SLSA Build Level 3 isolation. The reusable workflow is loaded from the same reviewed source revision as the release candidate, so product code and build instructions can change together. Linura makes no SLSA Level 3 claim from this boundary alone.

## v0.6 distributable binary set

The component maturity contract and release builder must agree on release artifacts. For the v0.6 candidate the distributable binary reproduction set is:

- `linurad`;
- `linuractl`;
- `linura-authorityd`;
- `linura-update-guard`;
- `linura-executor-systemd`.

`linura-firstboot` is **not** a v0.6 release artifact. It remains a `roadmap-scaffold` with activation milestone v0.9 in `contracts/components.toml`. Its historical presence in earlier development/release payloads must not be mistaken for current First Boot maturity.

`linura-authorityd` is a v0.6 release artifact because the bounded managed-effect runtime depends on it. It must therefore be included in sealed payload checksums, SPDX SBOM inputs, provenance, byte reproduction and independent published-release verification.

## Independent reproducibility check

A second fresh runner rebuilds the exact source with the same pinned toolchain, target and deterministic environment. It downloads the sealed proof payload and compares every distributable binary byte-for-byte.

A mismatch fails Trusted Release Proof and prevents promotion. Metadata such as proof receipts and recorded runner environment is intentionally not required to reproduce byte-for-byte; the reproduction qualification applies to distributable binaries.

Reproduction proves build determinism for the declared binaries. It does not replace the system acceptance gates that prove runtime/authority behavior.

## Sealed evidence boundary

The promotable proof artifact binds at least:

- exact source SHA;
- release tag/version and frozen release notes;
- build environment;
- distributable payload;
- SPDX SBOM;
- `RELEASE-EVIDENCE.json`;
- `SHA256SUMS`;
- proof receipt and provenance/attestation material.

Promotion/publication consume these exact bytes. They do not rebuild the release.

## Authority boundary

The reusable builder has no repository-content write permission and no tag/GitHub Release authority. System qualification workflows also do not receive publication authority merely because they can execute privileged actions inside disposable guests.

Promotion can dispatch the final Release workflow but cannot publish. Only the final Release publication job, behind the `release` environment, receives `contents: write` and can create the immutable version tag and publish the already-proven bytes.

## Failure semantics

Any of these conditions fail closed before promotion:

- exact source no longer equals current protected `main` at a required authorization point;
- frozen release contract invalid or inconsistent with workspace version;
- missing/failed exact-SHA permanent gate;
- missing/failed mandatory system qualification;
- tracked source mutation during build;
- SBOM/evidence/checksum/provenance validation failure;
- independent binary reproduction mismatch;
- stale/conflicting release tag identity.

A later green run for a different SHA does not repair the failed release authorization. The new source must enter proof through the normal exact-source chain.
