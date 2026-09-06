# Trusted release build boundary

Linura separates release authorization from the build instructions that produce promotable bytes.

See [ADR 0015 — Isolated and independently reproducible release builds](adr/0015-isolated-reproducible-release-build.md) for the durable trust-boundary decision, alternatives, failure behavior and rollback requirements.

## Deterministic stage graph

The release control plane uses one observation boundary followed by explicit, authenticated release-stage dispatches:

```text
protected main release intent
  -> exact-SHA CI / Security / CodeQL
  -> Release Proof Dispatch              # workflow_run observer only
  -> Trusted Release Proof               # explicit workflow_dispatch
  -> Reusable Trusted Release Build      # typed workflow_call
  -> Release Promotion                   # explicit workflow_dispatch
  -> Release                             # explicit workflow_dispatch
  -> Verify published release            # explicit workflow_dispatch
```

`workflow_run` is used only to observe independently completed permanent gates (`CI`, `Security`, `CodeQL`) and wake `Release Proof Dispatch`. It is not used as an implicit message bus between release-authority stages. After proof authorization begins, each receiver gets an explicit typed handoff and independently validates the source SHA, parent run identity, release contract and current repository state before granting the next capability.

## Reusable trusted builder

`.github/workflows/reusable-release-build.yml` is the canonical release builder. The calling proof workflow validates authorization and then delegates build instructions to that reusable workflow with only the exact source SHA, release tag and version.

The reusable builder:

- runs on the explicit `ubuntu-24.04` runner family rather than the moving `ubuntu-latest` alias;
- installs Rust 1.98.0 and targets `x86_64-unknown-linux-gnu` explicitly;
- builds with locked dependencies and disabled incremental compilation;
- derives `SOURCE_DATE_EPOCH` from the source commit;
- normalizes timezone and locale;
- remaps the workspace path from Rust debug/build metadata;
- records the runner, operating system, Rust/Cargo and build-envelope details in `BUILD-ENVIRONMENT.json`;
- constructs the release payload once, seals it with checksums and release evidence, and creates GitHub/Sigstore build-provenance attestations;
- asserts the source tree remains unchanged throughout the build.

This is **repository-owned reusable-workflow provenance hardening**, not SLSA Build Level 3 isolation. The reusable workflow is loaded from the same reviewed source revision as the release candidate, so the candidate can change both product code and build instructions together. Linura therefore makes no SLSA Level 3 claim from this boundary alone. Reaching that stronger trust model would require a separately governed builder definition referenced immutably, in addition to the evidence already collected here.

## Independent reproducibility check

A second fresh `ubuntu-24.04` job rebuilds the exact source with the same pinned toolchain, target and deterministic environment. It downloads the sealed proof payload and compares each distributable binary byte-for-byte:

- `linurad`
- `linuractl`
- `linura-update-guard`
- `linura-executor-systemd`

The current artifact set is governed by `contracts/components.toml`; future scaffolds such as `linura-firstboot` are not distributable merely because they are Cargo workspace members.

A mismatch fails Trusted Release Proof and prevents promotion. Metadata such as the proof receipt and recorded runner environment is intentionally not required to reproduce byte-for-byte; the qualification applies to the distributable binaries.

## Authority boundary

The reusable builder has no repository-content write permission and no tag or GitHub Release authority. Promotion can dispatch the final Release workflow but cannot publish. Only the final Release publication job, behind the `release` environment, receives `contents: write` and can create the immutable version tag and publish the already-proven bytes.
