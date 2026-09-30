# Development infrastructure

Linura treats development infrastructure as part of the product safety boundary. The same repository-owned commands should be used locally, in CI, in VM acceptance, and in release proof whenever practical.

## Canonical entry point

```bash
cargo xtask check
```

This executes formatting, Clippy, workspace tests, repository invariants, and structured asset validation. Additional commands expose acceptance scenarios and build plans without requiring contributors to memorize implementation-specific scripts.

## Deterministic Codex/cloud environment

Codex Cloud environments are external execution containers, but Linura keeps their repository-owned setup contract in version control so delegated tasks do not depend on ad-hoc `latest` installs.

The canonical environment-creation command is:

```bash
bash scripts/setup_codex_environment.sh
```

The setup script:

- requires a **glibc-based Linux x86_64 host with glibc >= 2.17** and the repository-declared Python major/minor;
- requires basic host primitives already available, including Bash, curl, Git, SHA-256 tooling, tar, `getconf`, and a working C compiler/linker exposed as `cc`;
- intentionally rejects musl-only hosts such as a default Alpine environment because the pinned bootstrap and Rust toolchain target are `x86_64-unknown-linux-gnu`;
- honors a caller-provided `CARGO_HOME`; when unset it uses `$HOME/.cargo`, and it exposes that exact Cargo home `bin` directory on `PATH`;
- never uses `apt install`, Homebrew, or an unversioned language/tool installer;
- bootstraps exactly rustup 1.28.2 from its versioned GNU `rustup-init` archive and verifies the repository-pinned SHA-256 before execution, so the Codex base image does not need to ship Rust or rustup;
- disables rustup automatic self-updates, sets the rustup default host to `x86_64-unknown-linux-gnu`, installs and selects exactly `1.98.0-x86_64-unknown-linux-gnu`, and re-verifies both rustup and the active fully qualified toolchain after installation;
- installs the exact Rust language version declared by both `rust-toolchain.toml` and `tools/codex/versions.env`, including rustfmt and Clippy, while the setup contract fixes the host triple independently;
- installs exactly `cargo-audit` 0.22.2 with Cargo's locked install mode; this source build uses the host-provided `cc` linker;
- downloads exactly actionlint 1.7.12 and verifies the same SHA-256 used by CI before extracting it;
- fetches only the locked Cargo dependency graph;
- fails if setup changes tracked repository state.

The canonical task-time preflight is:

```bash
bash scripts/preflight_codex_environment.sh
```

Use `--full` when a task should also run the complete `cargo xtask check` quality gate during preflight. The normal preflight is intentionally non-installing and non-mutating: it verifies host architecture, glibc >= 2.17, `cc`, Python major/minor, the exact rustup version, the exact fully qualified GNU Rust toolchain, cargo-audit, actionlint, offline locked Cargo metadata, workflow semantics and clean tracked state. A mismatch is reported as an environment defect rather than repaired during delegated implementation.

Repository-owned versions and integrity pins are declared in `tools/codex/versions.env`. Changing those pins is a reviewed development-infrastructure change and should remain aligned with CI/release tooling where the same tool is security-relevant.

The Codex product-side environment still has to be created/selected for `linura-org/linura`; the repository cannot create that account-level object by committing a setup script. Configure that environment to execute the canonical setup command during environment creation. The selected base image must satisfy the glibc >= 2.17 and `cc` prerequisites above. Setup-phase network access should be narrowly allowed for the pinned tool and dependency upstreams, including:

- `static.rust-lang.org` for the pinned rustup bootstrap and Rust toolchain;
- `index.crates.io`, `static.crates.io`, and `crates.io` for locked Cargo dependencies and the pinned cargo-audit install;
- `github.com` and GitHub release-asset hosts required to fetch the pinned actionlint release.

Ordinary delegated implementation should begin with the preflight and should not install, update or substitute tool versions. Once setup has warmed the locked Cargo graph, the normal preflight and `--full` verification are designed to run without dependency mutation; task-time internet access is not a substitute for a correctly provisioned environment.

## Layers

```text
source + schemas
      ↓
 cargo xtask
      ↓
unit / contract / adversarial tests
      ↓
image and disposable-VM harnesses
      ↓
hardware and visual evidence
      ↓
exact-SHA release candidate
      ↓
promotion + post-publication verification
```

Repository tooling must fail clearly when host capabilities such as QEMU, KVM, mkarchiso, SSH, or ImageMagick are unavailable. Missing host tooling is not silently treated as passing system evidence.

## Development invariants

- no privileged shell script is the canonical system contract;
- all host-mutating behavior must eventually cross typed Linura authority boundaries;
- system-image/bootstrap/update tooling must be restartable or explicitly recoverable;
- platform-specific code stays under platform/provider/executor boundaries;
- generated artifacts and fixtures are versioned and machine-readable;
- CI actions are pinned to immutable commit SHAs;
- delegated/cloud development environments use repository-owned pinned tool contracts rather than task-time latest-version installation;
- release bytes are built once and promoted, not rebuilt during publication.

The Arch image harness stages from ArchISO's `releng` profile and overlays Linura additions instead of pretending a sparse custom profile is independently boot-complete.

## Workstation live acceptance

The v0.10 workstation has a separate acceptance helper rather than extending the generic `tools/vm.py` into a second workstation authority. `qualification/v010/shell-runtime/start-vm.sh` remains the bounded owner of the exact Arch/virtio-GPU topology and supports two modes: deterministic automated/headless execution and opt-in interactive GTK or loopback VNC display. The interactive launcher and automated CI both consume the same substrate/runtime contracts.

Use `python3 tools/workstation_acceptance.py plan --mode <automated|interactive|hardware>` to inspect the selected lane before execution. Recording is performed in the guest/session Wayland environment and verified independently; host display transport is presentation only.
