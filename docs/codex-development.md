# Codex development across Linura

Codex can contribute to every repository area through the same reviewed contracts
and canonical gates as other contributors. Repository preparation makes the tools
discoverable; it does not grant production access, publish evidence, certify a
physical workstation, or increase an agent's authority.

## Prepare the environment

Configure these commands in the environment's setup and maintenance fields:

```bash
bash scripts/setup_codex_environment.sh --bindings
bash scripts/maintain_codex_environment.sh --bindings
```

Both resolve the repository root from their own path. Maintenance reruns the
idempotent pinned setup for the selected checkout, fetching its locked Cargo
graph. Core setup also provisions the repository-pinned, hash-locked Ruff
environment used by the canonical gate. The optional `--bindings` additionally
installs the existing hash-locked Python build requirements, including pip, into
`$HOME/.local/linura-tools/python`; neither environment changes the host Python.
Every bindings setup/maintenance pass clears and recreates that isolated build
environment before installing from the hash-locked requirements.
This intentionally discards undeclared packages and partially installed caches;
the doctor checks the lock digest and exact installed distribution set. No
task-time installer, `latest` tool selection, shell
startup-file modification, or repository credential is needed.

The environment owner must supply Linux x86_64, glibc >= 2.17, Python 3.12 with
venv support, Bash, curl, Git, SHA-256 tooling, tar, a working C linker, and the
standard text tools used by the scripts. Setup provisions the declared rustup,
Rust, rustfmt, Clippy, cargo-audit, actionlint and Ruff versions. Configure setup-phase
network access to the tool/dependency origins listed in
[development infrastructure](development-infrastructure.md), including `pypi.org`
and `files.pythonhosted.org` for the hash-locked Ruff wheel and optional binding
build environment. Task-phase offline Cargo checks
remain possible after preparation. A fresh security audit needs a current RustSec
advisory database and its own network access; cached dependency availability is
not a fresh security audit.

Use only the minimum repository/app permissions needed for the assigned task.
GitHub access, account-level environment selection, network policy, base-image
packages and external runners are operator configuration. Committing these files
cannot activate those settings. Do not add production, release, R2, personal SSH,
or fleet credentials to an ordinary coding environment.

## Inspect capabilities before work

```bash
python3 tools/codex/doctor.py --all
python3 tools/codex/doctor.py --profile shell --profile bindings --json
bash scripts/preflight_codex_environment.sh
```

The doctor aggregates missing and incompatible prerequisites instead of stopping
at the first missing tool. It performs bounded, non-installing probes and emits
only named check results and fixed remediation text. It always includes the core
profile. Nonzero status means the selected readiness profile is incomplete.
`--all` inventories all profiles, including the separate Arch image-builder
requirements; an Ubuntu coding container is not expected to be an Arch builder.
The JSON report explicitly sets `qualification_evidence` to false.

The strict preflight also validates workflow semantics, exact active GNU Rust
toolchain, rustfmt/Clippy availability, and the locked offline dependency graph.
It compares tracked source, index entries and HEAD before and after verification.
Existing work-in-progress edits are preserved and accepted; a check that changes
that state fails. This verifies non-mutation rather than requiring every task
checkout to remain clean. Untracked output is outside this tracked-source check.
Setup uses the same invariant. A task may diagnose a mismatch and run independently
available checks, but must report blocked gates and must not silently install or
substitute tools to make them appear passing.

## Work and verify

Setup exports do not persist into every task shell. The explicit wrapper exposes
the configured Cargo home and local tools without editing shell startup files:

```bash
bash scripts/run_codex.sh cargo xtask check
bash scripts/run_codex.sh cargo test --locked -p linura-control
bash scripts/run_codex.sh python3 -m unittest discover -s tests/tooling -p 'test_*.py'
```

The wrapper forwards argument arrays directly and keeps the caller's permissions.
It is developer tooling, not a product execution interface. It resolves the
repository root so these commands also work when invoked by absolute path from
a nested directory. Scoped `AGENTS.md` files route specialized work to existing
task guides; root instructions and explicit user scope still apply.

| Area | Readiness profile | Verification and limits |
| --- | --- | --- |
| Rust domain/control, adapters, SDK, executors, verifiers | `core` | `cargo xtask check`; affected crate tests and authority/adversarial guides |
| Tooling, contracts, schemas, documentation, workflows | `core` | Repository validators, tooling tests and pinned actionlint; Security and CodeQL remain separate CI gates |
| Qt/QML shell and shared UI | `shell` | CMake >= 3.24, C++20 compiler and Qt >= 6.4 Core/DBus/Qml/Quick/QuickControls2 development packages; build both CMake projects, then the graphical qualification lane |
| Python binding/build | `bindings` | Binding tests with `PYTHONPATH=bindings/python/src`; hash-locked isolated wheel build below |
| Disposable guests | `vm` | Preserve `python3 tools/vm.py doctor`; QEMU/SSH and exact image/profile/source evidence; KVM optional where the lane permits TCG |
| ArchISO packaging | `image` | Separately provisioned Arch builder, mkarchiso/releng and shell build dependencies; `python3 tools/image.py doctor` before real builds |
| Visual comparisons and recordings | `visual` | ImageMagick compare and FFmpeg/ffprobe prerequisites; real capture/comparison/interaction evidence remains required |
| Physical Level C | External maintained workstation | Enrollment, fixture/GPU/display/input/accessibility and independent Q11 evidence; a cloud container or VM cannot satisfy this |

The inventory checks prerequisite availability, not complete support of arbitrary
QEMU topologies, FFmpeg codecs, GPU drivers, C++ features, running compositors,
Quickshell imports or session services. Those are proved by the applicable real
builds and qualification workflows. Never install a second unpinned desktop stack
in a coding container as a substitute for the pinned graphical guest substrate.

Build the Python wheel offline after `--bindings` setup:

```bash
"$HOME/.local/linura-tools/python/bin/python3" -m pip wheel \
  --disable-pip-version-check --no-index --no-deps --no-build-isolation \
  --wheel-dir .artifacts/python-wheel ./bindings/python
```

## Account-side integration acceptance

Repository scripts cannot enable Codex, install its GitHub integration, select a
cloud environment for this repository, or grant review/write permissions. The
operator must confirm the following separately before claiming end-to-end Codex
compatibility:

1. Select the intended Codex environment for `linura-org/linura`; configure its
   setup and maintenance commands above, its base-image prerequisites and the
   narrow setup-phase network policy. Confirm a new task runs preflight and the
   canonical offline gate in a separate task shell.
2. Confirm the connected GitHub integration can read the assigned pull request,
   submit review findings and, only when authorized, update its existing head
   branch. Preserve native branch protections and the user's PR scope.
3. On a disposable draft PR, test the actual review-and-address flow: request a
   review, observe comments tied to the current head, address findings on the
   *same* PR, verify thread resolution, then request a new exact-head review
   after gates pass. Confirm the workflow neither creates a duplicate PR nor
   treats old-head feedback as a review of new code.
4. Check any specialized shell, VM, Arch image or physical qualifications in
   their actual supported environment. Readiness diagnostics and a passing
   Ubuntu coding-container job do not substitute for these executions.

These are operator acceptance steps, not CI assertions. Product-side review,
feedback and address controls depend on the Codex/GitHub connection and its
permissions; adding `AGENTS.md` guidance or making setup succeed does not make
those controls available by itself. Do not add a broad repository-write token
or production credentials to make an unavailable control appear functional.

## Required validation gates

`cargo xtask check` is canonical, but `cargo-audit` and Rust CodeQL are
separate native checks and must also succeed on the exact PR. Inspect
`python3 tools/check_validation_gates.py --json` for the machine-readable
critical-path routing inventory; readiness is not qualification evidence.
The stdlib-only routing checker decodes supported quoted YAML control keys and
rejects unsupported escapes, noncanonical mapping keys, YAML merges, anchors,
aliases, tags and explicit mapping syntax in audited workflows; executable shell
blocks remain opaque. Action `uses` values in audited workflows must be
inline scalars: folded, literal, tagged, anchored, aliased or absent
references are rejected rather than silently omitted from the exact-source
audit. Quoted inline action references are decoded and canonicalized before
counting checkouts, including escape sequences that otherwise conceal a second
checkout. All protected specialized qualification lanes reject inherited run
defaults, and required jobs prohibit unapproved step-shell overrides.
Required qualification steps reject arbitrary conditions and failure suppression;
only explicitly reviewed cleanup, v0.9 full-lane and reusable v0.10
cache-miss conditions are accepted.
A new subsystem must update its qualification routing instead of accepting
an omitted trigger as success.

## Review and handoff

The [canonical pull-request qualification sequence](development-infrastructure.md#pull-request-qualification-sequence) is the single source for stage order. During implementation, perform a **regression-impact review** of existing consumers, assertions, tests, fixtures and qualification routes. Complete the architecture/code/adversarial **internal-review record** in the PR template before compacting; an unchecked item or unavailable gate stays pending, and a checkbox is not qualification evidence.

Implement → internal architecture/code/adversarial review → fix findings → compact
to one clean commit → run full gates → request Codex review → fix genuinely new
findings → merge only when green. A missing dependency or unexecuted gate is
reported as blocked, not passed. Keep existing PRs untouched unless assigned.
Use a draft while required validation is incomplete; do not request final Codex
review or merge on incomplete evidence.

The fresh-environment CI lane exercises setup, maintenance, a separate task
process, the offline canonical gate and the offline Python wheel build in an
isolated home. It supplements canonical CI, Security, CodeQL and the applicable
VM/graphical gates; it replaces none of them.

Official guidance: [AGENTS.md discovery](https://developers.openai.com/codex/guides/agents-md)
and [Codex Cloud setup and maintenance](https://developers.openai.com/codex/cloud/environments).
Keep root and scoped instructions small enough for the configured discovery
budget; guides linked from them must be read when their area is changed.
