# Development infrastructure

Linura treats development infrastructure as part of the product safety boundary. The same repository-owned commands should be used locally, in CI, in VM acceptance, and in release proof whenever practical.

## Canonical entry point

```bash
cargo xtask check
```

This executes Rust formatting, the pinned Ruff Python correctness baseline, Clippy, workspace tests, repository invariants, and structured asset validation. Additional commands expose acceptance scenarios and build plans without requiring contributors to memorize implementation-specific scripts.

## Editor and Python analysis baseline

VS Code recommendations are repository-owned in `.vscode/extensions.json`: rust-analyzer for Rust, the Microsoft Python/Pylance pair for Python language intelligence, and Ruff for Python lint/format integration. `.vscode/settings.json` contains only project-relevant behavior; personal UI preferences and other workspace state remain ignored. Editor diagnostics are convenience feedback and never replace repository gates.

The language-specific rulers are tiered review guides rather than new compiler semantics:

- Rust uses columns **100 / 120 / 140**: rustfmt-aligned primary width, extended review boundary, then an exceptional-line boundary.
- Python uses columns **88 / 100 / 120**: Ruff formatter-aligned primary width, extended review boundary, then an exceptional-line boundary.

Rust formatting runs on save because rustfmt is already a canonical gate. Python formatting stays explicit so adopting Ruff does not silently rewrite the existing tooling corpus; Ruff lint diagnostics are still active in the editor and `ruff check .` is enforced by `cargo xtask check`.

The canonical Ruff version is pinned in `tools/codex/versions.env` and installed from `tools/python/ruff-requirements.lock` with hashes. `ruff.toml` selects `E4`, `E7`, `E9` and `F` explicitly instead of inheriting Ruff's changing default rule set. Repository tooling targets the canonical Python 3.12 host while `bindings/python/**` is checked against its public Python 3.10 minimum. This starts with high-signal Python correctness and compatibility checks; broader style/security categories should be adopted deliberately with a clean migration rather than appearing implicitly after a tool upgrade.

Pylance runs basic workspace analysis for interactive feedback, but Linura does **not** yet have a repository-enforced Python type checker. Before type checking becomes a required gate, evaluate **Pyright versus mypy** against the real scripts, tooling, qualification code and Python binding, then choose one canonical checker and migration plan. Do not make both mandatory by default and create competing diagnostic standards.

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
- installs exactly Ruff 0.16.10 into an isolated environment from the repository hash-locked wheel contract and exposes only that reviewed binary on the development PATH;
- fetches only the locked Cargo dependency graph;
- fails if setup changes tracked repository state.

The canonical task-time preflight is:

```bash
bash scripts/preflight_codex_environment.sh
```

Use `--full` when a task should also run the complete `cargo xtask check` quality gate during preflight. The normal preflight is intentionally non-installing and non-mutating: it verifies host architecture, glibc >= 2.17, `cc`, Python major/minor, the exact rustup version, the exact fully qualified GNU Rust toolchain, cargo-audit, actionlint, offline locked Cargo metadata, workflow semantics and unchanged tracked source/index state (existing task edits are allowed). A mismatch is reported as an environment defect rather than repaired during delegated implementation.

Repository-owned versions and integrity pins are declared in `tools/codex/versions.env`. Changing those pins is a reviewed development-infrastructure change and should remain aligned with CI/release tooling where the same tool is security-relevant.

The Codex product-side environment still has to be created/selected for `linura-org/linura`; the repository cannot create that account-level object by committing a setup script. Configure that environment to execute the canonical setup command during environment creation. The selected base image must satisfy the glibc >= 2.17 and `cc` prerequisites above. Setup-phase network access should be narrowly allowed for the pinned tool and dependency upstreams, including:

- `static.rust-lang.org` for the pinned rustup bootstrap and Rust toolchain;
- `index.crates.io`, `static.crates.io`, and `crates.io` for locked Cargo dependencies and the pinned cargo-audit install;
- `github.com` and GitHub release-asset hosts required to fetch the pinned actionlint release;
- `pypi.org` and `files.pythonhosted.org` for the hash-locked Ruff wheel and, when requested, the hash-locked Python binding build environment.

Ordinary delegated implementation should begin with the preflight and should not install, update or substitute tool versions. Once setup has warmed the locked Cargo graph, the normal preflight and `--full` verification are designed to run without dependency mutation; task-time internet access is not a substitute for a correctly provisioned environment.

For the repository-wide capability inventory, cached-environment maintenance,
explicit task PATH wrapper, scoped guidance and hash-locked Python build profile,
see [Codex development](codex-development.md). The fresh-environment CI lane
exercises these commands from an isolated home and supplements the existing gates.

## CI and qualification routing

`python3 tools/check_validation_gates.py --json` produces a machine-readable
critical-path routing inventory and runs under `scripts/check_repository.py`.
It protects the three mandatory, unfiltered native PR and main gates:
`canonical-check` (`cargo xtask check`), `dependency-audit`
(pinned `cargo-audit` with current advisory data) and `analyze` (Rust CodeQL).
It also fails when mapped critical sources lose the Codex, disposable-VM,
v0.4 durability/ENOSPC, v0.5 executor/verifier, v0.6 managed-lifecycle,
v0.7 Library, v0.8 agent, v0.9 First Boot or v0.10 workstation
qualification trigger, or the exact-source VM/workstation assertion.
It also ensures trusted release proof retains all inherited v0.4–v0.9
qualification jobs in its isolated-build dependencies and success-gated
release-promotion chain.
Changes to the shared validator and its tests trigger the v0.9 qualification
workflow as well.
The private-R2 evidence-publication verification lane is likewise registered as
a protected specialized workflow. Changes to its publisher, policy contract,
admission code, tests, threat model or routing validator must trigger its
scoped check on both PRs and main pushes; its verification job and executable
test command cannot be silently removed or skipped. That workflow selects its full or exact-source regression lane
from `contracts/v09-qualification-routing.toml`; ordinary Codex-only changes
do not implicitly qualify an untouched v0.9 runtime. Shared authority, policy,
protocol, provider SDK, agent runtime, Library, lifecycle, D-Bus transport,
firstboot-offline VM clients (linurad, linuractl and linura-sdk),
observation, persistence, executor/verifier, toolchain and Cargo configuration changes, and recovery changes,
as well as changes to the acceptance runner, v0.9 adversarial guest harness,
either recognized Cargo configuration file (`.cargo/config` or
`.cargo/config.toml`) or the compiled-in WirePlumber audio helper require
full v0.9 VM/adversarial qualification. In the firstboot-offline VM lane,
the production authority daemon is built and unit-tested, installed with
host/guest digest and size equality, and exercised on a deliberately invalid
state directory to prove fail-closed startup. Its binary identity is bound
into the full v0.9 evidence. This narrow startup check is not a claim
of full managed-lifecycle or privileged execution qualification.
The central routing
validator also ensures that every contract-declared full-impact source retains
an actual PR workflow trigger. Pure AGENTS/README guidance changes remain on
the fast regression lane, but mixed guidance and implementation changes cannot
skip the full qualification lane.

Follow the S16 tiered model: mandatory canonical CI, Security and CodeQL run
on each PR revision; path-scoped qualification runs when affected implementation
or contract files match, and v0.9 selects full VM/adversarial versus bounded
regression according to its reviewed impact contract. The v0.10 shell workflow
deliberately excludes only `apps/linura-shell/AGENTS.md` and its README from
expensive shell qualification; an actual QML, CMake, workflow, contract, or
qualification-harness change still triggers the runtime, even when mixed with
guidance edits. GitHub's ordered negative path filters are checked against
critical positive sources. An updated final PR head must pass every applicable
gate; results from superseded commits are not qualification evidence. Trusted
release proof independently executes the complete inherited machine suite.

The legacy constants in `tools/check_validation_gates.py` remain an independent
minimum anti-drift guard. The exhaustive PR routing authority is
`contracts/qualification-gate-matrix.toml`, verified by
`tools/applicable_qualification.py`. It classifies every execution lane, component, top-level TOML contract, and
public contract registered by `contracts/stability.toml` (including JSON
schemas), and requires its ordered path rules to match the executable
specialized workflow filters. New active components or registered contracts
fail closed until explicitly routed or deliberately classified as native-only.

The event-driven `Applicable qualification` workflow derives the exact gate
set for every PR revision and accepts only GitHub `pull_request` workflow runs
bound to the same PR and exact head SHA. Trusted default-branch
`pull_request_target` (including `closed`), native `workflow_run`, and
protected `main` push events reconcile one fail-closed status on each affected
contributor head SHA across every open PR sharing that SHA.
Native and specialized runs require the current PR's exact head/base identity;
the diagnostic Actions status writers serialize by deterministic SHA-prefix shard
across all event kinds, invalidating every affected head before fallible
PR checks. They then recheck live runs immediately before publishing success. The reconciler rechecks both identities immediately before
publication, preventing same-head PRs or a concurrent base update from sharing
authorization. The write-capable job never checks out PR-head code and never polls for hours
while occupying a hosted runner. It verifies reviewed job identities for every
applicable gate and independently enforces the v0.9 full-versus-regression job
group using the same routing contract as the v0.9 workflow. Missing or running
gates leave the status pending; skipped, cancelled, failed, timed-out, stale or
dispatched substitutes fail it. Pure routing-authority edits are validated
statically and must not fan out to every specialized VM lane. The Actions-authored `applicable-qualification` commit status is
**diagnostic only**, not a merge authority: same-repository PR workflows can
forge that context with `statuses: write`. The protected `main` ruleset
must continue to require `canonical-check`, `dependency-audit`, and
`analyze` independently, with strict up-to-date branch protection. Only
**after** the isolated GitHub App is deployed and the real adversarial,
shared-head, stale-success and ruleset acceptance in
`docs/qualification/trusted-publisher.md` passes may the ruleset
add the **App-owned** `linura/applicable-qualification` Check Run pinned
to its dedicated integration ID. Never require the diagnostic Actions
status, the same-named check from GitHub Actions, or `Any source`.
Path-filtered specialized workflows remain non-required globally;
the trusted App verifies their exact-head applicability. Missing
physical/visual/VM evidence remains blocked, never passed.
## Dependency-input caching

Canonical CI follows the same cache-authority boundary as the prepared v0.10 runtime substrate: caches accelerate immutable prerequisites but never become correctness authority. Repository-owned composite actions may retain Cargo registry/git inputs and Ubuntu package payloads only. Cache identities bind the reviewed implementation plus exact dependency/toolchain or runner-package resolution state; broad restore keys are forbidden.

Linura source, Cargo `target/` outputs, QML/CMake build trees, qualification evidence, and runtime binaries are always rebuilt or regenerated from the exact checked-out source. Ubuntu payload caches live under `runner.temp`, are installed through normal APT signed-index resolution, and requested packages are rechecked against their exact candidate versions after installation.

The machine-readable policy is `.github/actions/dependency-input-cache-policy.toml`. The anti-drift policy is executable in `tools/check_ci_cache_policy.py` and adversarially covered by `tests/tooling/test_ci_cache_policy.py`. Both composite-action source files have reviewed SHA-256 fingerprints in that checker: an edit to executable shell semantics (including inert here-document or unreachable-branch decoys) is rejected until the action is explicitly audited and its fingerprint intentionally updated. These reviewed-source fingerprints are separate from runtime cache keys.

The canonical CI job and step structure is also verified: conditional, skipped or failure-suppressed builds and checks cannot silently satisfy the policy. The QML source-build script has its own reviewed fingerprint; ordinary unrelated CI changes do not require re-pinning it. A fingerprint update requires a deliberate code and adversarial review, not automatic acceptance.

Cache bytes are untrusted: the cache service does not sign the stored content. APT validates package integrity against signed repository metadata during normal installation, while Cargo continues to enforce the lockfile and crate checksums. Pull-request caches are scoped to their merge refs and do not automatically accelerate unrelated PRs; a trusted default-branch run can warm shared inputs.

The routing report sets `qualification_evidence` to false. Qualified records
must independently bind the exact source SHA, environment/image and toolchain,
configuration, results and artifact digests. The existing isolated release
build and independent reproduction process governs release-byte identity.
Normal CI is not fully bit-reproducible: hosted OS packages and advisory data
can change, so a version-pinned runner alone is not immutable. Fresh security
audits remain deliberately time-dependent; offline Cargo metadata is not one.


## Qualification execution envelopes

`contracts/qualification-execution-envelopes.toml` is the reviewed inventory
of qualification lanes that require execution-context identity.
`python3 tools/qualification_envelope.py validate` is invoked by the canonical
repository checker, while the tooling tests run under `cargo xtask check`.

Envelope creation requires the exact checked-out source and verifies every
repository-controlled input against the Git blob at that source commit. Runner
identity includes kernel, OS-release digest, installed-package manifest,
architecture and virtualization; GitHub-hosted lanes additionally bind the
published runner image identity. Maintained physical execution fails closed
when virtualization is detected. Cache bytes must be independently hashed
before they can enter an envelope, and a cache hit never counts as
qualification.

The envelope SHA-256 is a stable content identity, not a signature or pass
receipt. Accepted evidence and release proof must independently bind the
envelope digest and their own results/artifacts. RustSec advisory identity and
retrieval time remain variable observations so security freshness is never
frozen for reproducibility.

## Qualification evidence binding

Execution identity and evidence acceptance are deliberately separate contracts.
The execution-envelope layer may create runner/guest/aggregate envelopes and
execution-component manifests, but it must not add acceptance fields to
qualification or release receipts. The evidence-binding layer consumes verified
envelopes, independent verifier results, reviewed test/contract IDs and retained
artifact bytes.

`contracts/qualification-evidence-binding.toml` pins the execution-envelope
schema and must classify every envelope lane exactly once. Each evidence-bearing
profile selects a reviewed semantic verifier adapter; the adapter derives pass,
environment verification, test/contract conclusions and verified claims from
retained proof material rather than trusting the producer's pass receipt. The
canonical repository checker runs both validators, so a change to the execution
lane inventory cannot silently drift past evidence acceptance.

After semantic verification and byte binding, the admission action creates a
deterministic `qualification-evidence.tar`, verifies that sealed object, and
uploads that exact tar internally. Workflow-level success uploads of the mutable
artifact directory are forbidden. Failure diagnostics use a separate
`failure()`-gated, explicitly unqualified artifact name. Downstream release
machinery structurally verifies and unseals the accepted tar before consuming
its files; publication and release authority remain separate.

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


## Pull-request qualification sequence

Safety-sensitive Linura work follows one review sequence rather than using external review as the first debugging pass. During implementation, perform a **regression-impact review**: search existing callers, consumers, tests, fixtures, contracts and qualification routes for assumptions that the change affects. Reconcile old expectations deliberately, preserve valid guarantees and add positive, negative and adversarial cases. For example, a routing-policy change must inspect *all* existing tests of the previous policy, not just add tests for the new policy. Never delete or weaken an inconvenient test merely to obtain a green result.

Before compaction, finish a concise **internal-review record** in the PR template covering architecture/ownership, code and API consequences, security and adversarial cases, regression impact and the applicable native and specialized gate inventory. Document meaningful exceptions or blocked evidence; a checked box is a human attestation, not independent proof. Routine documentation-only changes need a proportionate review.

```text
implement
→ internal architecture/code/adversarial review
→ fix every valid finding
→ compact to one coherent clean commit
→ run the full inherited + milestone gate set
→ request Codex review
→ fix only genuinely new valid findings
→ merge only when required checks are green
```

Compaction changes the source SHA, so exact-source qualification must run after the final compaction. If Codex identifies a genuinely new defect, fix it, recompact and rerun the applicable exact-head gates before merging. Do not request final review on an incomplete or red head; do not add routine progress comments to PR history. The repository-owned development-workflow checker keeps the root/scoped agent instructions, contributor guidance and PR template aligned with this sequence, but cannot prove that a human review happened. Review comments are resolved only after the underlying issue is fixed, and a green result must never be obtained by weakening a contract, deleting adversarial coverage, or reclassifying missing evidence as passing.

## Graphical qualification platform and fleet boundary

The repository-owned A/B/C acceptance system is the execution/evidence contract. A future graphical qualification platform such as `qualification.linura.org` is an observability/control surface over that contract, while the graphical qualification fleet is the set of actual automated VM, interactive VM and maintained physical runners. Neither a web UI nor a fleet controller may invent qualification success, widen runner authority, or substitute a VM for Level C.

A fleet is valid with one maintained physical workstation; scale is not part of the trust claim. Public live viewing or a disposable public demo environment must remain observational or sandboxed and cannot inject input into an automated A run or a release-qualifying C run. Privileged fleet/admin control is a separate authority surface from public viewing.


Envelope-bound evidence admission is defined by contracts/qualification-evidence-binding.toml. Reviewed semantic adapters, required artifact inventories, exact artifact-set digests, deterministic sealed uploads, and verifier/binder provenance fail closed before a result can be accepted; publication and release authority remain separate.
