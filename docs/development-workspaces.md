# Development workspaces and storage

Keep Linura's Cargo workspace and shared development contracts in this repository.
Keep machine-specific instances, credentials and large generated state outside
Git. A directory layout is not an environment specification or qualification
claim: tools, operating-system packages and required capabilities still need the
repository's reviewed pins and checks.

The dedicated-storage boundary and its staged rollout are recorded in
[ADR 0043](adr/0043-dedicated-development-and-qualification-storage.md).

Start with [contributing](../CONTRIBUTING.md), then use
[development infrastructure](development-infrastructure.md) for gates,
[environment preparation](codex-development.md) for setup/preflight and readiness
profiles, and [source formatting](source-formatting.md) for exact formatter rules.

## Source, specifications and local state

| Material | Ownership and retention |
| --- | --- |
| Cargo manifests, source, contracts, lockfiles, shared `.vscode` settings | Version-controlled in the existing repository |
| Environment recipes, dependency/tool pins, capability checks, CI commands | Repository-owned and reviewed; reuse the selected checkout's specification |
| Task worktrees and personal multi-root editor files | Persistent local storage; one assigned task/branch per worktree |
| Cargo/CMake outputs, disposable VM copies, temporary files | Generated local state; remove only exact inactive targets after inspection |
| Recovery bundles, uncommitted-work archives, retained evidence and recordings | Protected persistent storage with independent backup/retention rules |
| Credentials and production access | Protected credential facilities; not Git, shared caches, ordinary coding containers or agent scratch |

`.gitignore` prevents accidental tracking, not disk consumption, access or deletion.
An ignored recording, private key or database is not automatically safe to purge.
Do not add another source repository or duplicate the Cargo workspace to solve an
environment problem.

## Persistent worktrees

Use a durable directory, not `/tmp`, for a task expected to survive reboot or
cleanup. For example:

```text
~/dev/
  linura/                       primary repository and common Git metadata
  linura-platform/              separate website repository, if used
  linura-worktrees/
    development-workspaces/     one task/branch
    s17/                       another task/branch

~/linura-recovery/              protected interim recovery, not a worktree
```

These are examples, not paths every developer must create. Existing separate
clones can remain until their local work is verified and backed up; do not move,
remove or rebase an active task as incidental cleanup.

Keep recovery logically outside the worktree collection. Existing verified
copies under a legacy worktree/recovery directory remain protected: changing this
recommendation does not authorize moving or deleting them. A future relocation
requires a private destination, independently checked checksums/bundle integrity,
an explicit retention decision, and an off-machine copy for critical backups.

For a new task, from the primary repository:

```bash
git --no-optional-locks status --short
git worktree list --porcelain
git fetch origin main
mkdir -p ../linura-worktrees
git worktree add -b docs/my-task ../linura-worktrees/my-task origin/main
code ../linura-worktrees/my-task
```

Choose a unique branch and directory for the assigned scope. Opening the active
worktree's root in VS Code uses that checkout's shared `.vscode` settings; do not
have unrelated tasks switching branches in one editor/agent checkout. A personal
`.code-workspace` is optional and should not contain team-wide absolute paths.

Git worktrees share repository objects, most references and repository
configuration. They are checkout isolation, **not security isolation or independent
backups**. Deleting the primary repository can destroy the common metadata needed
by linked worktrees. Use isolated execution instances and narrowly scoped
credentials as well. On temporarily unavailable/removable storage, a worktree
lock protects Git pruning, not arbitrary filesystem deletion.

Use `git worktree move`/`remove` for deliberate lifecycle operations, after checking
uncommitted, untracked and ignored material. Avoid `--force`; a refusal is a reason
to inspect and preserve work, not a request to override safeguards.

### Shared editor tasks

Open the **active worktree**, then use **Tasks: Run Task**. The repository-owned
[tasks](../.vscode/tasks.json) use that folder as their working directory:

- **Linura: default environment** checks the core coding profile used by ordinary
  Rust, tooling, contract and documentation work.
- **Linura: complete environment inventory (not readiness)** inventories every
  profile. Missing image, VM, visual or editor capabilities in a coding-only
  instance remain explicit results, not an instruction to install packages
  mid-task.
- **Linura: authority-test host** detects UID-remapped system binaries and unsafe
  temporary-directory ownership before authority-sensitive unit tests emit a
  cascade of misleading recovery failures.
- **Linura: canonical check** requires preflight, output-isolation and authority
  host inspection before invoking the unchanged `cargo xtask check` gate.
- **Linura: Qt component builds (not qualification)** checks shell prerequisites,
  then configures/builds UI and bridge sequentially with compilation databases.
- **Linura: Qt editor inventory (not IDE acceptance)** checks the built modules,
  SDK and language-server arguments, and prints namespace-local machine settings.
- **Linura: heavy storage preflight (not qualification)** fails without a declared,
  verified dedicated mount; it does not execute a workload or provision storage.

Tasks use process/argument arrays, never shell evaluation, privileged commands,
setup installers or automatic folder-open execution. Each task permits one
instance; Cargo and CMake builds use one job. These are **per-editor/task limits**,
not a machine-wide scheduler or memory reservation. Retain the prepared instance's
resource quotas and measure the host budget before parallel work.

Cargo commands remove `CARGO_TARGET_DIR`, `CARGO_BUILD_TARGET_DIR` and
`CARGO_BUILD_BUILD_DIR` from the child environment, so detached test snapshots
keep their own default outputs. The output inspection also reports Cargo config
overrides and rejects existing files/symlinks at the default generated roots:

```bash
python3 tools/development_workspace.py outputs
```

Existing CMake caches must also identify this exact source and build directory.
The v0.10 official base-image and prepared-substrate caches use the validated,
private `vm-images/base/<environment>` prerequisite namespace. Their paths remain
stable across isolated CI jobs. Restored official image bytes are checked against
the upstream digest before being copied into a fresh disposable VM namespace;
the copy is checked again before construction. Prepared images retain their
contract, builder and digest verification. Neither cache contains qualification
evidence or Linura build outputs.

A cache from another checkout, an unknown/duplicate cache identity, or a redirected
path fails instead of reusing conflicting generated data.

Environment setup selects the existing Python 3.12 and publishes a private
alias at `$HOME/.local/linura-tools/python312/bin/python3`. The default VS
Code interpreter, integrated Linux terminals, tasks and Codex wrapper select
that path. Previously explicit VS Code interpreter choices may need one manual
reselection. No system Python or user shell startup file is modified and
ordinary tasks do not install Python packages.

The tasks do not edit shell profiles or repair the editor's parent environment.
Review any output variables/config inherited by language-server processes too.
Custom output configurations require deliberate review; the inspector does not
guess that arbitrary Cargo templates or paths provide safe isolation.

Ordinary task outputs are ignored `target/` and
`.artifacts/cmake/{ui,bridge}` inside the active worktree. Each worktree therefore
has independent defaults, and nested snapshots retain theirs. For dedicated
storage, keep registered source/Git roots off that mount and select reviewed,
per-invocation generated directories on the volume. A guarded launcher can place
its disposable source archive there after checking the original registered
checkout; that archive is neither another authoritative worktree nor a recovery
copy. Placing the original checkout on the volume does not satisfy this design's
independent source/storage boundary.
Do not introduce a globally shared target or rewrite tracked `.cargo` files with
machine-specific paths. Image tools expecting `target/release` remain unchanged.

Build the Qt modules in the prepared environment containing their matching
headers/compiler. Register these compilation databases and generated QML imports
in that environment's machine settings, not in Git. Task success proves component
construction only; it does not start a compositor, register an SDK in another
extension host, provide `qmlls` or qualify a native session.

## Required heavy-workload storage

Ordinary development uses the active workspace and its existing filesystem; it
does not require or create `/mnt/linura-data`. Its usable size naturally follows
the capacity and quota supplied by the workspace provider. Linura does not resize
that filesystem.

For heavy work, `/mnt/linura-data` is only the conventional local mount. The
inspector selects it automatically only when it is already an exact mount in the
current namespace. A provider/operator can instead declare an existing mount with
`LINURA_STORAGE_ROOT` (or `--storage-root`) and its independently verified UUID.
A real dedicated filesystem remains mandatory for persistent local, self-hosted,
native and physical qualification infrastructure. GitHub-hosted Linux jobs may
instead use the separately validated provider-ephemeral class described below;
`CI=true` alone is never an exemption.

| Operation | Required storage boundary |
| --- | --- |
| Editing, formatting, linting, lightweight component tests | Not required |
| Large/concurrent local or self-hosted builds | Dedicated UUID-bound volume; budget and isolate each build |
| GitHub-hosted disposable VM qualification | Checked provider-ephemeral job storage |
| Native/physical qualification and persistent recordings | Dedicated UUID-bound volume |
| Critical recovery | Dedicated protected storage plus an independent off-machine backup |

```text
/mnt/linura-data/
  builds/<worktree-id>/<environment>/<run>/<source-sha>/{cargo,cmake}/
  caches/<environment>/                  dependency inputs only
  qualification/
    vm-images/base/<environment>/        verified immutable prerequisites
    vm-images/disposable/<identity>/     private writable guest copies
    runs/<identity>/temporary/           disposable scratch/private source archives
    recordings/<identity>/              protected retained recordings
  evidence/<identity>/                   protected admitted evidence and diagnostics
  recovery/<identity>/                   protected recovery, never cache cleanup
```

A directory called `/mnt/linura-data` on the root filesystem does not add space,
and developers should not create it merely to satisfy the conventional name.
Before using a chosen path, inspect its filesystem and available blocks/inodes:

```bash
findmnt -T /mnt/linura-data
df -h / /mnt/linura-data
df -i / /mnt/linura-data
```

Do not run these against a nonexistent mountpoint and infer a volume exists.
Provisioning/mounting a disk is an explicit operator action, not task-time setup.
Until one exists, lightweight operations can use bounded ignored local outputs;
heavy infrastructure is **not operational**. Do not redirect heavy workloads to
root, `/tmp`, `.artifacts`, a root-backed Docker volume or a loopback file to make
them runnable. Size from measured cold-build, VM and recording peaks; an extension
download succeeding does not establish enough headroom for qualification.

Use separate Cargo and CMake outputs for concurrent worktrees, incompatible
toolchains/environments and qualification runs. Retain a reusable output directory
for ordinary iteration within one instance, but never treat cached binaries or
old results as exact-source qualification. Verified dependency inputs may be
shared under the existing cache policy; source/build/evidence caches are not
authority.

Cargo supports `--target-dir`, `build.target-dir` and `CARGO_TARGET_DIR`. Do not
globally export one shared `CARGO_TARGET_DIR` for all tasks: subprocesses and
detached-snapshot regression tests can inherit it and contaminate each other's
build state. A task runner must isolate **nested** workspaces too. Prefer reviewed
per-instance configuration/explicit arguments and verify the canonical gate's
expected output paths before relocating anything. Some image/qualification tools
expect `target/release`; moving it blindly breaks those consumers.

For CMake, select a component-specific build directory with `cmake -B` and enable
`-DCMAKE_EXPORT_COMPILE_COMMANDS=ON` when editor analysis needs it. Keep outputs and
compilation databases generated, not version-controlled. Absolute paths in a
container's database refer to that container; opening it in a host editor does not
make its headers and compiler available on the host.

### Inspect a provisioned storage volume

After an operator provides an actual persistent data filesystem, inspect it from
the host/worktree namespace where the filesystem identities are visible:

```bash
python3 tools/development_workspace.py storage \
  --storage-id "${LINURA_STORAGE_ID:?set the verified filesystem UUID}" \
  --environment coding-ubuntu \
  --run local-001 \
  --min-free-gib 12 \
  --max-parallel-builds 1
```

The [inspector](../tools/development_workspace.py) is bounded and non-installing.
It never creates directories, mounts disks, executes a build, deletes state or
publishes evidence. Exit 1 and `layout_ready: false` mean a selected boundary or
observation is missing/unsafe; unknown state does not become a successful check.
Without `--storage-root`, selection checks `LINURA_STORAGE_ROOT` first and then an
already-mounted `/mnt/linura-data`; it never scans for and adopts an arbitrary
disk. The `outputs` command remains the normal workspace-local readiness check.

The supported check requires an exact writable ext4, XFS or whole-filesystem Btrfs
mount, a matching declared UUID, a matching kernel device identity, and storage
backing distinct from both the source and system disks. A bounded `lsblk` topology
check supports block disks and ordinary partitions; loop, device-mapper, RAID,
network and unknown backing remain unsupported rather than guessed independent.
The query explicitly requests tree output: without `NAME` in the selected
columns, `lsblk --json` requires `--tree` to supply partition ancestry
([lsblk manual](https://www.man7.org/linux/man-pages/man8/lsblk.8.html)).
Btrfs mount recognition alone is insufficient: synthetic kernel device identities
or multi-device topology not established by this block inventory fail closed.
Use positively validated ext4/XFS disk/partition layouts for the current rollout;
do not infer Btrfs qualification from the filesystem name.
It rejects ordinary subdirectories,
read-only mounts, bind/subvolume aliases, repeated device mounts, same-device
storage, tmpfs, overlay and unknown backing. An
overlay-based container cannot infer the host's physical storage independence;
run this check in the appropriate host namespace. This is not support promotion
for every storage technology or a proof of redundancy/durability across outages.

The snapshot checks available bytes/inodes against the declared concurrency
budget. Defaults budget 8 GiB and 65,536 free inodes per planned build; these are
development safeguards, **not measured requirements for every workload**. Increase
the byte budget from actual cold-build/guest/recording peaks. Also inspect memory,
CPU quotas and other active workloads; the tool does not reserve resources or
establish overall build-environment readiness.

### Heavy command execution boundaries

`tools/vm.py plan`, `tools/image.py plan` and their `doctor` commands remain
read-only and do not require a data volume. A plan's preview paths are not
authorization to execute there. Actual generic VM `start` and Arch image
`stage`/`build` require the same checked storage contract:

```bash
export LINURA_STORAGE_ROOT=/mnt/linura-data
export LINURA_STORAGE_ID="<operator-verified-filesystem-uuid>"
python3 tools/development_workspace.py storage \
  --environment generic-vm --run local-001 --min-free-gib 12
```

An operator prepares the returned private `temporary` directory and validated
VM inputs on that volume. `vm.py start --run local-001 --image <checked-image>`
sets QEMU's scratch location to that directory; inherited `TMPDIR` cannot redirect
snapshot output to root. Writable `--persistent` images must be in that exact
worktree/environment/run/source `vm-disposable` namespace, never the base-image
tree. Image and cloud-init inputs must be regular single-link files without
symlink traversal, world-write access or QEMU option-delimiter syntax.

`image.py stage --run image-001` and `image.py build --run image-002` reserve a
new private `image` directory under the checked `archiso-build` CMake namespace.
Profile staging, Qt builds, ArchISO work and ISO output all stay there. Reservation
uses no-follow directory descriptors and refuses an existing image workspace;
failed runs are retained and require a fresh run ID, not automatic deletion.
These image-specific ancestors must be caller-owned and private. Neither command
changes source, moves earlier `.artifacts` content or repairs permissions.

These rules apply in CI too: `CI=true` is not an exemption. The existing generic
VM and native Arch runtime workflows run an unconditional reviewed
`scripts/prepare_qualification_storage.sh` step before heavyweight work. Local and
self-hosted runners must set `LINURA_STORAGE_ROOT` and `LINURA_STORAGE_ID` to the
actual provisioned mount and independently verified UUID. Supplying only one is a
hard error.

The checked-in qualification workflows select GitHub-hosted `ubuntu-24.04`
runners. Using a self-hosted runner also requires a reviewed workflow/routing
change; setting storage variables alone does not select or qualify that runner.

When both are unset on a GitHub-hosted Linux runner, the script permits only a
new private `$RUNNER_TEMP/linura-data` root. It verifies `GITHUB_ACTIONS=true`,
`RUNNER_ENVIRONMENT=github-hosted`, `RUNNER_OS=Linux`, exact `GITHUB_WORKSPACE`,
capacity, inodes, ownership and the same source/run namespaces. GitHub's
[variables reference](https://docs.github.com/en/actions/reference/workflows-and-actions/variables)
documents `GITHUB_*` and `RUNNER_*` defaults as non-overridable and `RUNNER_TEMP`
as emptied at job boundaries. The resulting class is disposable provider scratch: it does
not claim an independent disk, persistence, native hardware or physical evidence.
These environment checks assume the workflow is already running on GitHub's
trusted runner. They are consistency checks, not independent provider attestation:
a local process that controls its environment can supply the same variable values.
The Python helper does not authenticate a runner or sandbox a hostile local caller.
Local and self-hosted operators must use dedicated storage; the reviewed workflow
runner selection establishes where hosted mode is permitted. Capacity, ownership,
path and source checks still apply in either class. Evidence admission and
publication retain their separate authenticated boundaries.

The script exports only run-specific paths, `TMPDIR`, the checked storage class
and a one-job Cargo limit; it does not repurpose `HOME` or global Cargo target variables.
Cargo commands select the guarded target explicitly. Base/disposable images,
native cache restores, build scratch and evidence use their checked volume roles.
An unset diagnostic artifact root stays empty, never expands to `/`.
A formerly green workflow on older source is not a pass for this branch.
Do not push this branch as ready, bypass these checks or substitute an arbitrary
root-disk directory outside the guarded GitHub-hosted mode. The standalone native
VM, substrate builder, interactive
launcher, physical capture and Q11 write/finalization entrypoints independently
check the same boundary, so manual execution does not bypass CI preparation.

KVM is optional only for lanes whose reviewed contract selects QEMU TCG. An absent
or inaccessible `/dev/kvm` is reported as unexecuted KVM capability, never silently
converted into KVM evidence. Keep those disposable TCG lanes on GitHub Actions when
the local server lacks KVM; native/physical lanes retain their distinct prerequisites.

For an operator-provisioned native or physical runner, prepare a new clean-source
run explicitly (creation is opt-in, unlike the read-only inspector):

```bash
python3 tools/development_storage.py --source-root "$PWD" \
  --environment arch-hyprland-hardware --run physical-001 \
  prepare --source-sha "$(git rev-parse HEAD)"
```

Use the returned evidence namespace for Q11 state/capture destinations and the
returned scratch for temporary work. Q11's existing domain run ID is distinct
from this storage ID; existing request/fixture/source bindings stay unchanged.
Pass the storage ID to capture as `--run-id physical-001`, or use the prepared
`LINURA_RUN_ID` environment value. A fresh capture can use a private child of
that evidence namespace. Previous recordings/snapshots are refused and retained,
including artifacts from other fixtures; there is no automatic cross-fixture purge.
The global physical-recorder lock, exact-source checks, root-owned fixture,
virtualization denial, digest checks and independent verification remain mandatory.
Read-only Q11 status inspection remains available without running new heavy work.

### Integration dependencies and operational readiness

| Work | Dependency / status |
| --- | --- |
| Shared run preparation, generic/native VM and physical storage guards | Implemented; component checks are not native evidence |
| Combined formatter inventory and sanitized toolchain-contract validation | Integrated with merged PR #221's canonical implementation |
| Main integration and source continuity | Workspace/storage infrastructure is merged; S17 native integration and qualification are tracked by PR #241. Applicable checks still bind the exact current head |
| Host-native coding/Qt/editor readiness | Primary local or Remote SSH host uses the pinned repository toolchain and verified Qt SDK; an optional pinned container is available when a separate compatible instance is needed |
| Real heavy workloads, native/physical qualification and retained recordings | Actual operator-provisioned volume and supported runner configuration required |
| Critical recovery protection | Current copies stay protected; independent off-machine backup still required |

Storage availability is a per-host observation. A provisioned volume can satisfy
the checks independently of the remaining tool, editor and native prerequisites.
Do not mark native qualification or editor acceptance as passed until their actual
required evidence exists. Current CI results belong in the PR's verification
record rather than a permanent claim that every developer host is ready.

The workspace infrastructure has merged. S17's native implementation and bounded Level A qualification are recorded in [PR #241](https://github.com/linura-org/linura/pull/241); its final merge and full-slice acceptance remain subject to current-head gates and governance. Do not reuse unmerged [PR #224](https://github.com/linura-org/linura/pull/224) as the active implementation. Qualified native cases cannot be inferred from separately green development/workspace checks.

The storage root must be caller-owned, writable/searchable and private.
Existing protected recovery/evidence/recording directories must be caller-owned
and private. Missing namespaces are plans, not proof of provisioning; workload
launchers create their run-owned directories with `umask 077`. Operators must
protect the unmounted mountpoint against ordinary-user writes, preventing a later
unmount from becoming a root-disk destination. These checks are snapshots, not
resource reservations or protection against an administrator replacing mounts.

Proposed output paths bind the common Git/worktree identity, environment label,
run ID and source commit. Generated output, immutable prerequisite inputs, and
protected recovery/evidence/recordings have disjoint namespaces. The labels are
operator inputs, not authenticated runner identities; every report explicitly
sets `qualification_evidence` and `execution_performed` to false. Existing
qualification envelopes and evidence admission remain the sole acceptance path.

If no extra filesystem exists, report heavy execution as **blocked**. Do not
create a directory, Docker volume or loopback image on the full root disk and
claim additional capacity. Small component work can use isolated ignored output
on the existing filesystem while capacity permits. There is no automatic cleanup
or provisioning command in this tool.

### Enforced local interactive qualification boundary

The existing [interactive launcher](../qualification/v010/workstation-acceptance/launch-interactive.sh)
now requires `--run-id` and verified storage before archives, builds, VM copies or
recordings. Pass `--storage-root` and `--storage-id`, or declare `LINURA_STORAGE_ROOT`
and `LINURA_STORAGE_ID` in local machine configuration. The prepared image must
reside under the dedicated `qualification/vm-images/` tree. Evidence defaults to
the inspector's protected exact-run namespace; a different `--evidence-dir` is
rejected. Scratch and nested builds stay inside the dedicated run directory;
inherited Cargo output overrides are removed. A run-directory inode lock reserves
the run before building; retained evidence makes a reused run ID fail, rather
than erasing previous results. There is no root-disk fallback.

This does not change evidence admission or supply a qualification pass. Automated
CI, generic VM/image harnesses and physical capture entrypoints use the shared
guards; execution still requires supported provisioning and applicable evidence.
Do not claim the local guard enforces every unrelated direct launch path. Existing
qualification contracts remain authoritative; do not bypass them or repin runtime
substrates merely to accommodate a missing local volume.

### Ownership and retention

| State | Owner and configurable placement | Retirement |
| --- | --- | --- |
| Rust/CMake output | Task owner; isolated local defaults or dedicated private instance/build paths | Exact inactive directory only; rebuildable |
| Dependency cache | Environment owner; dedicated `caches/<environment>` | Retire reviewed inputs only; preserve offline prerequisites |
| Immutable VM base | Runner owner; dedicated `qualification/vm-images/base` | Verify digests; no writable guest use; retire explicitly |
| Guest copies and scratch | Run owner; dedicated exact-run namespace/TMPDIR | After supervision stops and needed diagnostics are retained |
| Recordings and evidence | Qualification/evidence owner; dedicated protected namespace | No build TTL; explicit retention after source/digest binding and independent backup |
| Recovery bundles/local-only archives | Repository owner; protected recovery root outside worktrees | Never worktree/cache teardown; verify destination and off-machine copy before retirement |

Existing image tools with fixed `.artifacts` paths are not silently relocated by
this inspector. Their runner/private checkout placement and path integration must
be reviewed before heavy use. No new cleanup daemon or competing cache policy is
introduced. Protected records have no automatic expiration in this implementation.

## One reviewed environment specification, isolated instances

Reuse repository-owned tool/dependency contracts across editors, task runners and
CI where applicable. Keep pins in their canonical locations, including
`rust-toolchain.toml`, `tools/codex/versions.env`, Cargo/npm/Python locks, formatter
configuration and qualification environment contracts. Do not maintain a second
hand-edited list of supposedly equivalent versions in personal scripts.

Environment creation may install the exact prescribed prerequisites using the
repository setup/recipe. An ordinary task must not repair its environment with
mutable/latest installers, copy GLib/Polkit headers into the source tree, relax
preflight or use production credentials. Report a mismatch and provision a
separate compatible instance. Definitions on an unmerged feature branch are not
automatically available or accepted on `main`.

The primary development environment is the selected local Linux host or Remote SSH host, with its checked worktree, verified Python 3.12/Rust pins and, for Qt work, an actual matching Qt/Wayland SDK. The optional snapshot-pinned isolated development instance was extracted and merged through [PR #244](https://github.com/linura-org/linura/pull/244); its maintained recipe is [tools/codex/container/README.md](../tools/codex/container/README.md). It is **not** a required cross-repository, general-purpose or default execution substrate. When host-sensitive prerequisites cannot be satisfied safely, use a separately prepared instance for those specific checks instead of modifying active host protection or substituting an obsolete PR #224 recipe. Neither host readiness nor optional-container readiness qualifies a native Arch/Hyprland VM or physical workstation.

Editor extensions are developer conveniences, not the compiler, Qt SDK, formatting
authority or qualification runner. Record the installed extension versions for
diagnostics, but do not confuse them with the repository's CLI tool pins.

## C/C++ and Qt/QML editor setup

The recommendations already include `ms-vscode.cpptools`, `theqtcompany.qt-core`,
`theqtcompany.qt-qml` and `xaver.clang-format`. Install them in the extension host
that owns the opened workspace: local desktop, Remote SSH or development container
as appropriate. Installing only on the desktop does not configure a remote
extension host.

For a reproducible editor installation, choose reviewed official releases and use
the supported `publisher.extension@version` CLI form. For example, the stable
releases checked for the October 2026 workspace recovery were:

```bash
code --install-extension ms-vscode.cpptools@1.34.4
code --install-extension theqtcompany.qt-core@1.16.0
code --install-extension theqtcompany.qt-qml@1.16.0
code --list-extensions --show-versions
```

These are a dated editor example, not new mandatory gate pins. Qt QML requires
Qt Core; verify extension dependencies and keep their compatible release pairing.
Do not install a whole extension pack, Qt SDK or compiler toolchain merely to
obtain syntax highlighting. Review any additional dependencies explicitly.

For meaningful C++ diagnostics, select the actual compiler and CMake compilation
database from the environment containing the matching Qt, Wayland, GLib and
Polkit development packages. Do not invent include directories or vendor headers
to hide missing dependencies. Use the host-native SDK when it is installed and verified in the active editor
namespace; attaching an editor to an optional isolated build environment is an
alternative, not a prerequisite. In either case source paths, headers and
compiler analysis must refer to that same namespace.

For QML, register the intended Qt installation and configure the generated
`org.linura.UI`, `org.linura.ShellBridge` and applicable Quickshell imports. Use the
selected environment's compatible `qmlls`; installing the extension alone does not
install or qualify that SDK/language server. Missing imports should be diagnosed,
not suppressed. In Qt QML 1.16, the machine settings
`qt-qml.qmlls.customExePath` and `qt-qml.qmlls.additionalImportPaths` select those
local paths; `qt-qml.doNotAskForQmllsDownload` prevents download prompts. Keep
machine-specific absolute paths outside shared settings, and do not accept an
automatic latest-language-server download as a pinned environment fix.

The shared workspace keeps `qt-qml.qmlls.enabled` false and suppresses download
prompts. This prevents an extension-downloaded server with unresolved host
libraries from entering a restart/EPIPE loop in the primary checkout. A prepared
editor namespace opts in explicitly: the successful editor inspector output sets
`qt-qml.qmlls.enabled` true and binds the matching SDK server and arguments in
that namespace's machine settings. Merely enabling the shared setting is not an
editor readiness fix.

After building both components, run `python3 tools/development_workspace.py editor`
**inside the prepared SDK namespace**. It prints machine settings for Qt discovery,
both compilation databases and the existing SDK's `qmlls`. For the pinned Qt 6.4.2
builder, `qt-qml.qmlls.customArgs` explicitly uses `--ignore-settings` and each
`--build-dir`; it avoids newer extension defaults such as `-I`, which that server
does not implement. Do not set unsupported import/download options to conceal
missing capabilities. Qt 6.4 language intelligence is limited; this is not a claim
of every feature in modern Qt or Quickshell support.

The inventory requires real QtQuick, Controls and Layouts import metadata, not
only headers and a server executable. A host-native or optional-container SDK that has only Qt headers may compile
components but still lack QtQuick/Controls/Layouts runtime imports needed for
QML language intelligence. Verify the **selected** SDK and QML imports instead
of assuming a particular historical image is complete. Do not copy SDK
libraries/imports between execution namespaces or retrofit an active instance;
provision missing prerequisites during explicit environment preparation.
First-party completion and actual VS Code activation remain required
operational checks, not inferred from an inventory.

For the **optional** isolated instance only, use **Dev Containers: Attach to
Running Container**, open its private task clone, and install reviewed editor
extensions in that instance's extension host. The primary local/Remote SSH
workspace continues to use its own native editor and toolchain. Container-local paths are not
valid on the Remote SSH host. Do not forward the Docker socket into the container,
create host wrappers masquerading as compilers/qmlls, or expose production/session
sockets. CLI task builds and an LSP handshake are component checks; actual editor
activation, diagnostics/completion and formatter selection require operator
verification in that attached VS Code window.

Keep verbose LSP traces off for ordinary development. Trust only intended
workspace source before allowing extensions/build tools to execute project code.
Editor format-on-save must use the selected pinned tools; a bundled formatter or
extension version is not proof of compliance. Run the repository checks.

## Readiness, validation and evidence

Run in the **selected task environment**, from its worktree root:

```bash
python3 tools/codex/doctor.py --profile core
python3 tools/codex/doctor.py --profile editor
python3 tools/codex/doctor.py --all  # inventory only; not every task needs every profile
bash scripts/preflight_codex_environment.sh
python3 tools/development_workspace.py authority-host
bash scripts/run_codex.sh cargo xtask check
```

The doctor inventories capabilities; the `editor` profile requires the shell
build prerequisites, real QtQuick/Controls/Layouts runtime import metadata and a
working SDK `qmlls`, not merely an executable file. `--all` may report missing
editor, Arch-image, VM or visual prerequisites in a coding-only instance. Select
the applicable profiles, and do not make all profiles appear ready by weakening
requirements. The authority-host inspection is a non-qualifying prerequisite for
unit tests whose assertions intentionally depend on native ownership semantics;
run those tests outside a UID-remapped sandbox. Preflight must pass before
repository edits in a Codex/cloud task. Setup/maintenance are
environment-preparation actions, not an instruction to install tools mid-task.

The default `authority-host` probe is **distribution-independent**:
it requires the native trusted `/usr/bin/bash` and temporary-root ownership
semantics used by authority-sensitive tests, not Ubuntu's package manager.
Ubuntu v0.9 recovery tests additionally require the explicitly selected
`--recovery-profile ubuntu-v09` check, which validates root-owned
`/usr/bin/apt`. On a native Arch host, the generic probe must not fail
because `apt` is absent; an Ubuntu-specific recovery gate must not be marked
ready when that executable is missing or UID-remapped. Choose a separately
prepared supported environment for the Ubuntu recovery profile:

```bash
python3 tools/development_workspace.py authority-host
python3 tools/development_workspace.py authority-host --recovery-profile ubuntu-v09
```

The second command is **only** for the Ubuntu v0.9 recovery lane; a nonzero
result does not authorize chowning system binaries, relaxing temporary-root
checks or skipping that lane. Readiness is not test or release evidence. An
optional development container may supply compatible Ubuntu dependencies, but
does not replace mandatory Arch/Hyprland VM or physical qualifications.

The canonical gate is not every CI gate: current RustSec audit, CodeQL, pinned
Python typing, multilingual formatting and all impact-routed qualification still
need their actual required executions. Follow the existing
[review/compaction/exact-head sequence](development-infrastructure.md#pull-request-qualification-sequence).

| Environment | What its actual checks can establish |
| --- | --- |
| Pinned coding/build instance | Static checks, unit/contract/adversarial/component tests |
| Dedicated exact-source Arch/Hyprland guest | Declared native graphical/session/authentication/recovery cases |
| Maintained physical workstation | Applicable hardware, real input/display/accessibility and Q11 cases |

Neither installing an extension, passing the doctor, compiling a container nor a
cloud VM can substitute for another evidence level. Retain source SHA, environment,
toolchain, configuration, run identity and artifact digests through the existing
execution-envelope/evidence-binding contracts. A failed native lane stays failed;
workspace migration must not silently discard its diagnostics or mark it passing.

## Safe cleanup and recovery

1. Inventory the actual filesystem, largest known build directories, active
   processes, worktrees and container mounts. Disk-full Git failures can occur
   even during optional index refresh; `git --no-optional-locks status --short`
   avoids that write but does not repair a full disk.
2. Verify the intended remote branch/commit and compare tracked source. GitHub
   holding a commit does not preserve uncommitted edits, untracked source, ignored
   evidence, unsaved editor buffers or personal configuration.
3. Make and verify a recovery bundle for committed history plus a separate private
   recovery copy for local-only material. A Git bundle alone omits that material.
   Keep an independent copy outside any checkout/container/temporary directory
   scheduled for removal; control access and never publish private recovery data.
4. Classify exact targets: rebuildable output, dependency input, source, evidence,
   credentials or active state. A running but idle container is not automatically
   disposable. Check shared mounts before deleting anything.
5. For a confirmed inactive Cargo build directory, use `cargo clean --target-dir`
   with its **explicit inspected path**; inspect CMake build trees similarly.
   Never pass a repository root, home directory, filesystem root or unresolved
   variable as a cleanup target. Outputs removed this way are not recoverable
   bytes, but can be rebuilt from source and the pinned dependencies.
6. Recheck free blocks/inodes and verify protected backups, source and evidence
   still exist. Record what was removed and whether recovery means restoring a
   copy or rebuilding. Limit simultaneous builds to the machine's measured budget.

Do not use blanket Docker pruning, worktree force-removal, `git clean -fdx` or
recursive deletion of broad roots as routine space management. Preserve installed
tools, caches needed for offline development and qualifications unless their
retirement is separately justified. Protect evidence/recovery directories from
cache TTLs and worktree/container teardown.

## Troubleshooting and handoff

- **No free space:** inspect blocks and inodes, stop starting new builds, preserve
  local-only work and remove only verified inactive output. A new directory on
  the same full filesystem is not additional capacity.
- **Extension installed, Qt headers/imports missing:** check the actual extension
  host, compiler/SDK registration and generated module/build paths; do not install
  unrelated latest packages or change qualification assertions.
- **Wrong Ruff/Python/Rust:** use the repository PATH wrapper and prepared instance;
  report exact mismatches. Editor fallback binaries do not satisfy gates.
- **Unexpected branch/source change:** stop writing that checkout, preserve both
  states and continue from a verified task worktree/commit, not a guessed branch.
- **Green old head, changed source:** consolidate and repeat applicable exact-head
  checks. Old screenshots, binaries and routine comments are not current evidence.

A durable handoff identifies the worktree/branch, base/head, dirty/untracked local
material, environment identity, completed and blocked checks, retained diagnostic
locations and verified recovery copies. Paths under `/tmp` and running containers
are not durable storage guarantees; migrate useful records before retiring them.

## Operator rollout checklist

1. Preserve committed history and local-only source/configuration before changing
   the workspace. Verify backups; restore accidental truncations only after the
   exact damaged paths and intended committed source are confirmed. Do not
   force-checkout, blindly commit empty files or erase another task's edits.
2. Open one persistent worktree per task. Keep the Cargo workspace at its existing
   root and shared editor files in Git; do not create another repository or move
   source merely to obtain disk space. Quiesce and preserve an active temporary
   checkout before a separately authorized migration.
3. Create/select isolated instances from the checkout's reviewed environment
   contracts. Use minimum credentials, no forwarded production/session/Docker
   sockets, and explicit CPU/memory/PID limits. Do not turn Git worktree isolation
   into a security-sandbox claim or install into another active task's instance.
4. Check default output isolation, then use the prepared-instance editor tasks.
   Keep per-task/nested outputs independent; configure matching compiler/Qt/import
   paths locally. An extension or task definition alone does not prove IDE/SDK
   integration on the developer's host.
5. Before heavy execution, provision a separate volume and inspect its identity, capacity and permissions,
   then deliberately configure that instance's private checkout/scratch/output
   placement. Keep immutable inputs and protected recovery/evidence out of
   disposal/TTL rules. A same-disk recovery copy protects against checkout cleanup,
   not disk failure: retain an independent backup too. If no volume is available,
   record heavy execution as blocked rather than claim this step completed.
6. Run doctor, preflight, output checks and the canonical gate in the selected
   instance. Keep fresh audit, CodeQL and applicable CI/native/physical evidence
   independent. Complete internal review, one clean commit and exact-head gates
   before final review/merge; retained reports or old-head passes are not grants.

References: [Git worktrees](https://git-scm.com/docs/git-worktree),
[Cargo output configuration](https://doc.rust-lang.org/cargo/reference/config.html#buildtarget-dir),
[VS Code workspaces](https://code.visualstudio.com/docs/editing/workspaces/workspaces),
[VS Code tasks](https://code.visualstudio.com/docs/debugtest/tasks),
[C/C++ setup](https://code.visualstudio.com/docs/cpp/config-linux),
[Qt QML extension](https://marketplace.visualstudio.com/items?itemName=TheQtCompany.qt-qml)
and [Qt extension installation](https://doc.qt.io/vscodeext/vscodeext-how-to-install.html).
