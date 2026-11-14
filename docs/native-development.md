# Native development preparation

Use the existing Ubuntu host as the primary development environment. Repository
preparation supports Linux x86_64 on Ubuntu **24.04**, Ubuntu **26.04** and
**Arch Linux**. Supporting these hosts does not require installing both
distributions, moving development into containers, or running every task twice.
An Arch builder remains necessary for ArchISO. Qualification machines, interactive
sessions and physical workstations satisfy their own acceptance contracts.

The implementation is developer preparation tooling, outside Linura's runtime
authority path. It exposes no provider, D-Bus, executor or agent interface. Read
and trust the checkout before running its preparation commands. See
[ADR 0044](adr/0044-explicit-native-development-preparation.md).

## Profiles and prerequisites

[native-profiles.toml](../tools/codex/native-profiles.toml) maps the existing
[doctor](../tools/codex/doctor.py) profiles to native packages. Dependencies expand
automatically for host preparation; every host selection includes `core`.

| Profile | Prepared dependencies | Host boundary |
| --- | --- | --- |
| `core` | Compiler/linker, pinned private Python, Rust/rustfmt/Clippy, Ruff, actionlint, cargo-audit, locked Cargo graph, private Node/Pyright | All three supported hosts |
| `shell` | Core, CMake/Ninja, consistent Qt SDK, Wayland/protocol/scanner, xkbcommon and native authentication build headers | Component compilation is separate evidence |
| `editor` | Shell, SDK language server and QML runtime imports | Does not install editor extensions or enable workspace language servers |
| `bindings` | Core and the existing hash-locked Python build environment | Reuses canonical `--bindings` bootstrap |
| `vm` | Core, QEMU/TCG utilities, SSH client and cloud-image tools | Does not grant KVM, reserve storage or create qualified VM evidence |
| `image` | Shell and ArchISO's canonical releng profile | Native Arch only; Ubuntu refuses before effects |
| `visual` | Core, ImageMagick and FFmpeg tools | Does not qualify a display, input device, GPU or recording |
| `hyprland-build` | Standalone source-pinned Arch compositor SDK inventory, including compiler, GLES3/EGL, Glaze and native library versions | Prepared by the S21 disposable-substrate driver; requires neither Rust nor the QML editor inside the SDK |

`shell` already supplies the native security-owner prerequisites. Its probes
include CTest, consistent Qt Core/DBus/Gui/Qml/Quick/QuickControls2, Wayland,
xkbcommon, GLib and Polkit; a second package profile would duplicate that
selection. Full security-owner CMake compilation and CTest remain required
separate checks, including native authentication enabled. Editor imports are a
separate selection, and SDK readiness is never a component-test pass.

The standalone `hyprland-build` doctor profile inventories the exact SDK described
by `contracts/s21-hyprland-build-environment.toml`. Generic `native.py` host
preparation refuses this selection before effects and directs it to
`python3 tools/hyprland_display_build.py prepare --run UNIQUE_RUN`. This reuses
the existing pinned Arch substrate builder and guarded storage, verifies signed
packages and GLES3 discovery, and preserves the Ubuntu host. It never replaces
the pinned SDK with current host packages or downgrades a maintained Arch host.
Run `doctor.py --profile hyprland-build` inside that prepared SDK. Selecting this
profile alone does not execute Rust or QML-editor checks. Default `core`,
`shell`, `editor` and host `native.py --all` selections retain their prior scope.

The starting host must already have Python >= 3.11 with `tomllib`, Git, Bash, its
working native package manager, authenticated repositories and administrator
authorization through `sudo`. The process itself must run as the developer, with
an ordinary private home and native filesystem ownership. Root execution,
symlinked installation ancestors and writable/shared tool directories fail.
No general environment-variable forwarding or shell startup-file loading occurs.
Preparation uses the default `~/.cargo` and `~/.rustup`; remove conflicting tool
overrides before preparation and subsequent diagnostics.

Preparation checks at least 2 GiB free in its private tool filesystem and 1 GiB
on the system filesystem. These are minimum guards, not storage reservations or
estimates of every package/build's peak use. Generations and native package
payloads need additional capacity; failures remain explicit. Heavy image/VM work
still requires the independent [storage preparation](development-workspaces.md).

## Inspect, review and prepare

Read-only inspection never installs anything:

```bash
python3 tools/development_drift.py
python3 tools/codex/doctor.py --all --json
python3 tools/codex/native.py plan --profile editor --profile bindings
```

Create a private plan, review its exact package versions/dependency closure, then
explicitly prepare that selection:

```bash
umask 077
python3 tools/codex/native.py plan --profile editor --profile bindings > /tmp/linura-native-plan.json
sudo -v
python3 tools/codex/native.py prepare --plan-file /tmp/linura-native-plan.json
```

Plans expire after 15 minutes. Preparation rederives the full selection and checks
source inputs, host/user/home, native repositories, installed versions and manual
package ownership before dispatch, including after obtaining its private lock.
Changed or malformed plans fail; no saved file supplies commands or credentials.
The digest detects stale data, not malicious code run by the same developer.
Native subprocesses preserve the caller's terminal session for ordinary sudo
credential caching, while using separate process groups for bounded cleanup.
Running preparation in a different terminal requires separate authorization.
Plans and receipts contain local paths and software inventories; review them
before sharing.

To prepare without a saved plan, the explicit command derives and checks one:

```bash
sudo -v
python3 tools/codex/native.py prepare --profile editor --profile bindings --profile vm --profile visual
```

Host `native.py --all` includes the Arch-only image profile and therefore refuses on Ubuntu.
Select the profiles needed for the task. On a maintained Arch builder,
`python3 tools/codex/native.py prepare --all` prepares the host inventory. The
standalone compositor SDK has its pinned substrate driver; `doctor.py --all`
also inventories it and cannot establish SDK readiness on an ordinary host.

Ubuntu preparation normally uses existing APT metadata. If metadata is absent or
outdated, explicitly request `prepare --refresh` with the desired profiles. This
updates metadata before constructing a new plan; it cannot apply a saved plan.
It adds no repositories or keys, refuses unauthenticated/insecure resolution,
removals, downgrades and broken package databases, and verifies installed versions.
The native package manager remains responsible for signatures, hooks and locks;
its administrator-owned configuration is trusted. Planning and revalidation do
not hold a transaction-wide package-manager lock against another administrator.
Avoid concurrent package maintenance.

Arch preparation requires existing sync databases no older than 24 hours, no
pending upgrades and no planned downgrades. It never runs `pacman -Sy`, refreshes
databases separately, imports keys, disables hooks or upgrades the whole host.
If these prerequisites fail, perform reviewed full-system maintenance separately
and replan. Arch explicitly [does not support partial upgrades](https://wiki.archlinux.org/title/System_maintenance#Partial_upgrades_are_unsupported).
Preparation never sets Linura's direct-pacman break-glass flag or bypasses a native
package-manager protection.

## Pinned tools and verification

[versions.env](../tools/codex/versions.env) owns the native Python/Node versions
and archive SHA-256 digests. Python is built under a private generation; neither
distribution's system Python is replaced. The sealed release's separate Python
pin remains unchanged. Node uses the repository's source-analysis pin; Pyright
uses the existing npm lockfile, integrity verification, disabled lifecycle scripts
and omitted optional dependencies. Downloads require HTTPS and the reviewed
digests before extraction or execution. Python/Node downloads use `python.org`
and `nodejs.org`; locked npm dependencies require `registry.npmjs.org`. The
canonical bootstrap retains its existing Rust, GitHub and PyPI network origins.

Canonical setup still owns Rust/Ruff/actionlint/Cargo and bindings preparation;
native preparation invokes it rather than maintaining a parallel installer.
Native tools live under `~/.local/linura-tools/native/generations/`. Verified file
manifests precede cached executable probes; changed caches produce a fresh
generation. Public Pyright launchers and the existing private Python selection
are published without overwriting unmanaged files. Failed/older generations are
retained for inspection, with no automatic package removal or cleanup.

After installation, preparation verifies exact package versions, preserves prior
manual package owners and restores automatic reasons for transitive dependencies.
It then runs the selected doctor checks. Shell checks include the native
security-owner build prerequisites as well as Qt. A failed check produces a
nonzero result and a failure receipt, never a ready receipt. SDK readiness is not
a compiled component test or acceptance result.

## Failure, maintenance and recovery

Only one preparation process can own the private lock. A contender cannot replace
the active receipt. `~/.local/linura-tools/native/last-run.json` records the phase,
original package inventory digest/manual owners, planned transaction, checks and
result. Prior receipts are archived privately under `history/` before replacement.
Neither a receipt nor a successful package-manager exit is qualification evidence.

Package transactions are not rolled back automatically. If an interrupted package
phase changed installed state or manual ownership, the next attempt refuses with
`prior_package_transaction_requires_operator_review`, preserving the old receipt.
Review it, repair any native package database problem using normal administrator
procedures, and reconcile dependency ownership deliberately. Only then use the
explicit `--accept-current-packages` flag with a newly derived plan to accept the
current native state. This acknowledges operator review; it does not recover the
database, restore ambiguous ownership or replay an old transaction.

A denied transaction that left package state unchanged can be retried after
authorization and replanning. A source/input change requires a fresh plan.
Never bypass a failed native protection or repair the ordinary task environment
silently. For explicit reinstall/rebuild maintenance:

```bash
python3 tools/codex/native.py plan --maintenance --profile editor > /tmp/linura-native-maintenance.json
sudo -v
python3 tools/codex/native.py maintain --plan-file /tmp/linura-native-maintenance.json
```

Maintenance reinstalls the exact selected native package closure and creates a
fresh private tool generation. It preserves shared packages and historical
generations. Inspect failed generations and references before any manual retirement.

## Evidence boundaries

The three build-readiness contexts are general Rust/Qt development, native
security-owner C++ compilation, and source-pinned compositor integration. They
reuse the existing profiles and build tools; they do not create five independent
development environments or a new acceptance hierarchy. A build contract, an
installed SDK, successful linking and native execution are distinct claims.

The S21 compositor integration is linked into the exact pinned Hyprland source,
rather than dynamically loaded through a plugin ABI. Compatibility verification
must compile its actual private headers, link the whole compositor and observe
the expected integration identity/protocol in the running compositor. A generic
mechanism build or version string alone cannot prove integration loading.

Reuse Level A/B/C from `contracts/v010-workstation-acceptance.toml`: S21-2 must
extend Level A for real display mutation, independently observed restoration and
S17 output-lock coverage before merge. Level B stays the same optional
interactive view of that substrate. Level C/Q11 remains separately maintained
physical acceptance, with later S21-7/release cases. No readiness profile can
promote any of these evidence levels.

Stateful package-manager fixtures exercise Ubuntu and Arch selection, denial,
staleness, partial failure, ownership, cache integrity and interruption paths.
Actual native package transactions on **each supported distribution** remain
separate platform validation: simulated transactions and these tests cannot
establish that those installations passed. Record the exact source, OS/repository
state, prepared profiles and checks when validating a newly prepared host.

Run preflight and `bash scripts/run_codex.sh cargo xtask check` on the resulting
checkout. CI verifies its own prepared environment and exact source independently;
native package versions need not equal a different distribution's versions.
Readiness does not prove Level A automated KVM, Level B interactive observation,
Level C physical/Q11 acceptance, or the restart/partial-failure composition of the
application. Those contracts and PR #241's validated application code are unchanged.
