# S21-2 pinned compositor integration

This source integration targets only the Hyprland commit and release archive in
`contracts/hyprland-display-integration.toml`. It is part of PR #259/S21-2.
The complete display UI belongs to S21-6; cross-domain and physical workstation
acceptance remain S21-7/release work. Building the compositor and qualifying its
display execution, restoration and S17 lock safety are S21-2 requirements.

## Build environment

`contracts/s21-hyprland-build-environment.toml` defines a disposable Arch x86_64
build environment, using the repository's existing fixed Arch cloud image and
2026-09-16 archive snapshot. `/mnt/linura-data` supplies guarded storage; it does
not supply an operating system or SDK.

The specification includes the compositor's runtime and build dependencies,
GLES3 headers/link libraries (`libglvnd` and Mesa), Glaze, protocol scanners,
Aquamarine and the Hyprland libraries. Repository database digests fix dependency
resolution, native pacman signatures remain mandatory, and explicit SDK package
versions/hashes reject mismatched headers and partial upgrades. Glaze 7.2.0 is a
separately digest-pinned, signature-verified archived package: snapshot Glaze 8
cannot satisfy the upstream `find_package(glaze 7...<8)` contract. CMake network
fetching is disabled for compositor builds.

Prepare the environment from a clean checkout with the existing dedicated
storage configuration:

```bash
bash scripts/run_codex.sh python3 tools/hyprland_display_build.py prepare \
  --run s21-display-sdk-unique-run
```

This downloads and verifies the contract-pinned base image and reuses
`qualification/v010/shell-runtime/prepare-substrate.sh` with fresh guarded
`vm`/`temporary` destinations. The builder automatically invokes
`tools/hyprland_display_environment.py` for this contract, checks repository
metadata before installation, verifies package versions, and runs a GLES3/Glaze
CMake probe before sanitizing the image. Its manifest binds the contract,
builder, dependency verifier, installed inventory and resulting image digest.
It contains neither Linura source nor build outputs and is not qualification
evidence. The existing runtime substrate remains a separate contract.

From a clean exact-source checkout, build with the resulting image:

```bash
bash scripts/run_codex.sh python3 tools/hyprland_display_build.py build \
  --archive /checked/input/source-v0.56.2.tar.gz \
  --prepared-image /checked/vm/s21-hyprland-build.qcow2 \
  --prepared-manifest /checked/vm/s21-hyprland-build.json \
  --run s21-display-build-unique-run \
  --acceleration tcg --jobs 1
```

The input image/manifest must belong to checked dedicated storage. The builder
creates a new disposable overlay, stages the digest-verified upstream archive
with exact reviewed source edits, and copies the selected native integration.
Large inputs, logs, VM images and compiler outputs stay in guarded run storage.
`--development` explicitly permits work in progress and cannot qualify a Git
head. Exact-source mode rejects changes before/after the build. Neither mode
claims runtime, rollback or S17 qualification merely from successful compilation.

On a memory-constrained host, the same prepared SDK can supply an unprivileged
native-speed build without installing its packages on the host:

```bash
bash scripts/run_codex.sh python3 tools/hyprland_display_build.py export-sdk \
  --prepared-image /checked/vm/s21-hyprland-build.qcow2 \
  --prepared-manifest /checked/vm/s21-hyprland-build.json \
  --run s21-display-sdk-export-unique-run --memory-mib 2048

bash scripts/run_codex.sh python3 tools/hyprland_display_build.py namespace-build \
  --archive /checked/input/source-v0.56.2.tar.gz \
  --sdk-archive /checked/export/arch-sdk.tar \
  --sdk-manifest /checked/export/build-result.json \
  --run s21-display-namespace-build-unique-run --jobs 1
```

The export contains packaged SDK files and public package metadata. It excludes
home directories, private keys, password databases and Linura build outputs.
The namespace engine requires an existing `bwrap`, verifies the SDK digest and
package inventory, mounts the SDK read-only, and exposes only the checked build
directory and temporary directory as writable. It has no network access or host
source mount. This is another engine for the same pinned build contract, not a
new acceptance environment. Existing Level A KVM runtime qualification remains
required. Use fresh run names; failed or development runs cannot be relabeled as
exact-head qualification.

## Safety boundary

The compositor owns the bounded BOOTTIME restoration timer and preserves all
unrelated monitor-rule fields through a typed overlay. Reply acknowledgements
are not native verification. Continuations require the original native client
connection; another connection cannot disarm the timer using copied correlation
fields. Linura's production caller must separately pass Control's canonical
managed authority and prepared native-owner admission. The private protocol is
an adapter mechanism, not a policy grant or public SDK.

Component tests exercise transaction and timer boundaries. They are not a
substitute for the exact pinned compositor build or native execution, rollback,
process-loss, hotplug and S17 coverage qualification. Required unexecuted checks
keep PR #259 incomplete and draft.
