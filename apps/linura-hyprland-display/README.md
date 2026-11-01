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
fields. Apply, confirm and explicit revert also require fresh kernel-peer and
root-systemd evidence for the exact immutable `linura-security-owner@UID.service`
launch. Binding the private global checks this before allocating a client slot;
ordinary same-UID clients cannot exhaust the protected-owner capacity. The
original invocation remains bound to the connection and reservation. A same-UID
process, replaced owner, stopped service or unavailable system bus cannot mutate
or retire the timer. An admitted replacement owner can observe old reservations;
the compositor's automatic recovery remains independent of this admission.
Each probe retains a pidfd and shares one
250 ms deadline; it neither starts a service nor relies on a POSIX session ID.
Linura's production caller must separately pass Control's canonical
managed authority and prepared native-owner admission. The private protocol is
an adapter mechanism, not a policy grant or public SDK.

The private prepared handoff now carries Control's exact sealed effect through
the root session executor. Rust validates the full native sample; the protected
owner immediately rechecks its digest and original timestamp on the same
connection before a one-use apply. A response can acknowledge an attempt, never
verify a layout or authorize keep/revert. Production status uses validated
durable correlation and cannot replay. Public mutation remains disabled pending
protected decisions, durable compositor-loss restoration and native acceptance.

The production continuation transport now carries Control's consumed, durably
recorded protected choice through the independently supervised root executor.
The owner rechecks session, topology, settled lock/input coverage and the complete
desired target before Keep, then uses only the original connection's single
decision reservation. Both native clocks retain the original dispatch deadline;
expiry, clock rollback, replacement or a duplicate cannot renew it. Revert first
acknowledges Restoring; a later native observation and independent Control
verification must prove restoration. Decision hashes and acknowledgements are
not credentials or postconditions. Missing native protected interaction still
blocks public activation; no ordinary UI or original-approval fallback exists.

Component tests exercise transaction and timer boundaries. They are not a
substitute for the exact pinned compositor build or native execution, rollback,
process-loss, hotplug and S17 coverage qualification. Required unexecuted checks
keep PR #259 incomplete and draft.

Output bindings additionally compare bounded native connector, EDID, physical
size and advertised color/HDR facts on every inventory refresh. An in-place
identity change advances both the output generation and topology generation;
unchanged object pointers and mode lists cannot preserve the old identity.
Missing optional EDID remains supported, including headless outputs. Malformed
or over-budget metadata makes the inventory unavailable. Layout/DPMS results
are separate from identity, so an approved mutation does not invalidate itself.
Exact-SDK regressions exercise these facts on the actual Aquamarine output type;
they do not replace live hotplug or protected-frame qualification.

The retained native inhibitor is checked with a zero-wait FIFO/CLOEXEC/liveness
probe after acquisition, on snapshots and before owned writes, including the
last native commit boundary and both direct-scanout paths. Peer loss, invalid
descriptors and unexpected input latch the lease as lost, refusing further
commits or successful verification even if a FIFO peer subsequently reopens.
Pending output state cannot escape through a later renderer commit. This cannot
silently reacquire a fence or replay compensation. Normal rendering with no
retained transaction or a healthy fence remains available. Kernel FIFO tests
cover both peer-loss directions and reopen without lease revival; full native
logind restart/race qualification and durable recovery remain required.

The native display apply request now requires the actual consumed private
interaction resource on its original, freshly attested connection. Its retained
scene survives client/resource loss through a compositor-owned mutation fence.
Owned writes invalidate old frame evidence before modesetting; fresh hardware
completion on every enabled head and accepted disable submissions are required
before native terminal retirement. Failed recovery keeps the opaque/input fence
and power inhibitor. Rejection before effects releases only its reserved scene.

Keep and explicit Revert require a separately consumed, purpose-bound native
decision. The private decision request retains the original attempt's wall and
BOOTTIME bounds, roles, physical input bindings and native commit high-water
marks, and reconfigures all enabled heads at their new logical geometry. Dormant
heads have private roles staged before Apply. A saved Apply epoch cannot confirm
or revert; automatic compensation remains confined to the original baseline.
Control's sealed decision challenge now reaches this retained scene through the
private owner adapter. The owner preserves the original reviewed material and
requires a fresh physical Keep/Revert choice, input/frame generations and a
one-use receipt before the separately prepared root continuation can proceed.
Expired, denied, replaced-owner and uncertain calls cancel only that exact scope.
This composition does not enable the public Authority1 methods: compositor-
replacement restoration and real multi-output/adversarial runtime acceptance
remain required before public activation.

The private Control safety adapter preempts display choice before lock/power
review or native sleep coverage coordination. Original compensation and its
opaque/input/power fences stay compositor-owned. Control polls actual retirement
within a nonrenewable two-second BOOTTIME budget; unavailable, late or unresolved
restoration cannot advance S17. Prepared lock acquisition also checks the native
display fence. This mechanism grants no lock/power authority, and its overlap
behavior still requires real native qualification.

The private native identity witness also carries the actual DRM backend's device
major/minor and connector object ID, obtained from its retained descriptor and
output object. The owner validates this source-versioned binding before hashing
and projecting metadata. Duplicate or malformed bindings fail closed; explicit
non-DRM outputs remain read-only without mutation checkpoint qualification.
These facts are required comparison material for recovery, not proof of kernel
lifetime across compositor replacement. No new restoration write is enabled.
