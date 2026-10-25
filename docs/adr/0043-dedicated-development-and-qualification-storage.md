# ADR 0043: Separate lightweight development from dedicated qualification storage

- Status: Accepted
- Refines: ADR 0022

## Context

Repository ownership of tooling does not make a machine's storage, editor SDK or
qualification environment operational. Root-disk exhaustion, shared build targets
and temporary source checkouts can lose work or contaminate exact-source evidence.
The workspace architecture needs a durable, explicit storage boundary without
making ordinary editing depend on a provisioned qualification runner.

When this ADR was written, identifier 0042 was reserved by the then-open S17
reference PR #224. That is historical numbering provenance, not a current
integration dependency: S17 implementation later moved into the split PR stack
ending with #241. This accepted storage decision neither imports S17 authority
nor changes its qualification boundary.

## Decision

Keep source repositories, registered task worktrees, shared editor settings and
environment specifications under their existing repository ownership. Open the
active task worktree in the editor. Worktrees are checkout isolation, not security
sandboxes or independent backups.

Require an independently provisioned block disk/filesystem for persistent local,
self-hosted, native and physical VM/build scratch, continuous recordings and
retained evidence. The
conventional local mount is `/mnt/linura-data`; it is selected only when already
mounted. Other machines and runners declare an explicit mount and independently
verified filesystem UUID. Ordinary development remains on the supplied workspace
filesystem, whose capacity/quota Linura neither provisions nor resizes.

GitHub-hosted Linux runners are a separate, explicitly bounded storage class. A
job may use only GitHub's non-overridable `RUNNER_TEMP` in a newly reserved private
`linura-data` subtree, after hosted-runner identity, exact checkout, capacity,
inode, ownership and namespace checks. This path is disposable job scratch, not a
persistent volume, backup or physical/native evidence store. `CI=true` alone,
self-hosted labels, bind mounts and directory names grant no exemption.

The hosted mode assumes GitHub's trusted workflow/runner boundary. Environment
values provide consistency checks, not independent provider attestation; a local
caller controlling its environment can reproduce them. These unprivileged helpers
are operational guards, not an authorization boundary against that caller.
Persistent local/self-hosted operation still requires dedicated storage by policy.
Reviewed workflow runner selection and independent evidence admission/publication
remain the respective execution-context and acceptance boundaries.

Before a heavy entrypoint writes or executes, require a known writable exact
mount, known backing topology independent of both source and system disks,
matching kernel device and declared UUID, sufficient available blocks/inodes,
appropriate permissions and safe non-overlapping paths. Unknown or unsupported
storage fails closed. Provisioning is an operator responsibility: repository tools
never partition, format, mount, relocate or automatically purge existing data.

Namespace generated state by worktree, environment, run and committed source
identity. Basic Cargo/CMake component iterations can retain independent local
defaults; do not globally export shared Cargo output variables into nested
workspaces. Separate disposable build/guest scratch from protected recovery,
evidence and recordings. Failures remain available for deliberate inspection;
relaunch is not permission to overwrite retained evidence. Critical backups also
require independently verified off-machine copies.

Pinned coding/build instances, native Arch/Hyprland runners and maintained physical
workstations remain separate readiness levels. A storage inventory, component
build or editor handshake is not runtime qualification, evidence admission,
support promotion or publication authority. Existing exact-source, native,
physical, recovery and independent-verification requirements remain mandatory.

## Rollout and consequences

The workspace inspector and guarded interactive, generic VM and Arch-image
entrypoints implement part of this boundary. Generic VM execution requires private
prepared scratch and checked VM inputs; writable guests cannot target base images.
Arch-image execution reserves new private workspaces and retains earlier runs.

Automated generic/native VM preparation, image/cache/build/evidence paths and
physical capture/Q11 write entrypoints now use the guarded layout. Local and
self-hosted runners still need provisioned storage and explicit UUID
configuration. GitHub-hosted jobs may use only the provider-ephemeral class and
still fail closed on identity, path, capacity, permission or source drift. This is
not permission to waive gates. The merged PR #221 toolchain/formatter inventory is
reused rather than duplicated. Each candidate must pass all applicable checks and
retain actual required evidence before final review or merge. Acceptance of this
decision does not assert that every local, self-hosted or physical runner has been
provisioned or qualified.

Environment recipes remain repository-owned and reused, including the reviewed
snapshot recipes currently on S17. Do not duplicate those recipes to conceal an
integration dependency. A complete matching Qt SDK, QML runtime metadata and
editor extension-host validation remain necessary for the editor profile.

Storage readiness is a per-host snapshot, not a reservation or a guarantee
against privileged mount changes during a run. Provisioning a valid disk on one
host does not establish another runner's capacity or qualification readiness.

## Alternatives

An optional data directory with silent root fallback preserves convenience but
violates the heavy-workload boundary. A mandatory disk for all editing would
unnecessarily block lightweight work. Automatically provisioning or purging disks
would expand tool authority and endanger recovery; none is selected.
