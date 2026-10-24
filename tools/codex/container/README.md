# Isolated pinned development environment

This recipe supplies development prerequisites, not product execution or
qualification evidence. It makes the previously prepared Ubuntu development
base repository-owned. Its immutable image and signed Ubuntu snapshot bind the
complete installed package/version graph; a mismatch fails image creation.
It is not a claim of bit-identical images or binaries.

Language and lint tools are **not** independently specified here. A new isolated
instance runs `scripts/setup_codex_environment.sh --bindings` from the selected
checkout, using `tools/codex/versions.env`, `tools/python/ruff-requirements.lock`,
the bindings lock and `Cargo.lock`. Host, editor, Codex and CI must continue to use
those same contracts. Do not repair an existing instance during implementation.

Before creation, check disk and memory and protect source recovery copies outside
build/artifact cleanup directories. Build with the restricted context below;
checkout files, `.git`, credentials, caches and binaries are excluded:

```sh
docker build --platform linux/amd64 --tag linura-development:20261006 \
  tools/codex/container
LINURA_DEV_IMAGE=$(docker image inspect --format '{{.Id}}' linura-development:20261006)
docker run --detach --name linura-s17-development \
  --user 1000:1000 --cap-drop ALL --security-opt no-new-privileges \
  --cpus 2 --memory 2g --memory-swap 3g --pids-limit 512 --ulimit core=0 \
  "$LINURA_DEV_IMAGE"
```

Creation alone permits network access to the setup origins documented in
`docs/development-infrastructure.md`. No ports, Docker/system/session sockets, host devices, production credentials,
or host checkout directories (even read-only) are forwarded.
Create a private clone of the selected task commit; do not copy the host's
working tree or Git configuration. A Git bundle also supports linked worktrees, whose `.git` file points outside
the checkout directory. Capture the selected commit on the host and stream
only its reachable Git objects into the instance:

```sh
task_source_sha="$(git rev-parse HEAD)"
task_bundle="$(mktemp /tmp/linura-task-source.XXXXXX.bundle)"
git bundle create "$task_bundle" HEAD
docker exec -i linura-s17-development sh -c \
  'umask 077; cat > /workspace/linura-task.bundle' < "$task_bundle"
docker exec linura-s17-development \
  git clone --no-hardlinks /workspace/linura-task.bundle /workspace/linura
docker exec --workdir /workspace/linura linura-s17-development \
  git checkout --detach "$task_source_sha"
rm -f -- "$task_bundle"
docker exec --workdir /workspace/linura linura-s17-development \
  bash scripts/setup_codex_environment.sh --bindings
docker network disconnect bridge linura-s17-development
docker exec --workdir /workspace/linura linura-s17-development \
  bash scripts/preflight_codex_environment.sh
docker exec --workdir /workspace/linura linura-s17-development \
  bash scripts/run_codex.sh python3 tools/codex/doctor.py --all
```

## Pinned Rust and Qt component readiness

The setup and preflight above must succeed in the task clone before compiled
verification. Do not infer a prepared Rust/Qt environment merely from an
installed `rustc` or `cmake`. The canonical strict preflight checks pinned
Rust 1.98.0, rustfmt, Clippy and offline `Cargo.lock` availability.
Check Qt's actual CMake/SDK modules separately, and compile affected components
using the same repository source and toolchain contracts:

```sh
docker exec --workdir /workspace/linura linura-s17-development \
  bash scripts/run_codex.sh python3 tools/codex/doctor.py --profile shell --json
docker exec --workdir /workspace/linura linura-s17-development \
  bash scripts/run_codex.sh python3 tools/development_workspace.py outputs
docker exec --workdir /workspace/linura linura-s17-development \
  bash scripts/run_codex.sh cargo xtask check
docker exec --workdir /workspace/linura linura-s17-development \
  bash scripts/run_codex.sh cmake -S apps/linura-shell/ui -B /build/linura-ui -G Ninja
docker exec --workdir /workspace/linura linura-s17-development \
  bash scripts/run_codex.sh cmake --build /build/linura-ui --parallel 2
docker exec --workdir /workspace/linura linura-s17-development \
  bash scripts/run_codex.sh cmake -S apps/linura-shell/bridge -B /build/linura-bridge -G Ninja
docker exec --workdir /workspace/linura linura-s17-development \
  bash scripts/run_codex.sh cmake --build /build/linura-bridge --parallel 2
```

`shell` readiness does not claim Qt editor/QML runtime imports. For editor
work additionally request `--profile editor` and require all checks to pass;
missing QML modules or a nonfunctional `qmlls` are real missing prerequisites,
not reasons to skip qualification. The repository-owned signed Ubuntu snapshot
and reviewed package-graph digest remain unchanged; modifying a package set
requires a new verified digest and a fresh container-build test. The actual
Docker build, Qt compile and any native graphical behavior remain unverified
until run in the intended instance. Do not convert a readiness check into
native workstation acceptance.

## Host-sensitive authority tests

The prepared Ubuntu image deliberately retains its native root-owned `/`,
`/usr/bin/bash` and sticky `/tmp`. Its Ubuntu v0.9 recovery tests additionally
require root-owned `/usr/bin/apt`; generic Linux authority-host ownership checks
do not require that package manager. Select the recovery profile explicitly
before these host-sensitive tests, then use the same prepared checkout and
repository tool wrapper:

```sh
docker exec --workdir /workspace/linura linura-s17-development \
  bash scripts/run_codex.sh python3 tools/development_workspace.py authority-host --recovery-profile ubuntu-v09
docker exec --workdir /workspace/linura linura-s17-development \
  bash scripts/run_codex.sh cargo test --locked -p linura-bootstrap
docker exec --workdir /workspace/linura linura-s17-development \
  bash scripts/run_codex.sh cargo xtask check
```

Do not add a user-owned `/tmp` bind mount or a tmpfs declared with `uid=1000` to
make temporary storage writable. A world-writable temporary root is trusted only
when it is root-owned and sticky; changing its owner recreates the same unsafe-host
failure as a UID-remapped outer sandbox. Do not `chown` or `chmod` host system
paths. A failed authority-host inspection means these host-sensitive tests remain
blocked in that namespace; it does not authorize skipping them or treating the
container result as qualification evidence.

Keep each task's clone, tools, caches and outputs private to its instance. Check
resources again before large builds. Source synchronization is explicit; run
preflight again on the actual task checkout, then affected tests and canonical
`cargo xtask check`. Setup/preflight/doctor results never replace Security,
CodeQL, native Arch/Hyprland, real authentication, VM, visual or maintained
physical-workstation evidence. The [v0.10 workstation acceptance contract](../../../contracts/v010-workstation-acceptance.toml) and [ADR 0042](../../../docs/adr/0042-s17-session-security-and-power-authority.md)
defines the official Polkit/GLib/Wayland acceptance and guest requirements; this
general base does not claim native-auth readiness or run privileged session
services.

Removing an instance discards its private tools and output; do not use that as a
source-backup strategy. Recovery copies, active task clones and qualification
evidence are never disposable build artifacts. Never prune them to make a gate
appear runnable. Update base/snapshot/graph pins only together after review.

## Optional source-analysis creation profile

Main's Python typing and multilingual formatting use additional, independently
locked tools. Create a **fresh** instance of the same image for them; do not
install into an active development/native builder. Check resources and verified
recovery copies first. This profile remains build infrastructure, not native or
full CI qualification. Like the main build instance, it imports only committed
Git objects from the selected task HEAD into a private clone: no bind mount
exposes host Git configuration, untracked files or local credentials.

```sh
docker run --detach --name linura-source-checks \
  --user 1000:1000 --cap-drop ALL --security-opt no-new-privileges \
  --cpus 1 --memory 1g --memory-swap 2g --pids-limit 128 --ulimit core=0 \
  "$LINURA_DEV_IMAGE"
source_checks_sha="$(git rev-parse HEAD)"
source_checks_bundle="$(mktemp /tmp/linura-source-checks.XXXXXX.bundle)"
git bundle create "$source_checks_bundle" HEAD
docker exec -i linura-source-checks sh -c \
  'umask 077; cat > /workspace/linura-source.bundle' < "$source_checks_bundle"
docker exec linura-source-checks \
  git clone --no-hardlinks /workspace/linura-source.bundle /workspace/linura
docker exec --workdir /workspace/linura linura-source-checks \
  git checkout --detach "$source_checks_sha"
rm -f -- "$source_checks_bundle"
docker exec linura-source-checks bash --noprofile --norc -euo pipefail -c '
  mkdir /workspace/source-checks
  cd /workspace/source-checks
  curl --fail --silent --show-error --location --max-time 120 \
    https://nodejs.org/dist/v22.23.3/node-v22.23.3-linux-x64.tar.xz \
    --output node-v22.23.3-linux-x64.tar.xz
  echo "df450af89261115ef9f9e3830c3eeb2cc9213b63c720b1af623cb5dcbe2e02de  node-v22.23.3-linux-x64.tar.xz" \
    | sha256sum --check --strict
  tar -xJf node-v22.23.3-linux-x64.tar.xz
  export PATH="/workspace/source-checks/node-v22.23.3-linux-x64/bin:$PATH"
  test "$(node --version)" = v22.23.3
  mkdir typing format
  cp /workspace/linura/tools/python-typecheck/package.json \
    /workspace/linura/tools/python-typecheck/package-lock.json typing/
  npm ci --prefix typing --ignore-scripts --omit=optional --no-audit --no-fund
  cp /workspace/linura/tools/source-format/package.json \
    /workspace/linura/tools/source-format/package-lock.json format/
  npm ci --prefix format --ignore-scripts --no-audit --no-fund
  python3 -m venv clang
  clang/bin/python3 -m pip install --disable-pip-version-check --no-cache-dir \
    --require-hashes --only-binary=:all: --no-deps \
    -r /workspace/linura/tools/source-format/clang-requirements.lock
'
docker network disconnect bridge linura-source-checks
docker exec --workdir /workspace/linura linura-source-checks \
  /workspace/source-checks/node-v22.23.3-linux-x64/bin/node \
  /workspace/source-checks/typing/node_modules/pyright/index.js \
  --project pyrightconfig.json
```

The Node version is the existing `.github/workflows/ci.yml` version; the archive
digest is from that exact official Node release. Keep them aligned when main
changes, rather than updating dependencies or regenerating locks to accommodate
the base image's different npm. The Pyright, Prettier, StyLua and clang-format
versions/integrity remain owned by the existing repository lockfiles. Creation
requires the documented npm/Python origins plus `nodejs.org`; ordinary checks run
after network disconnection. No lifecycle scripts or optional Pyright packages
are installed.

Use private scratch copies for deliberate formatting and copy back only reviewed
task files. Do not add a host checkout mount or mass-format frozen sources.
This limited profile does **not** supply the pinned shfmt or Qt QML formatter,
Rust gates, Security/CodeQL or real session/PAM/power evidence. Their missing
prerequisites and unexecuted checks remain explicit; canonical CI's complete
installation and gate commands are unchanged.
