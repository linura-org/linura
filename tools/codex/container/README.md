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
  --mount "type=bind,source=$PWD,target=/source,readonly" \
  "$LINURA_DEV_IMAGE"
```

Creation alone permits network access to the setup origins documented in
`docs/development-infrastructure.md`. No ports, Docker/system/session sockets,
host devices, production credentials or writable host directories are forwarded.
Create a private clone of the selected committed revision; do not copy the host's
working tree or Git configuration. For the approved main integration baseline:

```sh
docker exec --env GIT_CONFIG_COUNT=1 --env GIT_CONFIG_KEY_0=safe.directory \
  --env GIT_CONFIG_VALUE_0=/source linura-s17-development \
  git clone --no-hardlinks /source /workspace/linura
docker exec --workdir /workspace/linura linura-s17-development \
  git checkout --detach 8dc705f2c7233fb478c7ae944b5de4caca59fa89
docker exec --workdir /workspace/linura linura-s17-development \
  bash scripts/setup_codex_environment.sh --bindings
docker network disconnect bridge linura-s17-development
docker exec --workdir /workspace/linura linura-s17-development \
  bash scripts/preflight_codex_environment.sh
docker exec --workdir /workspace/linura linura-s17-development \
  bash scripts/run_codex.sh python3 tools/codex/doctor.py --all
```

Keep each task's clone, tools, caches and outputs private to its instance. Check
resources again before large builds. Source synchronization is explicit; run
preflight again on the actual task checkout, then affected tests and canonical
`cargo xtask check`. Setup/preflight/doctor results never replace Security,
CodeQL, native Arch/Hyprland, real authentication, VM, visual or maintained
physical-workstation evidence. The separate `tools/codex/native-auth` recipe
supplies official Polkit/GLib/Wayland development headers; this general base does
not claim native-auth readiness or run privileged session services.

Removing an instance discards its private tools and output; do not use that as a
source-backup strategy. Recovery copies, active task clones and qualification
evidence are never disposable build artifacts. Never prune them to make a gate
appear runnable. Update base/snapshot/graph pins only together after review.

## Optional source-analysis creation profile

Main's Python typing and multilingual formatting use additional, independently
locked tools. Create a **fresh** instance of the same image for them; do not
install into an active development/native builder. Check resources and verified
recovery copies first. This profile remains build infrastructure, not native or
full CI qualification. Its source mount is read-only:

```sh
docker run --detach --name linura-source-checks \
  --user 1000:1000 --cap-drop ALL --security-opt no-new-privileges \
  --cpus 1 --memory 1g --memory-swap 2g --pids-limit 128 --ulimit core=0 \
  --mount "type=bind,source=$PWD,target=/source,readonly" \
  "$LINURA_DEV_IMAGE"
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
  cp /source/tools/python-typecheck/package.json \
    /source/tools/python-typecheck/package-lock.json typing/
  npm ci --prefix typing --ignore-scripts --omit=optional --no-audit --no-fund
  cp /source/tools/source-format/package.json \
    /source/tools/source-format/package-lock.json format/
  npm ci --prefix format --ignore-scripts --no-audit --no-fund
  python3 -m venv clang
  clang/bin/python3 -m pip install --disable-pip-version-check --no-cache-dir \
    --require-hashes --only-binary=:all: --no-deps \
    -r /source/tools/source-format/clang-requirements.lock
'
docker network disconnect bridge linura-source-checks
docker exec --workdir /source linura-source-checks \
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
task files. Do not change the read-only mount or mass-format frozen sources.
This limited profile does **not** supply the pinned shfmt or Qt QML formatter,
Rust gates, Security/CodeQL or real session/PAM/power evidence. Their missing
prerequisites and unexecuted checks remain explicit; canonical CI's complete
installation and gate commands are unchanged.
