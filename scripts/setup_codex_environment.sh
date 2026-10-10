#!/usr/bin/env bash
set -euo pipefail

readonly REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
# shellcheck source=scripts/lib/codex_source_state.sh
source scripts/lib/codex_source_state.sh
INITIAL_SOURCE_STATE="$(codex_source_state)"
readonly INITIAL_SOURCE_STATE
trap codex_source_state_exit_guard EXIT

BUILD_BINDINGS=false
case "${1:-}" in
  "") [[ $# -eq 0 ]] || exit 2 ;;
  --bindings) [[ $# -eq 1 ]] || exit 2; BUILD_BINDINGS=true ;;
  *) echo 'usage: bash scripts/setup_codex_environment.sh [--bindings]' >&2; exit 2 ;;
esac

# Canonical deterministic setup for Linura Codex/cloud development environments.
# This script intentionally does not apt-install mutable "latest" packages.
# Host primitives must be supplied by the configured Codex base environment.

readonly VERSION_CONTRACT="tools/codex/versions.env"
if [[ ! -f "$VERSION_CONTRACT" ]]; then
  echo "missing Codex toolchain contract: $VERSION_CONTRACT" >&2
  exit 1
fi
# shellcheck disable=SC1090
source "$VERSION_CONTRACT"

: "${RUSTUP_VERSION:?}"
: "${RUSTUP_INIT_SHA256:?}"
: "${RUST_VERSION:?}"
: "${CARGO_AUDIT_VERSION:?}"
: "${ACTIONLINT_VERSION:?}"
: "${ACTIONLINT_SHA256:?}"
: "${RUFF_VERSION:?}"
: "${PYTHON_MAJOR_MINOR:?}"
: "${HOST_OS:?}"
: "${HOST_ARCH:?}"

readonly RUSTUP_TARGET="x86_64-unknown-linux-gnu"
readonly RUST_TOOLCHAIN="${RUST_VERSION}-${RUSTUP_TARGET}"
readonly MIN_GLIBC_MAJOR=2
readonly MIN_GLIBC_MINOR=17
readonly RUSTUP_INIT_URL="https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/${RUSTUP_TARGET}/rustup-init"
readonly ACTIONLINT_ARCHIVE="actionlint_${ACTIONLINT_VERSION}_linux_amd64.tar.gz"
readonly ACTIONLINT_URL="https://github.com/rhysd/actionlint/releases/download/v${ACTIONLINT_VERSION}/${ACTIONLINT_ARCHIVE}"
readonly TOOL_ROOT="${HOME}/.local/linura-tools"
readonly RUFF_ROOT="${TOOL_ROOT}/ruff"
readonly RUFF_LOCK="tools/python/ruff-requirements.lock"
readonly ACTIONLINT_ROOT="${TOOL_ROOT}/actionlint/${ACTIONLINT_VERSION}"
readonly BIN_ROOT="${HOME}/.local/bin"
readonly CARGO_ROOT="${CARGO_HOME:-${HOME}/.cargo}"
readonly RUSTUP_BOOTSTRAP_LIB="scripts/lib/bootstrap_rustup.sh"

if [[ ! -f "$RUSTUP_BOOTSTRAP_LIB" ]]; then
  printf 'missing Codex rustup bootstrap library: %s\n' "$RUSTUP_BOOTSTRAP_LIB" >&2
  exit 1
fi
# shellcheck source=scripts/lib/bootstrap_rustup.sh
source "$RUSTUP_BOOTSTRAP_LIB"

require_command() {
  local command_name="$1"
  if ! command -v "$command_name" >/dev/null 2>&1; then
    printf 'missing required host command: %s\n' "$command_name" >&2
    exit 1
  fi
}

reports_exact_version() {
  local expected="$1"
  shift
  local output token
  if ! output="$("$@" 2>/dev/null)"; then
    return 1
  fi
  while IFS= read -r token; do
    token="${token#v}"
    if [[ "$token" == "$expected" ]]; then
      return 0
    fi
  done < <(printf '%s\n' "$output" | tr '[:space:]' '\n')
  return 1
}

require_supported_glibc() {
  local version_text major minor
  version_text="$(getconf GNU_LIBC_VERSION 2>/dev/null || true)"
  if [[ ! "$version_text" =~ ^glibc[[:space:]]+([0-9]+)\.([0-9]+)([^0-9].*)?$ ]]; then
    printf 'unsupported C runtime: %s; expected glibc >= %d.%d for %s\n' \
      "${version_text:-unknown}" "$MIN_GLIBC_MAJOR" "$MIN_GLIBC_MINOR" "$RUSTUP_TARGET" >&2
    return 1
  fi
  major="${BASH_REMATCH[1]}"
  minor="${BASH_REMATCH[2]}"
  if (( 10#$major < MIN_GLIBC_MAJOR || (10#$major == MIN_GLIBC_MAJOR && 10#$minor < MIN_GLIBC_MINOR) )); then
    printf 'unsupported glibc version: %s; expected >= %d.%d for %s\n' \
      "$version_text" "$MIN_GLIBC_MAJOR" "$MIN_GLIBC_MINOR" "$RUSTUP_TARGET" >&2
    return 1
  fi
  printf '%s\n' "$version_text"
}

for command_name in bash cc curl getconf git python3 sha256sum tar uname; do
  require_command "$command_name"
done

actual_os="$(uname -s)"
actual_arch="$(uname -m)"
if [[ "$actual_os" != "$HOST_OS" || "$actual_arch" != "$HOST_ARCH" ]]; then
  printf 'unsupported Codex setup host: %s-%s; expected %s-%s\n' \
    "$actual_os" "$actual_arch" "$HOST_OS" "$HOST_ARCH" >&2
  exit 1
fi

glibc_version="$(require_supported_glibc)"

actual_python="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
if [[ "$actual_python" != "$PYTHON_MAJOR_MINOR" ]]; then
  printf 'unsupported Python major/minor: %s; expected %s.x\n' "$actual_python" "$PYTHON_MAJOR_MINOR" >&2
  exit 1
fi

mkdir -p "$ACTIONLINT_ROOT" "$BIN_ROOT" "$CARGO_ROOT/bin"
export CARGO_HOME="$CARGO_ROOT"
export PATH="${CARGO_ROOT}/bin:${BIN_ROOT}:${PATH}"

# rust-toolchain.toml remains the language-version source of truth. The Codex
# contract fixes the host triple independently so an existing rustup default-host
# cannot silently select a musl or otherwise incompatible toolchain.
repo_rust_version="$(python3 - <<'PY'
import pathlib
import re

text = pathlib.Path('rust-toolchain.toml').read_text(encoding='utf-8')
match = re.search(r'^channel\s*=\s*"([^"]+)"\s*$', text, re.MULTILINE)
if match is None:
    raise SystemExit('rust-toolchain.toml does not declare a channel')
print(match.group(1))
PY
)"
if [[ "$repo_rust_version" != "$RUST_VERSION" ]]; then
  printf 'Codex/toolchain drift: contract=%s rust-toolchain.toml=%s\n' \
    "$RUST_VERSION" "$repo_rust_version" >&2
  exit 1
fi

# A fresh Codex base image is not required to ship rustup. Bootstrap the exact
# repository-pinned rustup-init binary through the isolated helper, which
# verifies its digest and executes it with the canonical multicall basename.
# Re-running setup is idempotent.
if ! command -v rustup >/dev/null 2>&1 || ! reports_exact_version "$RUSTUP_VERSION" rustup --version; then
  bootstrap_rustup "$RUSTUP_INIT_URL" "$RUSTUP_INIT_SHA256" "$RUSTUP_TARGET"
  hash -r
fi
require_command rustup
if ! reports_exact_version "$RUSTUP_VERSION" rustup --version; then
  printf 'unexpected rustup version after setup; expected exactly %s\n' "$RUSTUP_VERSION" >&2
  exit 1
fi

# Keep both the rustup version and host selection deterministic even when the
# base image already carried a differently configured rustup installation.
rustup set auto-self-update disable
rustup set default-host "$RUSTUP_TARGET"
rustup toolchain install "$RUST_TOOLCHAIN" --profile minimal --component clippy --component rustfmt --no-self-update
rustup default "$RUST_TOOLCHAIN"
if ! reports_exact_version "$RUSTUP_VERSION" rustup --version; then
  printf 'rustup self-updated during toolchain setup; expected exactly %s\n' "$RUSTUP_VERSION" >&2
  exit 1
fi
active_toolchain="$(rustup show active-toolchain | awk '{print $1}')"
if [[ "$active_toolchain" != "$RUST_TOOLCHAIN" ]]; then
  printf 'unexpected active Rust toolchain: %s; expected %s\n' "$active_toolchain" "$RUST_TOOLCHAIN" >&2
  exit 1
fi

for command_name in cargo rustc; do
  require_command "$command_name"
done
actual_rust="$(rustc --version | awk '{print $2}')"
if [[ "$actual_rust" != "$RUST_VERSION" ]]; then
  printf 'unexpected rustc version: %s (expected %s)\n' "$actual_rust" "$RUST_VERSION" >&2
  exit 1
fi

# Keep the security tool exact. Building cargo-audit from its published locked
# source graph relies on the host-provided `cc` linker checked above.
if ! command -v cargo-audit >/dev/null 2>&1 || ! reports_exact_version "$CARGO_AUDIT_VERSION" cargo-audit --version; then
  cargo install cargo-audit --locked --force --version "$CARGO_AUDIT_VERSION"
fi
if ! reports_exact_version "$CARGO_AUDIT_VERSION" cargo-audit --version; then
  printf 'unexpected cargo-audit version after setup; expected exactly %s\n' "$CARGO_AUDIT_VERSION" >&2
  exit 1
fi

# Install actionlint from the exact archive and digest already trusted by Linura CI.
actionlint_bin="$ACTIONLINT_ROOT/actionlint"
if [[ ! -x "$actionlint_bin" ]] || ! reports_exact_version "$ACTIONLINT_VERSION" "$actionlint_bin" -version; then
  archive_path="$(mktemp)"
  curl --fail --location --proto '=https' --tlsv1.2 --retry 3 \
    --output "$archive_path" \
    "$ACTIONLINT_URL"
  printf '%s  %s\n' "$ACTIONLINT_SHA256" "$archive_path" | sha256sum --check --strict
  rm -rf "$ACTIONLINT_ROOT"
  mkdir -p "$ACTIONLINT_ROOT"
  tar -xzf "$archive_path" -C "$ACTIONLINT_ROOT" actionlint
  rm -f "$archive_path"
  chmod 0755 "$actionlint_bin"
fi
ln -sfn "$actionlint_bin" "$BIN_ROOT/actionlint"
if ! reports_exact_version "$ACTIONLINT_VERSION" "$actionlint_bin" -version; then
  printf 'unexpected actionlint version after setup; expected exactly %s\n' "$ACTIONLINT_VERSION" >&2
  exit 1
fi

# Provision Ruff from a hash-locked wheel set. Keep it isolated from the
# optional bindings build environment so core lint readiness is deterministic
# and a bindings refresh cannot remove the canonical linter.
ruff_bin="$RUFF_ROOT/bin/ruff"
ruff_marker="$RUFF_ROOT/.linura-ruff-lock-sha256"
ruff_lock_digest="$(sha256sum "$RUFF_LOCK" | awk '{print $1}')"
ruff_marker_digest=""
if [[ -f "$ruff_marker" && ! -L "$ruff_marker" ]]; then
  read -r ruff_marker_digest < "$ruff_marker" || true
fi
if [[ ! -x "$ruff_bin" || "$ruff_marker_digest" != "$ruff_lock_digest" ]] \
  || ! reports_exact_version "$RUFF_VERSION" "$ruff_bin" --version; then
  if [[ -L "$TOOL_ROOT" || -L "$RUFF_ROOT" ]]; then
    echo 'refusing to recreate a symlinked Ruff environment' >&2
    exit 1
  fi
  python3 -m venv --clear "$RUFF_ROOT"
  "$RUFF_ROOT/bin/python3" -m pip install \
    --disable-pip-version-check --no-cache-dir --require-hashes --only-binary=:all: --no-deps \
    -r "$RUFF_LOCK"
  printf '%s\n' "$ruff_lock_digest" > "$ruff_marker"
fi
ln -sfn "$ruff_bin" "$BIN_ROOT/ruff"
if ! reports_exact_version "$RUFF_VERSION" "$ruff_bin" --version; then
  printf 'unexpected Ruff version after setup; expected exactly %s\n' "$RUFF_VERSION" >&2
  exit 1
fi

# Warm the exact Cargo dependency graph without modifying Cargo.lock.
cargo fetch --locked

if [[ "$BUILD_BINDINGS" == true ]]; then
  python_root="$TOOL_ROOT/python"
  # A version-only pip install over an existing venv preserves undeclared wheels.
  if [[ -L "$TOOL_ROOT" || -L "$python_root" ]]; then
    echo 'refusing to clear a symlinked Codex bindings environment' >&2
    exit 1
  fi
  # Clear the entire isolated environment on *every* setup/maintenance pass:
  # a changed lock, a contaminated site-packages tree, or a failed prior run
  # must never be accepted as a trusted cached build environment.
  python3 -m venv --clear "$python_root"
  "$python_root/bin/python3" -m pip install \
    --disable-pip-version-check --no-cache-dir --require-hashes --only-binary=:all: --no-deps \
    -r bindings/python/build-requirements.lock
  # Written only after successful installation. The doctor verifies the
  # lock digest *and* the complete installed distribution/version set.
  sha256sum bindings/python/build-requirements.lock |
    awk '{print $1}' > "$python_root/.linura-bindings-lock-sha256"
fi

# Run the same task-time preflight in a separate process. CI also runs it from
# a host-only PATH to verify discovery without inherited setup exports.
bash scripts/preflight_codex_environment.sh
if [[ "$BUILD_BINDINGS" == true ]]; then
  python3 tools/codex/doctor.py --profile bindings
fi

# Setup is not allowed to repair or rewrite tracked repository state.
codex_verify_source_state "$INITIAL_SOURCE_STATE"

printf 'Linura Codex environment ready.\n'
printf '  host: %s-%s (%s)\n' "$actual_os" "$actual_arch" "$glibc_version"
printf '  python: %s\n' "$(python3 --version)"
printf '  rustup: %s\n' "$(rustup --version | head -1)"
printf '  toolchain: %s\n' "$active_toolchain"
printf '  rustc: %s\n' "$(rustc --version)"
printf '  cargo: %s\n' "$(cargo --version)"
printf '  cargo-audit: %s\n' "$(cargo-audit --version)"
printf '  actionlint: %s\n' "$("$actionlint_bin" -version | head -1)"
printf '  ruff: %s\n' "$("$ruff_bin" --version)"
printf 'Run: bash scripts/preflight_codex_environment.sh\n'
