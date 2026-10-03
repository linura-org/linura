#!/usr/bin/env bash
set -euo pipefail

readonly REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
# shellcheck source=scripts/lib/codex_source_state.sh
source scripts/lib/codex_source_state.sh
INITIAL_SOURCE_STATE="$(codex_source_state)"
readonly INITIAL_SOURCE_STATE
trap codex_source_state_exit_guard EXIT

case "${1:-}" in
  "") [[ $# -eq 0 ]] || exit 2 ;;
  --full) [[ $# -eq 1 ]] || exit 2 ;;
  *) echo 'usage: bash scripts/preflight_codex_environment.sh [--full]' >&2; exit 2 ;;
esac
export RUSTUP_AUTO_INSTALL=0

readonly VERSION_CONTRACT="tools/codex/versions.env"
if [[ ! -f "$VERSION_CONTRACT" ]]; then
  echo "missing Codex toolchain contract: $VERSION_CONTRACT" >&2
  exit 1
fi
# shellcheck disable=SC1090
source "$VERSION_CONTRACT"

: "${RUSTUP_VERSION:?}"
: "${RUST_VERSION:?}"
: "${CARGO_AUDIT_VERSION:?}"
: "${ACTIONLINT_VERSION:?}"
: "${PYTHON_MAJOR_MINOR:?}"
: "${HOST_OS:?}"
: "${HOST_ARCH:?}"

readonly RUSTUP_TARGET="x86_64-unknown-linux-gnu"
readonly RUST_TOOLCHAIN="${RUST_VERSION}-${RUSTUP_TARGET}"
readonly MIN_GLIBC_MAJOR=2
readonly MIN_GLIBC_MINOR=17
readonly CARGO_ROOT="${CARGO_HOME:-${HOME}/.cargo}"

export CARGO_HOME="$CARGO_ROOT"
export PATH="${CARGO_ROOT}/bin:${HOME}/.local/bin:${PATH}"

require_command() {
  local command_name="$1"
  if ! command -v "$command_name" >/dev/null 2>&1; then
    printf 'missing required command: %s\n' "$command_name" >&2
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

for command_name in bash cargo-audit cc getconf git python3 rustup sha256sum uname; do
  require_command "$command_name"
done

actual_os="$(uname -s)"
actual_arch="$(uname -m)"
test "$actual_os" = "$HOST_OS"
test "$actual_arch" = "$HOST_ARCH"

glibc_version="$(require_supported_glibc)"

actual_python="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
test "$actual_python" = "$PYTHON_MAJOR_MINOR"

if ! reports_exact_version "$RUSTUP_VERSION" rustup --version; then
  printf 'unexpected rustup version; expected exactly %s (run Codex environment setup)\n' "$RUSTUP_VERSION" >&2
  exit 1
fi

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
test "$repo_rust_version" = "$RUST_VERSION"

installed_rust_toolchain="$(
  rustup toolchain list | awk -v toolchain="$RUST_TOOLCHAIN" '
    $1 == toolchain { print $1; exit }
  '
)"
if [[ "$installed_rust_toolchain" != "$RUST_TOOLCHAIN" ]]; then
  printf 'missing required Rust toolchain: %s (run Codex environment setup)\n' "$RUST_TOOLCHAIN" >&2
  exit 1
fi

active_toolchain="$(rustup show active-toolchain | awk '{print $1}')"
if [[ "$active_toolchain" != "$RUST_TOOLCHAIN" ]]; then
  printf 'unexpected active Rust toolchain: %s; expected %s (run Codex environment setup)\n' \
    "$active_toolchain" "$RUST_TOOLCHAIN" >&2
  exit 1
fi

rustc_bin="$(rustup which --toolchain "$RUST_TOOLCHAIN" rustc)"
cargo_bin="$(rustup which --toolchain "$RUST_TOOLCHAIN" cargo)"
test -x "$rustc_bin"
test -x "$cargo_bin"

actual_rust="$("$rustc_bin" --version | awk '{print $2}')"
test "$actual_rust" = "$RUST_VERSION"

if ! reports_exact_version "$CARGO_AUDIT_VERSION" cargo-audit --version; then
  printf 'unexpected cargo-audit version; expected exactly %s\n' "$CARGO_AUDIT_VERSION" >&2
  exit 1
fi

actionlint_bin="${HOME}/.local/linura-tools/actionlint/${ACTIONLINT_VERSION}/actionlint"
test -x "$actionlint_bin"
if ! reports_exact_version "$ACTIONLINT_VERSION" "$actionlint_bin" -version; then
  printf 'unexpected actionlint version; expected exactly %s\n' "$ACTIONLINT_VERSION" >&2
  exit 1
fi

# Presence of the language toolchain does not prove its quality components exist.
rustup run "$RUST_TOOLCHAIN" cargo fmt --version >/dev/null
rustup run "$RUST_TOOLCHAIN" cargo clippy --version >/dev/null

# Prove the exact dependency graph is locally available without network mutation.
"$cargo_bin" metadata --locked --offline --format-version 1 >/dev/null

# Validate workflow syntax/contexts with the same pinned semantic validator CI uses.
"$actionlint_bin" -color

# Environment verification must not change tracked source.
codex_verify_source_state "$INITIAL_SOURCE_STATE"

if [[ "${1:-}" == "--full" ]]; then
  CARGO_NET_OFFLINE=true "$cargo_bin" xtask check
  codex_verify_source_state "$INITIAL_SOURCE_STATE"
fi

printf 'Linura Codex environment preflight passed.\n'
printf '  host: %s-%s (%s)\n' "$actual_os" "$actual_arch" "$glibc_version"
printf '  python: %s\n' "$(python3 --version)"
printf '  rustup: %s\n' "$(rustup --version | head -1)"
printf '  toolchain: %s\n' "$active_toolchain"
printf '  rustc: %s\n' "$("$rustc_bin" --version)"
printf '  cargo-audit: %s\n' "$(cargo-audit --version)"
printf '  actionlint: %s\n' "$("$actionlint_bin" -version | head -1)"
