#!/usr/bin/env bash
set -euo pipefail

# Setup exports cannot persist across Codex setup/task processes. Use this
# explicit entry point instead of changing a user's shell startup files.
readonly REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
export CARGO_HOME="${CARGO_HOME:-${HOME}/.cargo}"
# A task shell must never fetch a missing or conflicting Rust toolchain implicitly.
export RUSTUP_AUTO_INSTALL=0
export PATH="${CARGO_HOME}/bin:${HOME}/.local/bin:${PATH}"
cd "$REPO_ROOT"
if [[ $# -eq 0 ]]; then
  echo 'usage: bash scripts/run_codex.sh <development-command> [args...]' >&2
  exit 2
fi
# Development commands retain the caller's permissions. This is not a product
# executor, credential broker, shell-evaluation API, or qualification oracle.
exec "$@"
