#!/usr/bin/env bash
set -euo pipefail

# Setup exports cannot persist across Codex setup/task processes. Use this
# explicit entry point instead of changing a user's shell startup files.
readonly REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
export CARGO_HOME="${CARGO_HOME:-${HOME}/.cargo}"
# A task shell must never fetch a missing or conflicting Rust toolchain implicitly.
export RUSTUP_AUTO_INSTALL=0
readonly PYTHON_BIN="${HOME}/.local/linura-tools/python312/bin"
if [[ ! -L "$PYTHON_BIN/python3" || ! -x "$PYTHON_BIN/python3" ]]; then
    echo 'Linura Python 3.12 selection is missing; run environment setup' >&2
    exit 1
fi
export PATH="$PYTHON_BIN:${CARGO_HOME}/bin:${HOME}/.local/bin:${PATH}"
if [[ "$(python3 -I -S -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')" != 3.12 ]]; then
    echo 'Linura requires a verified Python 3.12 interpreter; no system Python fallback' >&2
    exit 1
fi
cd "$REPO_ROOT"
if [[ $# -eq 0 ]]; then
    echo 'usage: bash scripts/run_codex.sh <development-command> [args...]' >&2
    exit 2
fi
# Development commands retain the caller's permissions. This is not a product
# executor, credential broker, shell-evaluation API, or qualification oracle.
exec "$@"
