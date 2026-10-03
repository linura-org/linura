#!/usr/bin/env bash
set -euo pipefail

# Configure only as the environment's maintenance hook, before the task starts.
# Setup is idempotent and refreshes the locked graph for the selected checkout.
readonly REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
exec bash "$REPO_ROOT/scripts/setup_codex_environment.sh" "$@"
