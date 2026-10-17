#!/usr/bin/bash
set -euo pipefail

# Instance provisioning and storage identity remain operator responsibilities.
# This step creates only fresh private run directories, never a mount or disk.
environment="${1:?qualification environment is required}"
source_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
: "${GITHUB_RUN_ID:?}"
: "${GITHUB_RUN_ATTEMPT:?}"
: "${GITHUB_JOB:?}"
: "${GITHUB_ENV:?}"
: "${SOURCE_SHA:?}"

storage_root="${LINURA_STORAGE_ROOT:-}"
storage_id="${LINURA_STORAGE_ID:-}"
storage_class="dedicated"
if [[ -n "$storage_root" || -n "$storage_id" ]]; then
    [[ -n "$storage_root" && -n "$storage_id" ]] || {
        echo "dedicated qualification storage requires both root and UUID" >&2
        exit 2
    }
elif [[ "${GITHUB_ACTIONS:-}" == true &&
    "${RUNNER_ENVIRONMENT:-}" == github-hosted &&
    "${RUNNER_OS:-}" == Linux ]]; then
    : "${RUNNER_TEMP:?GitHub-hosted RUNNER_TEMP is required}"
    storage_root="$RUNNER_TEMP/linura-data"
    storage_class="github-hosted-ephemeral"
else
    echo "heavy execution requires UUID-bound dedicated storage outside GitHub-hosted runners" >&2
    exit 2
fi

run_id="gh-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}-${GITHUB_JOB}"
umask 077
LINURA_STORAGE_ROOT="$storage_root" LINURA_STORAGE_ID="$storage_id" \
    LINURA_STORAGE_CLASS="$storage_class" \
    python3 "$source_root/tools/development_storage.py" \
    --source-root "$source_root" --environment "$environment" --run "$run_id" \
    prepare --source-sha "$SOURCE_SHA" --format env >>"$GITHUB_ENV"
printf 'LINURA_STORAGE_ROOT=%s\nLINURA_STORAGE_ID=%s\nLINURA_STORAGE_CLASS=%s\n' \
    "$storage_root" "$storage_id" "$storage_class" >>"$GITHUB_ENV"
