#!/usr/bin/env bash
# Lint every complete workflow with pinned actionlint. No source projection is needed.
set -euo pipefail

if [[ $# -ne 1 || ! -x "$1" ]]; then
  printf 'expected exactly one executable actionlint binary argument\n' >&2
  exit 2
fi
actionlint_bin="$1"
test -f .github/workflows/applicable-qualification.yml
python3 tools/applicable_qualification.py validate > /dev/null

mapfile -d '' workflow_files < <(
  find .github/workflows -maxdepth 1 -type f \( -name '*.yml' -o -name '*.yaml' \) -print0
)
test "${#workflow_files[@]}" -gt 0
"$actionlint_bin" -color "${workflow_files[@]}"
