#!/usr/bin/env bash
# Pinned actionlint 1.7.12 cannot parse GitHub's supported concurrency.queue
# key. Validate the full reviewed source first; project away ONLY that one
# independently validated key for actionlint while checking every other byte.
set -euo pipefail

if [[ $# -ne 1 || ! -x "$1" ]]; then
  printf 'expected exactly one executable actionlint binary argument\n' >&2
  exit 2
fi
actionlint_bin="$1"
test -f .github/workflows/applicable-qualification.yml
python3 tools/applicable_qualification.py validate > /dev/null

mapfile -d '' workflow_files < <(
  find .github/workflows -maxdepth 1 -type f \( -name '*.yml' -o -name '*.yaml' \) ! -name applicable-qualification.yml -print0
)
test "${#workflow_files[@]}" -gt 0
"$actionlint_bin" -color "${workflow_files[@]}"
sed '/^      queue: max$/d' .github/workflows/applicable-qualification.yml |
  "$actionlint_bin" -color -
