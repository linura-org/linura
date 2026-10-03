#!/usr/bin/env bash

# Hash both index and worktree diffs, HEAD and index entries. Pre-existing edits
# are valid task input; changing them during environment checks is not. Never
# print source contents (which may contain sensitive work in progress).
codex_source_state() {
  {
    git rev-parse HEAD || return
    git ls-files --stage -z || return
    git diff --no-ext-diff --no-textconv --binary || return
    git diff --cached --no-ext-diff --no-textconv --binary || return
  } | sha256sum
}

codex_verify_source_state() {
  local expected="$1" actual
  actual="$(codex_source_state)" || return
  if [[ "$actual" != "$expected" ]]; then
    echo 'Codex environment command changed tracked source or index state' >&2
    return 1
  fi
}

# Validate source integrity even when an earlier command fails. A failing
# validator must not be allowed to hide changes it made to tracked source.
# Both callers set INITIAL_SOURCE_STATE before installing this EXIT trap.
codex_source_state_exit_guard() {
  local original_status="$?"
  trap - EXIT
  if ! codex_verify_source_state "$INITIAL_SOURCE_STATE"; then
    exit 1
  fi
  exit "$original_status"
}
