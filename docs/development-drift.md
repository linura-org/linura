# Inspecting development source drift

Run the repository-owned inspector before starting a new milestone or reusing an
old task checkout:

```bash
python3 tools/development_drift.py
python3 tools/development_drift.py /path/to/checkout --offline
python3 tools/development_drift.py /path/to/checkout --expected-main <prior-main-sha>
```

The default path is the checkout containing the script. A nested input directory
selects its Git worktree root. The JSON report compares local `origin/main` with
a live `ls-remote` observation, then inventories all local branches and registered
worktrees, including detached, locked, missing and prunable entries. Each accessible
worktree reports its commit, branch, staged/unstaged/untracked paths, whitespace
checks and ahead/behind counts against the observed tracking-main commit.
SHA-1 and SHA-256 repositories are supported. An optional prior SHA is a comparison
input, never a permanently hard-coded expected head.

| Exit | Meaning |
| --- | --- |
| `0` | All inspected worktrees are clean, attached and at tracking main; live main matches it; the observed inventory remained consistent |
| `1` | Inspection completed and observed source drift, such as local changes, a detached checkout, a stale tracking reference or a changed expected main |
| `2` | Inspection is incomplete: offline mode, unreachable/unsupported origin, inaccessible worktree, hidden index entries, incomplete history, command failure, timeout or concurrent inventory changes |

Incomplete inspection takes precedence over observed drift. `--offline` always
leaves live main unverified and returns `2`, while still reporting local findings.
An intentionally active topic worktree can cause exit `1`; that is an inventory
finding, not permission to reset it. Inactive branches are reported separately:
their divergence or missing upstream is not itself active-checkout drift. Recovery
branches under `backup/` are explicitly marked for preservation. Ahead/behind
counts describe ancestry; squash merging can leave unique ancestry even when
changes were integrated. No branch is declared safe to delete.

The inspector performs no fetch, pull, checkout, reset, clean, merge, rebase,
prune, configuration change or deletion. It disables optional Git index locks,
fsmonitor, external diff/textconv, automatic maintenance and replacement objects.
Assume-unchanged/skip-worktree entries and shallow/grafted history make the
inspection incomplete instead of permitting a false clean result. Inherited
`GIT_*` variables are rejected except `GIT_PAGER`, which is overridden by
`--no-pager`; remove overrides deliberately before repeating an inspection.

Live queries accept a single credential-free HTTPS or SSH origin (SSH uses the
`git` account or the SSH default; `git@host:path` is accepted). Embedded URL
credentials, URL query/fragment data, custom remote helpers and local transports
are rejected before network dispatch. Credential helpers and interactive prompts
are disabled; SSH requires existing host verification and noninteractive
authentication. A private remote that needs an interactive/helper login remains
unverified. The inspector uses the installed Git and SSH clients and the existing
developer trust configuration; it is not a sandbox for executing an untrusted
repository or transport configuration.

Each local command has a ten-second limit, each remote command twenty-five
seconds, and the whole Git-query budget defaults to 120 seconds. `--timeout`
accepts 1–600 seconds. Each command's captured output is limited to 4 MiB, with
a shared 32 MiB budget across commands. The inventory accepts at most 128
worktrees and 1,024 local branches. Bound exhaustion
is incomplete evidence, never a partial success. Timeout cleanup terminates the
command's process group. Reports omit remote URLs, raw stderr, lock/prune reasons,
commit messages and diff contents. Paths and branch names remain local information:
review them before sharing a report. Save reports only to an appropriate private
destination outside tracked source; the inspector writes JSON to standard output.

The snapshot is sequential. Ref, worktree, index-visibility and status inventories
are rechecked to detect concurrent changes, but this is not an atomic filesystem
snapshot or proof that every byte stayed unchanged. Ignored outputs, separate
clones and other unregistered directories are outside its scope. An absent
finding is not proof of a healthy disk, complete recovery backup or qualified
runtime behavior.

## Resolve findings without losing work

1. Inspect changed paths locally. Preserve useful edits and unique commits in
   persistent task/recovery storage before considering destructive cleanup.
   Never copy secrets into a report, patch attachment or model context.
2. Verify the intended origin independently. If tracking main is stale, fetch it
   explicitly, inspect ancestry and changes, then fast-forward a clean `main`
   with `git merge --ff-only origin/main`. Preserve local divergence for review;
   never use an automatic hard reset to manufacture alignment.
3. Keep assigned work in its existing topic branch/worktree. Review missing
   upstreams and inactive branches against merged PRs and retained recovery
   records. A gone upstream, old name, matching tree or squash merge does not
   authorize branch or backup deletion. Inspect missing-worktree metadata before
   any separately authorized prune.
4. Repeat the source inspection after intended edits and commits. Then run
   `bash scripts/preflight_codex_environment.sh`, the non-mutating output and
   authority-host checks in [development workspaces](development-workspaces.md),
   and `python3 tools/codex/doctor.py --all` to inventory host capabilities.
   Do not repair a task host or install mutable tools to hide a mismatch.
5. Run `bash scripts/run_codex.sh cargo xtask check` and every applicable gate
   on the final committed source. Keep unavailable native, VM, visual, Security
   and CodeQL evidence pending. A clean source report and readiness inventory
   cannot complete a milestone or qualify a prerequisite slice. For example,
   S21 depends on S17 in `contracts/v010-workstation-slices.toml`; source cleanup
   cannot promote S17 acceptance or create a second session/power authority.

Follow the [canonical review sequence](development-infrastructure.md#pull-request-qualification-sequence)
and [workspace retention rules](development-workspaces.md) throughout resolution.
