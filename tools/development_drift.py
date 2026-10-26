#!/usr/bin/env python3
"""Inventory development source drift without changing Git state or source files.

Exit 0: verified source alignment; 1: observed drift; 2: incomplete inspection.
This is a diagnostic snapshot, never qualification or permission to discard work.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import datetime as dt
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import time
from typing import Any
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
MAX_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_TOTAL_OUTPUT_BYTES = 32 * 1024 * 1024
MAX_WORKTREES = 128
MAX_BRANCHES = 1024
SHA = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
TRACKING = "refs/remotes/origin/main"


class AuditError(ValueError):
    """Only fixed diagnostic codes reach reports; never raw Git diagnostics."""


@dataclass(frozen=True)
class Result:
    returncode: int | None
    output: bytes = b""
    error: str | None = None


class Git:
    def __init__(self, timeout: float = 120) -> None:
        # Reject overrides rather than silently inspecting a different repository
        # or allowing tracing to leak credentials into an inherited log sink.
        if any(key.startswith("GIT_") and key != "GIT_PAGER" for key in os.environ):
            raise AuditError("inherited_git_environment")
        self.deadline = time.monotonic() + timeout
        self.remaining_output = MAX_TOTAL_OUTPUT_BYTES
        self.environment = os.environ.copy()
        self.environment.update(
            GIT_CONFIG_NOSYSTEM="1",
            GIT_CONFIG_GLOBAL=os.devnull,
            GIT_NO_REPLACE_OBJECTS="1",
            GIT_OPTIONAL_LOCKS="0",
            GIT_TERMINAL_PROMPT="0",
            GIT_ASKPASS="/bin/false",
            SSH_ASKPASS="/bin/false",
            LC_ALL="C",
        )

    def run(self, cwd: Path, *args: str, remote: bool = False) -> Result:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            return Result(None, error="audit_timeout")
        command = [
            "git",
            "--no-optional-locks",
            "--no-pager",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.untrackedCache=false",
            "-c",
            "gc.auto=0",
            "-c",
            "maintenance.auto=false",
            "-c",
            "credential.helper=",
            "-c",
            "core.askPass=/bin/false",
            "-c",
            "core.sshCommand=ssh -oBatchMode=yes -oStrictHostKeyChecking=yes",
            "-c",
            "protocol.allow=never",
            "-c",
            "protocol.https.allow=always",
            "-c",
            "protocol.ssh.allow=always",
            "-C",
            str(cwd),
            *args,
        ]
        process: subprocess.Popen[bytes] | None = None
        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env=self.environment,
                start_new_session=True,
            )
            assert process.stdout is not None
            deadline = time.monotonic() + min(25 if remote else 10, remaining)
            output = bytearray()
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while selector.get_map():
                    wait = deadline - time.monotonic()
                    if wait <= 0:
                        return Result(None, error="command_timeout")
                    for key, _ in selector.select(wait):
                        chunk = os.read(key.fd, 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                        else:
                            self.remaining_output -= len(chunk)
                            if self.remaining_output < 0:
                                return Result(None, error="audit_output_limit")
                            output.extend(chunk)
                            if len(output) > MAX_OUTPUT_BYTES:
                                return Result(None, error="output_limit")
                try:
                    code = process.wait(timeout=max(0, deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    return Result(None, error="command_timeout")
            return Result(code, bytes(output))
        except OSError:
            return Result(None, error="command_unavailable")
        finally:
            if process is not None:
                # On failure, kill helpers too, before reaping the session leader.
                if process.returncode is None:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                process.wait()
                if process.stdout is not None:
                    process.stdout.close()

    def require(self, cwd: Path, *args: str) -> bytes:
        result = self.run(cwd, *args)
        if result.error or result.returncode != 0:
            raise AuditError(result.error or "git_query_failed")
        return result.output


def oid(value: bytes) -> str:
    text = value.decode("ascii", errors="replace").removesuffix("\n")
    if SHA.fullmatch(text) is None:
        raise AuditError("invalid_object_id")
    return text


def optional_oid(git: Git, root: Path, ref: str) -> str | None:
    result = git.run(root, "rev-parse", "--verify", "--quiet", ref)
    if result.error:
        raise AuditError(result.error)
    if result.returncode == 1:
        return None
    if result.returncode != 0:
        raise AuditError("ref_query_failed")
    return oid(result.output)


def live_main(git: Git, root: Path) -> tuple[str | None, str]:
    # Git transports receive URLs as arguments. Reject embedded credentials,
    # custom helpers and local transports before starting a network subprocess.
    try:
        urls = git.require(root, "remote", "get-url", "--all", "origin").splitlines()
        if len(urls) != 1:
            return None, "unsupported_origin"
        url = urls[0].decode("ascii")
        if any(ord(char) <= 32 or ord(char) == 127 for char in url):
            return None, "unsupported_origin"
        parsed = urlsplit(url)
        https = parsed.scheme == "https" and parsed.username is None
        ssh = parsed.scheme == "ssh" and parsed.username in {None, "git"}
        scp = re.fullmatch(r"git@[a-zA-Z0-9.-]+:[a-zA-Z0-9_./-]+", url) is not None
        if not scp and not (
            (https or ssh)
            and parsed.hostname
            and parsed.path
            and parsed.password is None
            and not parsed.query
            and not parsed.fragment
        ):
            return None, "unsupported_origin"
        helper = git.run(root, "config", "--get", "remote.origin.vcs")
        if helper.error or helper.returncode != 1:
            return None, "unsupported_origin"
    except (UnicodeError, ValueError) as exc:
        return None, str(exc) if isinstance(exc, AuditError) else "unsupported_origin"
    remote = git.run(
        root,
        "ls-remote",
        "--exit-code",
        "--heads",
        "--upload-pack=git-upload-pack",
        "origin",
        "refs/heads/main",
        remote=True,
    )
    match = re.fullmatch(
        rb"([0-9a-f]{40}|[0-9a-f]{64})\trefs/heads/main\n", remote.output
    )
    if remote.error or remote.returncode != 0 or match is None:
        return None, remote.error or "remote_unavailable_or_invalid"
    return oid(match[1]), "verified"


def parse_worktrees(data: bytes) -> list[dict[str, Any]]:
    if not data or not data.endswith(b"\0\0"):
        raise AuditError("invalid_worktree_inventory")
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for block in data[:-2].split(b"\0\0"):
        entry: dict[str, Any] = {}
        for field in block.split(b"\0"):
            name, _, value = field.partition(b" ")
            key = name.decode("ascii", errors="replace")
            if (
                key
                not in {
                    "worktree",
                    "HEAD",
                    "branch",
                    "bare",
                    "detached",
                    "locked",
                    "prunable",
                }
                or key in entry
            ):
                raise AuditError("invalid_worktree_inventory")
            # Lock/prune reasons are arbitrary local text; retain only the flag.
            entry[key] = (
                True
                if key in {"bare", "detached", "locked", "prunable"}
                else os.fsdecode(value)
            )
        path = entry.get("worktree")
        if not isinstance(path, str) or not Path(path).is_absolute() or path in seen:
            raise AuditError("invalid_worktree_inventory")
        if not entry.get("bare") and (
            SHA.fullmatch(entry.get("HEAD", "")) is None
            or bool(entry.get("branch")) == bool(entry.get("detached"))
        ):
            raise AuditError("invalid_worktree_inventory")
        seen.add(path)
        result.append(entry)
    if len(result) > MAX_WORKTREES:
        raise AuditError("worktree_limit")
    return result


def parse_status(data: bytes) -> list[dict[str, str]]:
    if not data:
        return []
    if not data.endswith(b"\0"):
        raise AuditError("invalid_status")
    fields = iter(data[:-1].split(b"\0"))
    result = []
    for field in fields:
        if (
            len(field) < 4
            or field[2:3] != b" "
            or any(c not in b" MADRCUT?!" for c in field[:2])
        ):
            raise AuditError("invalid_status")
        entry = {"status": field[:2].decode("ascii"), "path": os.fsdecode(field[3:])}
        if b"R" in field[:2] or b"C" in field[:2]:
            original = next(fields, b"")
            if not original:
                raise AuditError("invalid_status")
            entry["original_path"] = os.fsdecode(original)
        result.append(entry)
    return result


def relation(git: Git, root: Path, left: str, right: str) -> dict[str, Any]:
    data = git.require(root, "rev-list", "--left-right", "--count", f"{left}...{right}")
    if re.fullmatch(rb"[0-9]+\s+[0-9]+\n", data) is None:
        raise AuditError("invalid_ancestry_counts")
    ahead, behind = map(int, data.split())
    return {
        "ahead": ahead,
        "behind": behind,
        "state": "diverged"
        if ahead and behind
        else "ahead"
        if ahead
        else "behind"
        if behind
        else "equal",
    }


def branches(
    git: Git, root: Path, baseline: str | None
) -> tuple[bytes, list[dict[str, Any]]]:
    data = git.require(
        root,
        "for-each-ref",
        "--format=%(refname)%00%(objectname)%00%(upstream)",
        "refs/heads/",
    )
    lines = data.splitlines()
    if len(lines) > MAX_BRANCHES:
        raise AuditError("branch_limit")
    result = []
    for line in lines:
        parts = line.split(b"\0")
        if len(parts) != 3 or not parts[0].startswith(b"refs/heads/"):
            raise AuditError("invalid_branch_inventory")
        ref, sha, upstream = parts
        name = os.fsdecode(ref.removeprefix(b"refs/heads/"))
        head = oid(sha)
        entry: dict[str, Any] = {
            "branch": name,
            "sha": head,
            "upstream": os.fsdecode(upstream) or None,
        }
        if baseline:
            entry["vs_tracking_main"] = relation(git, root, head, baseline)
        if upstream:
            target = optional_oid(git, root, os.fsdecode(upstream))
            entry["upstream_sha"] = target
            entry["upstream_state"] = (
                relation(git, root, head, target) if target else {"state": "missing"}
            )
        entry["retention"] = (
            "preserve-recovery"
            if name.startswith("backup/")
            else "review-before-retirement"
        )
        result.append(entry)
    return data, result


def status(git: Git, path: Path) -> bytes:
    return git.require(
        path,
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
        "--ignore-submodules=none",
    )


def index_visibility(git: Git, path: Path) -> bytes:
    data = git.require(path, "ls-files", "-v", "-z")
    if data and not data.endswith(b"\0"):
        raise AuditError("invalid_index_inventory")
    for entry in data.split(b"\0")[:-1]:
        if len(entry) < 3 or entry[1:2] != b" ":
            raise AuditError("invalid_index_inventory")
        if entry[:1].islower() or entry[:1] == b"S":
            # assume-unchanged/skip-worktree can conceal modified source files.
            raise AuditError("hidden_index_entries")
    return data


def summarize(
    git: Git, path: Path, common: Path, baseline: str | None
) -> tuple[dict[str, Any], bytes, bytes]:
    actual_common = Path(
        os.fsdecode(
            git.require(path, "rev-parse", "--path-format=absolute", "--git-common-dir")
        ).removesuffix("\n")
    ).resolve()
    if actual_common != common:
        raise AuditError("worktree_repository_mismatch")
    head = oid(git.require(path, "rev-parse", "--verify", "HEAD^{commit}"))
    branch = git.run(path, "symbolic-ref", "--quiet", "HEAD")
    if branch.error or branch.returncode not in {0, 1}:
        raise AuditError(branch.error or "branch_query_failed")
    index = index_visibility(git, path)
    snapshot = status(git, path)
    report: dict[str, Any] = {
        "directory": str(path),
        "head_sha": head,
        "branch": os.fsdecode(branch.output).removesuffix("\n")
        if branch.returncode == 0
        else None,
        "changes": parse_status(snapshot),
        "diff_checks": {},
    }
    for name, args in (("worktree", ()), ("index", ("--cached",))):
        check = git.run(
            path, "diff", "--no-ext-diff", "--no-textconv", "--check", *args, "--"
        )
        if check.error or check.returncode not in {0, 2}:
            raise AuditError(check.error or "diff_check_failed")
        # diff --check includes offending file *contents*. Never emit its output.
        report["diff_checks"][name] = {"ok": check.returncode == 0}
    if baseline:
        report["vs_tracking_main"] = relation(git, path, head, baseline)
    return report, snapshot, index


def audit(
    repo: Path,
    *,
    offline: bool = False,
    expected_main: str | None = None,
    timeout: float = 120,
) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema_version": 1,
        "audit_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "read_only": True,
        "qualification_evidence": False,
        "source_ready": False,
        "snapshot_consistent": False,
        "findings": [],
        "scope": "selected repository, registered worktrees and local branches; ignored outputs and separate clones are outside scope",
    }

    def finding(code: str, severity: str, **details: Any) -> None:
        report["findings"].append({"code": code, "severity": severity, **details})

    try:
        if not 1 <= timeout <= 600:
            raise AuditError("invalid_timeout")
        if expected_main is not None and SHA.fullmatch(expected_main) is None:
            raise AuditError("invalid_expected_main")
        git = Git(timeout)
        candidate = repo.expanduser().resolve()
        root = Path(
            os.fsdecode(
                git.require(candidate, "rev-parse", "--show-toplevel")
            ).removesuffix("\n")
        ).resolve()
        common = Path(
            os.fsdecode(
                git.require(
                    root, "rev-parse", "--path-format=absolute", "--git-common-dir"
                )
            ).removesuffix("\n")
        ).resolve()
        report["repository"] = str(root)
        shallow = git.require(root, "rev-parse", "--is-shallow-repository")
        if shallow != b"false\n" or (common / "info/grafts").exists():
            raise AuditError("incomplete_or_grafted_history")
        tracking = optional_oid(git, root, TRACKING)
        baseline: dict[str, Any] = {
            "tracking_main_sha": tracking,
            "live_main_sha": None,
            "expected_main_sha": expected_main,
            "remote_query": "not_requested",
        }
        report["baseline"] = baseline
        if tracking is None:
            finding("tracking_main_missing", "drift")
        if offline:
            finding("live_main_unverified", "incomplete")
        else:
            live, query_status = live_main(git, root)
            baseline["remote_query"] = query_status
            if live is None:
                finding("live_main_unverified", "incomplete")
            else:
                baseline.update(live_main_sha=live, remote_query="verified")
                if tracking != live:
                    finding("tracking_main_stale", "drift")
                if expected_main is not None and expected_main != live:
                    finding("expected_main_changed", "drift")
        worktree_data = git.require(root, "worktree", "list", "--porcelain", "-z")
        worktrees = parse_worktrees(worktree_data)
        report["registered_worktrees"] = worktrees
        branch_data, report["local_branches"] = branches(git, root, tracking)
        snapshots: list[tuple[Path, bytes, bytes, str]] = []
        found_primary = False
        for worktree in worktrees:
            if worktree.get("bare"):
                continue
            path = Path(worktree["worktree"])
            try:
                summary, snapshot, index = summarize(git, path, common, tracking)
                worktree["audit"] = summary
                if path.resolve() == root:
                    found_primary = True
                    report["primary_checkout"] = summary
                if summary["head_sha"] != worktree["HEAD"] or summary[
                    "branch"
                ] != worktree.get("branch"):
                    finding(
                        "worktree_changed_during_audit",
                        "incomplete",
                        directory=str(path),
                    )
                snapshots.append((path, snapshot, index, summary["head_sha"]))
                if summary["changes"]:
                    finding("uncommitted_changes", "drift", directory=str(path))
                if not all(check["ok"] for check in summary["diff_checks"].values()):
                    finding("whitespace_errors", "drift", directory=str(path))
                if summary.get("vs_tracking_main", {}).get("state") != "equal":
                    finding(
                        "checkout_not_at_tracking_main", "drift", directory=str(path)
                    )
                if summary["branch"] is None:
                    finding("detached_checkout", "drift", directory=str(path))
            except (OSError, ValueError) as exc:
                code = (
                    str(exc) if isinstance(exc, AuditError) else "worktree_unavailable"
                )
                worktree["audit"] = {"error": code}
                finding(code, "incomplete", directory=str(path))
        if not found_primary:
            finding("primary_checkout_unverified", "incomplete")
        # Detect concurrent ref moves, checkout switches, and status changes.
        # This is a sequential diagnostic, not an atomic filesystem snapshot.
        consistent = (
            git.require(root, "worktree", "list", "--porcelain", "-z") == worktree_data
            and git.require(
                root,
                "for-each-ref",
                "--format=%(refname)%00%(objectname)%00%(upstream)",
                "refs/heads/",
            )
            == branch_data
            and optional_oid(git, root, TRACKING) == tracking
        )
        for branch in report["local_branches"]:
            if (
                branch["upstream"]
                and optional_oid(git, root, branch["upstream"])
                != branch["upstream_sha"]
            ):
                consistent = False
        for path, snapshot, index, head in snapshots:
            if (
                status(git, path) != snapshot
                or index_visibility(git, path) != index
                or oid(git.require(path, "rev-parse", "HEAD")) != head
            ):
                consistent = False
        report["snapshot_consistent"] = consistent
        if not consistent:
            finding("snapshot_changed_during_audit", "incomplete")
    except (OSError, ValueError, RuntimeError) as exc:
        finding(
            str(exc) if isinstance(exc, AuditError) else "repository_unavailable",
            "incomplete",
        )
    incomplete = any(item["severity"] == "incomplete" for item in report["findings"])
    report["exit_code"] = 2 if incomplete else 1 if report["findings"] else 0
    report["source_ready"] = report["exit_code"] == 0
    return report


def timeout_seconds(value: str) -> float:
    try:
        number = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "use a timeout between 1 and 600 seconds"
        ) from exc
    if not 1 <= number <= 600:
        raise argparse.ArgumentTypeError("use a timeout between 1 and 600 seconds")
    return number


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repo", nargs="?", type=Path, default=ROOT)
    parser.add_argument(
        "--offline",
        action="store_true",
        help="inventory local state; live main remains unverified (exit 2)",
    )
    parser.add_argument(
        "--expected-main",
        help="optional prior main SHA; a changed baseline is drift, not corruption",
    )
    parser.add_argument(
        "--timeout",
        type=timeout_seconds,
        default=120,
        help="overall Git query budget in seconds (1-600; default 120)",
    )
    args = parser.parse_args()
    report = audit(
        args.repo,
        offline=args.offline,
        expected_main=args.expected_main,
        timeout=args.timeout,
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    return report["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
