from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tools import development_drift as drift  # noqa: E402


class DevelopmentDriftTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.repo = self.base / "source with spaces"
        self.repo.mkdir()
        self.environment = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith("GIT_")
        }
        self.environment.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
        self.git("init", "-b", "main")
        self.git("config", "user.email", "fixture@example.invalid")
        self.git("config", "user.name", "Fixture")
        self.git("config", "commit.gpgsign", "false")
        (self.repo / "tracked.txt").write_text("base\n", encoding="utf-8")
        self.git("add", "tracked.txt")
        self.git("commit", "-m", "base")
        self.head = self.git("rev-parse", "HEAD").decode().strip()
        self.live = self.head
        self.git("remote", "add", "origin", "https://example.invalid/linura.git")
        self.git("update-ref", drift.TRACKING, self.head)
        self.git("config", "branch.main.remote", "origin")
        self.git("config", "branch.main.merge", "refs/heads/main")

    def git(self, *args: str, cwd: Path | None = None) -> bytes:
        return subprocess.run(
            ["git", "-C", str(cwd or self.repo), *args],
            env=self.environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
            timeout=10,
        ).stdout

    def audit(self, repo: Path | None = None, **kwargs):
        run = drift.Git.run

        def remote(git, cwd, *args, **options):
            if args[0] == "ls-remote":
                return drift.Result(0, f"{self.live}\trefs/heads/main\n".encode())
            return run(git, cwd, *args, **options)

        with (
            patch.dict(
                os.environ,
                {
                    key: value
                    for key, value in os.environ.items()
                    if not key.startswith("GIT_")
                },
                clear=True,
            ),
            patch.object(drift.Git, "run", remote),
        ):
            return drift.audit(repo or self.repo, **kwargs)

    def commit(self, text="next\n") -> str:
        (self.repo / "tracked.txt").write_text(text, encoding="utf-8")
        self.git("commit", "-am", "change")
        return self.git("rev-parse", "HEAD").decode().strip()

    def codes(self, report) -> set[str]:
        return {finding["code"] for finding in report["findings"]}

    def test_aligned_checkout_is_read_only_and_not_qualification(self):
        before = {
            path: (path.read_bytes(), path.stat().st_mtime_ns)
            for path in self.repo.rglob("*")
            if path.is_file()
        }
        report = self.audit()
        self.assertEqual(report["exit_code"], 0, report)
        self.assertTrue(report["source_ready"])
        self.assertTrue(report["snapshot_consistent"])
        self.assertTrue(report["read_only"])
        self.assertFalse(report["qualification_evidence"])
        after = {
            path: (path.read_bytes(), path.stat().st_mtime_ns)
            for path in self.repo.rglob("*")
            if path.is_file()
        }
        self.assertEqual(before, after)
        self.assertEqual(
            report["primary_checkout"]["vs_tracking_main"]["state"], "equal"
        )

    def test_nested_path_and_non_utf8_or_newline_names_are_lossless(self):
        nested = self.repo / "nested"
        nested.mkdir()
        names = [
            "with\nnewline.txt",
            'quote" and space.txt',
            os.fsdecode(b"invalid-\xff.txt"),
        ]
        for name in names:
            (self.repo / name).write_bytes(b"private file contents")
        report = self.audit(nested)
        self.assertEqual(report["exit_code"], 1)
        entries = report["primary_checkout"]["changes"]
        self.assertEqual({entry["path"] for entry in entries}, set(names))
        self.assertNotIn("private file contents", json.dumps(report))

    def test_staged_rename_and_whitespace_do_not_disclose_diff_contents(self):
        self.git("mv", "tracked.txt", "renamed\nfile.txt")
        (self.repo / "renamed\nfile.txt").write_text(
            "private-diff-marker  \n", encoding="utf-8"
        )
        self.git("add", "renamed\nfile.txt")
        report = self.audit()
        self.assertIn("whitespace_errors", self.codes(report))
        self.assertFalse(report["primary_checkout"]["diff_checks"]["index"]["ok"])
        self.assertNotIn("private-diff-marker", json.dumps(report))
        # Explicit parser fixture also covers a rename whose new content no
        # longer meets Git's similarity threshold in the integration test.
        self.assertEqual(
            drift.parse_status(b"R  renamed\nfile.txt\0tracked.txt\0"),
            [
                {
                    "status": "R ",
                    "path": "renamed\nfile.txt",
                    "original_path": "tracked.txt",
                }
            ],
        )

    def test_ahead_behind_and_divergence_are_not_corruption(self):
        next_head = self.commit()
        ahead = self.audit()
        self.assertEqual(
            ahead["primary_checkout"]["vs_tracking_main"],
            {"ahead": 1, "behind": 0, "state": "ahead"},
        )
        self.git("update-ref", drift.TRACKING, next_head)
        self.live = next_head
        self.git("switch", "-c", "older", self.head)
        behind = self.audit()
        self.assertEqual(
            behind["primary_checkout"]["vs_tracking_main"]["state"], "behind"
        )
        self.commit("other change\n")
        diverged = self.audit()
        self.assertEqual(
            diverged["primary_checkout"]["vs_tracking_main"],
            {"ahead": 1, "behind": 1, "state": "diverged"},
        )
        self.assertEqual(diverged["exit_code"], 1)

    def test_live_baseline_drift_missing_tracking_and_expected_sha(self):
        self.live = "e" * 40  # A remote commit not fetched into this repository.
        report = self.audit(expected_main=self.head)
        self.assertEqual(report["exit_code"], 1)
        self.assertTrue(
            {"tracking_main_stale", "expected_main_changed"} <= self.codes(report)
        )
        self.git("update-ref", "-d", drift.TRACKING)
        report = self.audit()
        self.assertIn("tracking_main_missing", self.codes(report))
        self.assertFalse(report["source_ready"])

    def test_offline_or_remote_failures_are_incomplete_even_when_locally_clean(self):
        report = self.audit(offline=True)
        self.assertEqual(report["exit_code"], 2)
        self.assertFalse(report["source_ready"])
        self.assertEqual(report["baseline"]["remote_query"], "not_requested")
        original = drift.Git.run
        for result in (
            drift.Result(128, b"private-remote-marker"),
            drift.Result(None, error="command_timeout"),
            drift.Result(0, b"malformed\n"),
            drift.Result(
                0,
                f"{self.head}\trefs/heads/main\n{self.head}\trefs/heads/main\n".encode(),
            ),
        ):

            def run(git, cwd, *args, **options):
                return (
                    result
                    if args[0] == "ls-remote"
                    else original(git, cwd, *args, **options)
                )

            with self.subTest(result=result), patch.object(drift.Git, "run", run):
                report = drift.audit(self.repo)
            self.assertEqual(report["exit_code"], 2)
            self.assertNotIn("private-remote-marker", json.dumps(report))
            self.assertIn("primary_checkout", report)

    def test_retained_recovery_and_gone_upstream_do_not_authorize_deletion(self):
        self.git("branch", "backup/retained")
        self.git("branch", "old-topic")
        self.git("config", "branch.old-topic.remote", "origin")
        self.git("config", "branch.old-topic.merge", "refs/heads/deleted")
        report = self.audit()
        self.assertEqual(report["exit_code"], 0, report)
        branches = {entry["branch"]: entry for entry in report["local_branches"]}
        self.assertEqual(branches["backup/retained"]["retention"], "preserve-recovery")
        self.assertEqual(branches["old-topic"]["upstream_state"]["state"], "missing")
        self.assertEqual(
            self.git("rev-parse", "backup/retained").decode().strip(), self.head
        )

    def test_linked_locked_and_detached_worktrees_are_audited(self):
        other = self.base / "linked\ncheckout"
        self.git("worktree", "add", "--detach", str(other), self.head)
        self.git("worktree", "lock", "--reason", "private-lock-marker", str(other))
        (other / "dirty").write_bytes(b"not discarded")
        report = self.audit()
        self.assertEqual(report["exit_code"], 1)
        self.assertTrue(
            {"detached_checkout", "uncommitted_changes"} <= self.codes(report)
        )
        linked = next(
            item
            for item in report["registered_worktrees"]
            if item["worktree"] == str(other)
        )
        self.assertTrue(linked["locked"])
        self.assertIsNone(linked["audit"]["branch"])
        self.assertNotIn("private-lock-marker", json.dumps(report))
        self.assertEqual((other / "dirty").read_bytes(), b"not discarded")

    def test_missing_worktree_is_incomplete_and_is_never_pruned(self):
        other = self.base / "missing"
        self.git("worktree", "add", "-b", "missing", str(other), self.head)
        shutil.rmtree(other)
        before = self.git("worktree", "list", "--porcelain", "-z")
        report = self.audit()
        self.assertEqual(report["exit_code"], 2)
        self.assertEqual(before, self.git("worktree", "list", "--porcelain", "-z"))
        self.assertTrue(
            any(item.get("prunable") for item in report["registered_worktrees"])
        )

    def test_replaced_worktree_repository_is_rejected(self):
        other = self.base / "replaced"
        self.git("worktree", "add", "-b", "replaced", str(other), self.head)
        (other / ".git").unlink()
        self.git("init", "-b", "main", cwd=other)
        report = self.audit()
        self.assertEqual(report["exit_code"], 2)
        self.assertIn("worktree_repository_mismatch", self.codes(report))

    def test_environment_redirection_tracing_and_configuration_fail_closed(self):
        for key in (
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_INDEX_FILE",
            "GIT_CONFIG_COUNT",
            "GIT_CONFIG_KEY_0",
            "GIT_TRACE",
            "GIT_SSH_COMMAND",
        ):
            with (
                self.subTest(key=key),
                patch.dict(os.environ, {key: "private-environment-marker"}),
            ):
                report = drift.audit(self.repo)
            self.assertEqual(report["exit_code"], 2)
            self.assertIn("inherited_git_environment", self.codes(report))
            self.assertNotIn("private-environment-marker", json.dumps(report))

    def test_assume_unchanged_and_skip_worktree_cannot_hide_drift(self):
        for flag in ("assume-unchanged", "skip-worktree"):
            self.git("update-index", f"--{flag}", "tracked.txt")
            (self.repo / "tracked.txt").write_text(
                "concealed change\n", encoding="utf-8"
            )
            self.assertEqual(self.git("status", "--porcelain"), b"")
            report = self.audit()
            self.assertEqual(report["exit_code"], 2)
            self.assertIn("hidden_index_entries", self.codes(report))
            self.git("update-index", f"--no-{flag}", "tracked.txt")
            (self.repo / "tracked.txt").write_text("base\n", encoding="utf-8")

    def test_shallow_and_grafted_history_are_not_complete_ancestry(self):
        (self.repo / ".git/shallow").write_text(self.head + "\n", encoding="ascii")
        report = self.audit()
        self.assertEqual(report["exit_code"], 2)
        self.assertIn("incomplete_or_grafted_history", self.codes(report))
        (self.repo / ".git/shallow").unlink()
        (self.repo / ".git/info/grafts").write_text(self.head + "\n", encoding="ascii")
        report = self.audit()
        self.assertEqual(report["exit_code"], 2)
        self.assertIn("incomplete_or_grafted_history", self.codes(report))

    def test_bare_primary_inventory_and_sha256_repositories(self):
        bare = self.base / "bare.git"
        self.git("clone", "--bare", str(self.repo), str(bare))
        linked = self.base / "bare-linked"
        self.git("worktree", "add", str(linked), "main", cwd=bare)
        self.git(
            "remote",
            "set-url",
            "origin",
            "https://example.invalid/linura.git",
            cwd=bare,
        )
        self.git("update-ref", drift.TRACKING, self.head, cwd=bare)
        report = self.audit(linked)
        self.assertEqual(report["exit_code"], 0, report)
        self.assertTrue(
            any(item.get("bare") for item in report["registered_worktrees"])
        )
        sha256 = self.base / "sha256"
        sha256.mkdir()
        self.git("init", "-b", "main", "--object-format=sha256", cwd=sha256)
        self.git(
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "--allow-empty",
            "-m",
            "sha256",
            cwd=sha256,
        )
        self.live = self.git("rev-parse", "HEAD", cwd=sha256).decode().strip()
        self.git("update-ref", drift.TRACKING, self.live, cwd=sha256)
        self.git(
            "remote", "add", "origin", "https://example.invalid/linura.git", cwd=sha256
        )
        report = self.audit(sha256)
        self.assertEqual(report["exit_code"], 0, report)
        self.assertEqual(len(report["primary_checkout"]["head_sha"]), 64)

    def test_external_diff_and_fsmonitor_are_not_executed(self):
        marker = self.base / "executed"
        helper = self.base / "helper"
        helper.write_text(f"#!/bin/sh\ntouch '{marker}'\n", encoding="utf-8")
        helper.chmod(0o700)
        self.git("config", "diff.external", str(helper))
        self.git("config", "core.fsmonitor", str(helper))
        (self.repo / "tracked.txt").write_text("changed\n", encoding="utf-8")
        self.assertEqual(self.audit()["exit_code"], 1)
        self.assertFalse(marker.exists())

    def test_unsafe_remote_urls_and_custom_helpers_are_not_invoked(self):
        original = drift.Git.run
        for url in (
            "https://private-url-marker@example.invalid/source.git",
            "https://user:private-url-marker@example.invalid/source.git",
            "https://example.invalid/source.git?token=private-url-marker",
            "ext::private-url-marker",
            "file:///private-url-marker",
            "helper::private-url-marker",
        ):
            self.git("remote", "set-url", "origin", url)
            calls = []

            def run(git, cwd, *args, **options):
                calls.append(args[0])
                return original(git, cwd, *args, **options)

            with self.subTest(url=url), patch.object(drift.Git, "run", run):
                report = drift.audit(self.repo)
            self.assertEqual(report["exit_code"], 2)
            self.assertNotIn("ls-remote", calls)
            self.assertNotIn("private-url-marker", json.dumps(report))
            self.assertIn("primary_checkout", report)
        self.git("remote", "set-url", "origin", "https://example.invalid/source.git")
        self.git("config", "remote.origin.vcs", "private-helper-marker")
        report = self.audit()
        self.assertEqual(report["baseline"]["remote_query"], "unsupported_origin")
        self.assertEqual(report["exit_code"], 2)

    def test_supported_ssh_urls_and_rewritten_urls_are_checked(self):
        for url in (
            "ssh://git@example.invalid/source.git",
            "ssh://example.invalid/source.git",
            "git@example.invalid:org/source.git",
        ):
            self.git("remote", "set-url", "origin", url)
            with self.subTest(url=url):
                self.assertEqual(self.audit()["exit_code"], 0)
        self.git("remote", "set-url", "origin", "https://example.invalid/source.git")
        self.git(
            "config",
            "url.ext::private-rewrite-marker.insteadOf",
            "https://example.invalid/",
        )
        report = self.audit()
        self.assertEqual(report["baseline"]["remote_query"], "unsupported_origin")
        self.assertNotIn("private-rewrite-marker", json.dumps(report))

    def test_inventory_bounds_and_failed_local_queries_are_incomplete(self):
        self.git("branch", "second")
        for field in ("MAX_BRANCHES", "MAX_WORKTREES"):
            with self.subTest(field=field), patch.object(drift, field, 0):
                self.assertEqual(self.audit()["exit_code"], 2)
        original = drift.Git.run
        for command in ("status", "diff", "ls-files", "symbolic-ref"):

            def run(git, cwd, *args, **options):
                return (
                    drift.Result(128, b"private-command-marker")
                    if args[0] == command
                    else original(git, cwd, *args, **options)
                )

            with self.subTest(command=command), patch.object(drift.Git, "run", run):
                report = drift.audit(self.repo, offline=True)
            self.assertEqual(report["exit_code"], 2)
            self.assertNotIn("private-command-marker", json.dumps(report))

    def test_concurrent_ref_and_status_changes_are_incomplete(self):
        original = drift.Git.run
        for kind in ("branch", "status"):
            calls = 0

            def run(git, cwd, *args, **options):
                nonlocal calls
                target = "for-each-ref" if kind == "branch" else "status"
                if args[0] == target:
                    calls += 1
                    if calls == 2:
                        if kind == "branch":
                            self.git("branch", "concurrent")
                        else:
                            (self.repo / "concurrent").write_bytes(b"changed")
                return original(git, cwd, *args, **options)

            with self.subTest(kind=kind), patch.object(drift.Git, "run", run):
                report = drift.audit(self.repo, offline=True)
            self.assertIn("snapshot_changed_during_audit", self.codes(report))
            self.assertFalse(report["snapshot_consistent"])
            self.assertEqual(report["exit_code"], 2)

    def test_invalid_repository_unborn_head_and_bad_expected_sha(self):
        empty = self.base / "empty"
        empty.mkdir()
        self.assertEqual(self.audit(empty)["exit_code"], 2)
        self.git("init", "-b", "main", cwd=empty)
        self.assertEqual(self.audit(empty)["exit_code"], 2)
        report = self.audit(expected_main="private-invalid-marker")
        self.assertEqual(report["exit_code"], 2)
        self.assertNotIn("private-invalid-marker", json.dumps(report))

    def test_cli_reports_exit_status_and_does_not_write_a_report_file(self):
        with (
            patch.object(
                sys, "argv", ["development_drift.py", str(self.repo), "--offline"]
            ),
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            code = drift.main()
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output.getvalue())["exit_code"], 2)


class DriftCommandTests(unittest.TestCase):
    def stub(self, body: str) -> drift.Git:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        binary = Path(temporary.name) / "git"
        binary.write_text(f"#!{sys.executable}\n{body}\n", encoding="utf-8")
        binary.chmod(0o700)
        runner = drift.Git(timeout=1)
        runner.environment["PATH"] = temporary.name
        return runner

    def test_output_limit_discards_partial_output_and_stderr(self):
        runner = self.stub(
            "import os\nos.write(2, b'private-stderr-marker')\nos.write(1, b'x' * 65536)"
        )
        with patch.object(drift, "MAX_OUTPUT_BYTES", 64):
            result = runner.run(ROOT, "status")
        self.assertEqual(result.error, "output_limit")
        self.assertEqual(result.output, b"")

    def test_total_output_budget_is_shared_by_commands(self):
        runner = self.stub("import os\nos.write(1, b'x' * 40)")
        runner.remaining_output = 64
        self.assertEqual(runner.run(ROOT, "first").returncode, 0)
        result = runner.run(ROOT, "second")
        self.assertEqual(result.error, "audit_output_limit")
        self.assertEqual(result.output, b"")

    def test_timeout_and_closed_pipe_hang_are_bounded(self):
        for body in (
            "import time\ntime.sleep(20)",
            "import os, time\nos.close(1)\ntime.sleep(20)",
        ):
            runner = self.stub(body)
            runner.deadline = time.monotonic() + 0.05
            started = time.monotonic()
            result = runner.run(ROOT, "status")
            self.assertEqual(result.error, "command_timeout")
            self.assertLess(time.monotonic() - started, 3)

    def test_missing_command_and_exhausted_budget_are_explicit(self):
        runner = drift.Git()
        runner.environment["PATH"] = "/nonexistent-linura-test-directory"
        self.assertEqual(runner.run(ROOT, "status").error, "command_unavailable")
        runner.deadline = 0
        self.assertEqual(runner.run(ROOT, "status").error, "audit_timeout")

    def test_parsers_reject_truncation_unknown_fields_and_duplicate_paths(self):
        head = b"a" * 40
        record = b"worktree /example\0HEAD " + head + b"\0branch refs/heads/main\0\0"
        self.assertEqual(len(drift.parse_worktrees(record)), 1)
        for value in (
            b"",
            record[:-1],
            record + record,
            record.replace(b"HEAD ", b"unknown "),
            record.replace(b"branch refs/heads/main", b"HEAD " + head),
        ):
            with self.subTest(value=value), self.assertRaises(drift.AuditError):
                drift.parse_worktrees(value)
        for value in (b"?? incomplete", b"R  destination\0", b"XY path\0", b"?? \0"):
            with self.subTest(value=value), self.assertRaises(drift.AuditError):
                drift.parse_status(value)
        self.assertEqual(drift.oid(b"a" * 64 + b"\n"), "a" * 64)
        for value in ("0", "601", "nan", "inf", "bad"):
            with self.subTest(value=value), self.assertRaises(Exception):
                drift.timeout_seconds(value)


if __name__ == "__main__":
    unittest.main()
