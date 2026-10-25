"""Native runner component/adversarial tests, NEVER actual PAM qualification."""

from __future__ import annotations

import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "qualification/v010/session-security"


def load(name: str):
    spec = importlib.util.spec_from_file_location(
        name.replace("-", "_"), FIXTURE / (name + ".py")
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


runner = load("qualify-native-auth")
fixture = load("native-auth-fixture")
LOCK = "session:lock:12345678-1234-1234-1234-123456789abc:1000:c1:9:12345678-1234-1234-1234-123456789abc:1"
SOURCE = "a" * 40


def wire(values):
    return "".join(f"{key}={value}\n" for key, value in values.items()).encode("ascii")


def lock_receipt(operation, secure, recovered):
    return {
        "request_id": "request:v010:session-lock:" + operation,
        "resource": LOCK,
        "desired_secure": str(secure).lower(),
        "completion": "verified-committed-reconciled",
        "recovered": str(recovered).lower(),
        "stages": runner.STAGES,
        "transaction_id": "transaction:v1:" + "a" * 64,
        "effect_digest": "b" * 64,
    }


def setting(operation, enabled, latest):
    return {
        "request_id": "request:v010:protective-lock-setting:" + operation,
        "confirmation_lock": LOCK,
        "recorded_consent": "enabled" if enabled else "revoked",
        "latest_for_recorded_epoch": str(latest).lower(),
        "current_native_protection": "not-queried",
        "intent_id": "intent:s17:protective-lock:" + "a" * 64,
        "revision_id": "policy:protective-lock:v1:" + "b" * 64,
        "confirmed_at_unix_ms": "42",
    }


def assistive(phase):
    return {
        "schema_version": 1,
        "claim": "native-assistive-metadata-cases-only",
        "phase": phase,
        "native_owner_pid": 123,
        "native_owner_invocation": LOCK.split(":")[6].replace("-", ""),
        "native_owner_start_ticks": "42",
        "checks": {
            "registry-discovers-actual-native-owner": True,
            "typed-protected-presentation-tree": True,
            "no-text-value-editable-action-or-geometry-interface": True,
            "remote-input-and-relabel-methods-rejected": True,
        },
        "s17_complete": False,
        "release_support_promotion": False,
    }


class FakeGuest:
    def __init__(self, fail_at=None):
        self.commands = []
        self.fail_at = fail_at
        self.configured = False
        self.response: bytes | None = None

    def run(
        self,
        command,
        interaction=None,
        payload=None,
        expect_failure=False,
        allow_early_denial=False,
    ):
        self.commands.append(command)
        if self.fail_at == len(self.commands):
            raise RuntimeError("component transport failure")
        if command.endswith("set-response"):
            self.configured = True
            self.response = payload
        if interaction is not None:
            interaction()
        if command.endswith("clear-response"):
            self.configured = False
        args = command.split()
        if command.startswith(runner.ASSISTIVE_COMMAND):
            return json.dumps(assistive(args[-1])).encode("ascii")
        if "configure-protective-lock" in args:
            index = args.index("configure-protective-lock")
            return wire(setting(args[index + 2], args[index + 1] == "enable", True))
        if "protective-lock-setting-status" in args:
            return wire(
                setting(
                    args[-1].removeprefix("request:v010:protective-lock-setting:"),
                    True,
                    False,
                )
            )
        if "session-lock-status" in args:
            operation = args[-1].removeprefix("request:v010:session-lock:")
            return wire(
                {
                    "request_id": "request:v010:session-lock:" + operation,
                    "transaction_id": "transaction:v1:" + "a" * 64,
                    "resource": LOCK,
                    "desired_secure": "false",
                    "historical_transaction_state": "committed",
                    "current_native_coverage": "not-queried",
                }
            )
        if expect_failure:
            return b""
        for action, secure, recovered in (
            ("lock-session", True, False),
            ("recover-session-lock", True, True),
            ("unlock-session", False, False),
        ):
            if action in args:
                index = args.index(action)
                operation = args[index + 1].removeprefix("request:v010:session-lock:")
                return wire(lock_receipt(operation, secure, recovered))
        return b""


class NativeAuthenticationRunnerTests(unittest.TestCase):
    def setUp(self):
        # Fake guests have no native cooldown. Only component tests suppress the
        # wait; the executable runner exposes no cooldown-reset/skip option.
        sleeper = patch.object(runner.time, "sleep")
        self.sleep = sleeper.start()
        self.addCleanup(sleeper.stop)
        self.diagnostics = io.StringIO()
        diagnostic_sink = patch.object(runner.sys, "stderr", self.diagnostics)
        diagnostic_sink.start()
        self.addCleanup(diagnostic_sink.stop)

    def test_failure_state_is_bounded_categorical_and_cannot_accept_raw_service_text(
        self,
    ):
        state = {
            "ActiveState": "failed",
            "SubState": "failed",
            "Result": "exit-code",
            "ExecMainCode": "1",
            "ExecMainStatus": "72",
            "MainPID": "0",
            "InvocationID": "12345678123412341234123456789abc",
        }
        report = runner.native_owner_failure_state(wire(state), LOCK)
        self.assertEqual(
            report,
            {
                "claim": "failure-diagnostics-only",
                "active": False,
                "running": False,
                "pid_present": False,
                "main_code": 1,
                "main_status": 72,
                "result": "exit-code",
                "same_invocation": True,
            },
        )
        for key, bad in (
            ("ActiveState", "private-wire-marker"),
            ("SubState", "private-wire-marker"),
            ("Result", "private-wire-marker"),
            ("ExecMainCode", "7"),
            ("ExecMainStatus", "256"),
            ("MainPID", "2147483648"),
            ("ExecMainStatus", "072"),
            ("ExecMainStatus", "-1"),
            ("InvocationID", "private-wire-marker"),
        ):
            with self.subTest(key=key), self.assertRaises(RuntimeError) as caught:
                runner.native_owner_failure_state(wire(state | {key: bad}), LOCK)
            self.assertNotIn("private-wire-marker", str(caught.exception))
        for bad in (
            wire(state) + b"Result=success\n",
            b"x" * (runner.MAXIMUM_OUTPUT + 1),
        ):
            with self.assertRaises(RuntimeError):
                runner.native_owner_failure_state(bad, LOCK)
        for invocation in ("", "0" * 32, "a" * 32):
            self.assertFalse(
                runner.native_owner_failure_state(
                    wire(state | {"InvocationID": invocation}), LOCK
                )["same_invocation"]
            )

    def test_exit_diagnostics_discard_identifiers_and_reject_unbounded_or_raw_values(
        self,
    ):
        rows = [
            {"MESSAGE": "private-wire-marker"},
            {"EXIT_CODE": "exited", "EXIT_STATUS": "72", "_PID": "12345"},
            {"EXIT_CODE": "exited", "EXIT_STATUS": "71"},
            {"EXIT_CODE": "killed", "EXIT_STATUS": "9"},
        ]
        report = runner.native_owner_failure_journal(
            b"\n".join(json.dumps(row).encode() for row in rows)
        )
        self.assertEqual(
            report,
            {
                "exits": [
                    {"code": "exited", "status": 72},
                    {"code": "exited", "status": 71},
                    {"code": "killed", "status": 9},
                ],
                "timeouts": [],
                "lock_progress": [],
            },
        )
        self.assertEqual(
            runner.native_owner_failure_journal(b""),
            {"exits": [], "timeouts": [], "lock_progress": []},
        )
        for bad in (
            b"x" * (runner.MAXIMUM_OUTPUT + 1),
            b"{}\n" * 65,
            b"[]",
            b"\xff",
            b'{"EXIT_CODE":"exited","EXIT_CODE":"killed","EXIT_STATUS":"72"}',
            b'{"EXIT_CODE":"exited"}',
            b'{"EXIT_STATUS":"72"}',
            b'{"EXIT_CODE":[],"EXIT_STATUS":"72"}',
            b'{"EXIT_CODE":"exited","EXIT_STATUS":true}',
            b'{"EXIT_CODE":"exited","EXIT_STATUS":"072"}',
            b'{"EXIT_CODE":"exited","EXIT_STATUS":"256"}',
            b'{"EXIT_CODE":"exited","EXIT_STATUS":"private-wire-marker"}',
        ):
            with self.subTest(wire=bad[:64]), self.assertRaises(RuntimeError) as caught:
                runner.native_owner_failure_journal(bad)
            self.assertNotIn("private-wire-marker", str(caught.exception))

    def test_timeout_journal_retains_only_complete_closed_labels(self):
        stages = sorted(runner.OWNER_TIMEOUT_STAGES)
        rows = [{"MESSAGE": "native-owner-timeout stage=" + stage} for stage in stages]
        rows += [
            {"MESSAGE": "native-owner-timeout stage=wayland-pump\n"},
            {"MESSAGE": "native-owner-timeout stage=private-wire-marker"},
            {"MESSAGE": "prefix native-owner-timeout stage=wayland-pump"},
            {"MESSAGE": "native-owner-timeout stage=wayland-pump suffix"},
            {"MESSAGE": ["private-wire-marker"]},
        ]
        report = runner.native_owner_failure_journal(
            b"\n".join(json.dumps(row).encode() for row in rows)
        )
        self.assertEqual(report, {"exits": [], "timeouts": stages, "lock_progress": []})
        self.assertNotIn("private-wire-marker", json.dumps(report))

    def test_lock_progress_journal_retains_only_closed_ordered_protocol_milestones(
        self,
    ):
        stages = [
            "requested",
            "surface-configured",
            "frame-flushed",
            "all-surfaces-flushed",
            "acknowledged",
            "released",
            "requested",
        ]
        rows = [
            {"MESSAGE": "native-owner-lock-progress stage=" + stage} for stage in stages
        ]
        rows += [
            {"MESSAGE": "native-owner-lock-progress stage=private-wire-marker"},
            {"MESSAGE": "prefix native-owner-lock-progress stage=requested"},
            {"MESSAGE": "native-owner-lock-progress stage=requested suffix"},
            {"MESSAGE": ["private-wire-marker"]},
            {"MESSAGE": "native-owner-lock-progress stage=surface-configured\n"},
        ]
        report = runner.native_owner_failure_journal(
            b"\n".join(json.dumps(row).encode() for row in rows)
        )
        self.assertEqual(
            report,
            {
                "exits": [],
                "timeouts": [],
                "lock_progress": stages + ["surface-configured"],
            },
        )
        self.assertNotIn("private-wire-marker", json.dumps(report))

    def test_compositor_diagnostics_retain_only_bounded_aggregate_output_context(self):
        monitor = {
            "id": 7,
            "width": 1280,
            "height": 800,
            "disabled": False,
            "dpmsStatus": True,
            "name": "private-wire-marker",
        }
        value = runner.compositor_failure_monitors(
            json.dumps(
                [monitor, monitor | {"id": 8, "disabled": True, "width": 0}]
            ).encode()
        )
        self.assertEqual(
            value,
            {"count": 2, "enabled_count": 1, "powered_count": 1, "zero_mode_count": 1},
        )
        self.assertNotIn("private-wire-marker", json.dumps(value))
        for bad in (
            b"x" * (runner.MAXIMUM_OUTPUT + 1),
            b"{}",
            b"\xff",
            b'[{"id":0,"id":1}]',
            json.dumps([monitor] * 17).encode(),
            json.dumps([monitor, monitor]).encode(),
            *(
                json.dumps([monitor | {key: wrong}]).encode()
                for key, wrong in (
                    ("id", True),
                    ("id", -1),
                    ("id", 2**31),
                    ("width", True),
                    ("width", -1),
                    ("height", 32769),
                    ("disabled", 0),
                    ("dpmsStatus", "true"),
                )
            ),
        ):
            with self.subTest(wire=bad[:64]), self.assertRaises(RuntimeError) as caught:
                runner.compositor_failure_monitors(bad)
            self.assertNotIn("private-wire-marker", str(caught.exception))

    def test_compositor_logs_discard_raw_text_and_keep_only_closed_failure_labels(self):
        rows = [
            "[test] " + marker + " private-wire-marker"
            for _, marker in runner.COMPOSITOR_FAILURE_MARKERS
        ]
        rows.append("private-wire-marker unknown log data")
        value = runner.compositor_failure_log("\n".join(rows).encode())
        self.assertEqual(
            value, [label for label, _ in runner.COMPOSITOR_FAILURE_MARKERS]
        )
        self.assertNotIn("private-wire-marker", json.dumps(value))
        for bad in (b"x" * (runner.MAXIMUM_OUTPUT + 1), b"unknown\n" * 257, b"\xff"):
            with self.assertRaises(RuntimeError) as caught:
                runner.compositor_failure_log(bad)
            self.assertNotIn("private-wire-marker", str(caught.exception))

    def test_scheduler_diagnostics_keep_only_closed_flags_in_original_event_order(self):
        for needs in (False, True):
            for pending in (False, True):
                for scheduled in (False, True):
                    row = (
                        "private-wire-marker CDRMOutput::scheduleFrame: reason 7, "
                        f"needsFrame {str(needs).lower()}, "
                        f"isPageFlipPending {str(pending).lower()}, "
                        f"frameEventScheduled {str(scheduled).lower()}"
                    )
                    value = runner.compositor_failure_log(
                        (
                            "New sessionLock with id private-wire-marker\n"
                            + row
                            + "\ndrm: Committed a buffer, updating state\n"
                        ).encode()
                    )
                    self.assertEqual(
                        value,
                        [
                            "lock-request",
                            f"frame-schedule:needs={int(needs)}:in-flight={int(pending)}:scheduled={int(scheduled)}",
                            "buffer-committed",
                        ],
                    )
                    self.assertNotIn("private-wire-marker", json.dumps(value))
        prefix = "CDRMOutput::scheduleFrame: reason "
        for bad in (
            "256, needsFrame true, isPageFlipPending false, frameEventScheduled false",
            "1000, needsFrame true, isPageFlipPending false, frameEventScheduled false",
            "7, needsFrame 1, isPageFlipPending false, frameEventScheduled false",
            "7, needsFrame true, isPageFlipPending unknown, frameEventScheduled false",
            "7, needsFrame true, isPageFlipPending false, frameEventScheduled false private-wire-marker",
        ):
            self.assertEqual(runner.compositor_failure_log((prefix + bad).encode()), [])

    def test_failure_diagnostics_never_convert_failure_to_evidence_or_skip_cleanup(
        self,
    ):
        state = {
            "ActiveState": "failed",
            "SubState": "failed",
            "Result": "exit-code",
            "ExecMainCode": "1",
            "ExecMainStatus": "72",
            "MainPID": "0",
            "InvocationID": "12345678123412341234123456789abc",
        }

        class DiagnosticGuest(FakeGuest):
            def run(self, command, *args, **kwargs):
                if "systemctl show linura-security-owner@" in command:
                    self.commands.append(command)
                    return wire(state)
                if "/usr/bin/journalctl " in command:
                    self.commands.append(command)
                    return b'{"EXIT_CODE":"exited","EXIT_STATUS":"72"}\n'
                # SSH does not inherit the compositor's instance environment.
                # These are diagnostic context only, even for a failed owner.
                if "/usr/bin/hyprctl -i 0 " in command:
                    self.commands.append(command)
                    if command.endswith("-j monitors all"):
                        return json.dumps(
                            [
                                {
                                    "id": 0,
                                    "width": 1280,
                                    "height": 800,
                                    "disabled": False,
                                    "dpmsStatus": True,
                                    "name": "private-wire-marker",
                                }
                            ]
                        ).encode()
                    if command.endswith(
                        "rollinglog | /usr/bin/tail -c 12000 | /usr/bin/tail -n +2 | /usr/bin/tail -n 128"
                    ):
                        return b"drm: Session inactive private-wire-marker\n"
                    raise AssertionError("unexpected compositor diagnostic command")
                return super().run(command, *args, **kwargs)

        guest = DiagnosticGuest(fail_at=2)
        with self.assertRaisesRegex(RuntimeError, "component transport failure"):
            runner.qualify(guest, Mock(), LOCK, SOURCE)
        self.assertEqual(guest.commands[-1], runner.FIXTURE_COMMAND + "clear-response")
        self.assertTrue(
            any(
                command.startswith("set -o pipefail; ") and "rollinglog |" in command
                for command in guest.commands
            )
        )
        diagnostic = json.loads(self.diagnostics.getvalue().partition("=")[2])
        self.assertEqual(diagnostic["claim"], "failure-diagnostics-only")
        self.assertEqual(diagnostic["main_status"], 72)
        self.assertTrue(diagnostic["same_invocation"])
        self.assertEqual(diagnostic["exits"], [{"code": "exited", "status": 72}])
        self.assertEqual(
            diagnostic["compositor_monitors"],
            {"count": 1, "enabled_count": 1, "powered_count": 1, "zero_mode_count": 0},
        )
        self.assertEqual(diagnostic["compositor_events"], ["session-inactive"])
        self.assertNotIn("private-wire-marker", self.diagnostics.getvalue())
        self.assertFalse(guest.configured)
        assert guest.response is not None
        self.assertTrue(
            guest.response.decode("ascii").strip() not in self.diagnostics.getvalue()
        )

    def test_negative_cases_preserve_distribution_consecutive_failure_lockout(self):
        class ConsecutiveFailureGuest(FakeGuest):
            def __init__(self):
                super().__init__()
                self.failures = 0
                self.maximum_failures = 0
                self.authenticated_after_failure = 0

            def run(self, command, *args, **kwargs):
                authenticates = any(
                    action in command
                    for action in ("configure-protective-lock ", "unlock-session ")
                )
                denied = kwargs.get("expect_failure", False)
                if authenticates and not denied and self.failures >= 3:
                    raise RuntimeError("distribution consecutive failure limit reached")
                result = super().run(command, *args, **kwargs)
                if authenticates:
                    if denied:
                        self.failures += 1
                        self.maximum_failures = max(
                            self.maximum_failures, self.failures
                        )
                    else:
                        if self.failures:
                            self.authenticated_after_failure += 1
                        self.failures = (
                            0  # Only actual successful PAM, not password setup.
                        )
                return result

        guest = ConsecutiveFailureGuest()
        report = runner.qualify(guest, Mock(), LOCK, SOURCE)
        self.assertTrue(all(report["checks"].values()))
        self.assertEqual(guest.maximum_failures, 2)
        self.assertEqual(guest.authenticated_after_failure, 2)
        self.assertFalse(any("faillock" in command for command in guest.commands))

    def test_native_cooldown_wait_tracks_the_production_failure_boundary(self):
        import re

        source = (
            ROOT / "apps/linura-shell/security-owner/native_approval.h"
        ).read_text()
        match = re.search(r"FailureCooldownMs = ([0-9']+);", source)
        self.assertIsNotNone(match)
        assert match is not None
        native_ms = int(match[1].replace("'", ""))
        self.assertGreater(runner.NATIVE_DENIAL_SETTLE_SECONDS * 1000, native_ms)

    def test_early_account_denial_cannot_admit_transport_failure_or_success(self):
        with tempfile.TemporaryDirectory() as directory:
            identity = Path(directory) / "component-identity"
            identity.touch(mode=0o600)
            guest = runner.Guest(identity)
            for status, early in ((1, True), (1, False), (255, True), (0, True)):
                process = subprocess.Popen(
                    [sys.executable, "-c", f"raise SystemExit({status})"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                process.wait(timeout=5)
                interaction = Mock()
                with (
                    self.subTest(status=status, early=early),
                    patch.object(runner.subprocess, "Popen", return_value=process),
                ):
                    if status == 1 and early:
                        self.assertEqual(
                            guest.run(
                                "fixed-account-case",
                                interaction,
                                expect_failure=True,
                                allow_early_denial=True,
                            ),
                            b"",
                        )
                    else:
                        with self.assertRaises(RuntimeError):
                            guest.run(
                                "fixed-account-case",
                                interaction,
                                expect_failure=True,
                                allow_early_denial=early,
                            )
                interaction.assert_not_called()
            with patch.object(runner.subprocess, "Popen") as execute:
                with self.assertRaises(RuntimeError):
                    guest.run("not-a-negative-case", allow_early_denial=True)
                execute.assert_not_called()

    def test_early_failure_reports_only_fixed_categories_and_never_raw_diagnostics(
        self,
    ):
        with tempfile.TemporaryDirectory() as directory:
            identity = Path(directory) / "component-identity"
            identity.touch(mode=0o600)
            guest = runner.Guest(identity)
            for status in (0, 1, 255):
                process = subprocess.Popen(
                    [
                        sys.executable,
                        "-c",
                        "import sys; sys.stderr.write('native owner refused the scoped interaction: private-wire-marker'); "
                        f"raise SystemExit({status})",
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                process.wait(timeout=5)
                interaction = Mock()
                with (
                    self.subTest(status=status),
                    patch.object(runner.subprocess, "Popen", return_value=process),
                ):
                    with self.assertRaises(RuntimeError) as caught:
                        guest.run("fixed-lock-case", interaction)
                interaction.assert_not_called()
                self.assertIn(f"exit={status}", str(caught.exception))
                self.assertIn("owner-refused-scope", str(caught.exception))
                self.assertNotIn("private-wire-marker", str(caught.exception))
                self.assertNotIn(
                    "native owner refused the scoped interaction", str(caught.exception)
                )
            self.assertEqual(
                runner.failure_categories(b"private-wire-marker"), "unclassified"
            )
            for category, marker in (
                (
                    "native-auth-denied",
                    b"native owner authentication was denied or still challenged",
                ),
                ("native-auth-daemon", b"native authentication daemon"),
                ("native-auth-service", b"native authentication service"),
                ("native-auth-subject", b"native authentication subject"),
                ("native-auth-account", b"native authentication account"),
                ("native-auth-process", b"native process"),
                ("native-call", b"native session call"),
            ):
                self.assertEqual(
                    runner.failure_categories(marker + b" private-wire-marker"),
                    category + ",native",
                )
            self.assertEqual(
                runner.failure_categories(
                    b"native assistive probe failed: registry private-wire-marker"
                ),
                "assistive-registry,native",
            )
            for category in (
                "call-deadline",
                "call-peer-unavailable",
                "call-disconnected",
            ):
                self.assertEqual(
                    runner.failure_categories(
                        ("native assistive probe failed: " + category).encode("ascii")
                        + b" private-wire-marker"
                    ),
                    "assistive-"
                    + category
                    + (",timeout" if category == "call-deadline" else "")
                    + ",native",
                )

    def test_unlock_failure_stages_remain_distinct_without_exporting_error_text(self):
        for category, detail in (
            (
                "session-evidence-identity",
                "session evidence does not bind the exact current epoch",
            ),
            (
                "session-state-unsupported",
                "session state is unsupported, ambiguous or unsafe",
            ),
            (
                "session-coverage-unverified",
                "compositor has not verified exact-session secure coverage",
            ),
            (
                "owner-missing-proof",
                "native owner did not prove fresh purpose-bound authentication",
            ),
            (
                "owner-release-unverified",
                "native owner did not independently confirm release",
            ),
            (
                "release-commit-pending",
                "release was committed but its native generation acknowledgement is pending",
            ),
            (
                "release-recovery-pending",
                "verified release is durable but native acknowledgement is pending",
            ),
            ("dispatch-refused", "native lock precondition refused dispatch"),
            ("dispatch-ambiguous", "native lock transport outcome is indeterminate"),
            (
                "native-owner-changed",
                "native security owner changed during the operation",
            ),
            (
                "owner-discovery-churn",
                "native owner discovery remained unstable within its bounded probe",
            ),
            (
                "owner-discovery-changed",
                "native security owner changed during discovery",
            ),
            (
                "owner-discovery-timeout",
                "native owner discovery exceeded its original deadline",
            ),
            (
                "owner-discovery-bound",
                "native bus enumeration exceeds its aggregate bound",
            ),
            (
                "owner-discovery-codec",
                "native endpoint introspection is malformed",
            ),
            (
                "native-generation-mismatch",
                "native lock generation differs from the requested generation",
            ),
            ("native-observation-codec", "native lock observation codec mismatch"),
            ("native-lock-codec", "native lock call result is malformed"),
            ("native-approval-codec", "native approval result is malformed"),
            (
                "native-reply-bound",
                "native session reply exceeded its time or size bound",
            ),
        ):
            with self.subTest(category=category):
                result = runner.failure_categories(
                    (detail + ": private-wire-marker").encode("ascii")
                )
                self.assertIn(category, result.split(","))
                self.assertNotIn("private-wire-marker", result)
                self.assertNotIn(detail, result)
        for category, detail in (
            ("executor", "privileged executor failed"),
            ("execution-rejected", "effect was rejected before dispatch"),
            ("verification", "independent verification failed"),
            (
                "verification-unsatisfied",
                "independent verification did not prove intended state",
            ),
            ("indeterminate", "managed mutation remains indeterminate"),
            ("terminal", "durable transaction is terminal and cannot be replayed"),
            ("reconciliation", "post-commit reconciliation failed"),
            ("contract", "managed lifecycle contract failed"),
        ):
            with self.subTest(category=category):
                self.assertEqual(
                    runner.failure_categories(
                        (detail + ": private-wire-marker").encode("ascii")
                    ),
                    category,
                )

    def test_stdout_and_stderr_share_one_output_budget(self):
        with tempfile.TemporaryDirectory() as directory:
            identity = Path(directory) / "component-identity"
            identity.touch(mode=0o600)
            guest = runner.Guest(identity)
            guest.ssh = [
                sys.executable,
                "-c",
                "import sys; sys.stdout.write('a' * 9000); sys.stderr.write('b' * 9000)",
            ]
            with self.assertRaisesRegex(RuntimeError, "output exceeds its bound"):
                guest.run("component-only")

    def test_response_cannot_reach_argv_environment_or_retained_report_and_cleanup_runs(
        self,
    ):
        guest = FakeGuest()
        native_input = Mock()
        report = runner.qualify(guest, native_input, LOCK, SOURCE)
        self.assertFalse(guest.configured)
        self.assertEqual(guest.commands[-1], runner.FIXTURE_COMMAND + "clear-response")
        returned_to_lock = [
            guest.commands[index - 1]
            for index, command in enumerate(guest.commands)
            if index > 0 and command == runner.ASSISTIVE_COMMAND + "locked"
        ][1:]  # The initial locked presentation is independently checked too.
        self.assertEqual(len(returned_to_lock), 5)
        for command, expected in zip(
            returned_to_lock,
            (
                "unlock-session s17-native-account-locked-",
                "configure-protective-lock enable ",
                "configure-protective-lock revoke ",
                "unlock-session s17-native-cancel-",
                "unlock-session s17-native-incorrect-",
            ),
            strict=True,
        ):
            self.assertIn(expected, command)
        self.assertIsNotNone(guest.response)
        assert guest.response is not None
        response = guest.response.decode("ascii").strip()
        self.assertTrue(
            all(response not in command for command in guest.commands),
            "response must never become command arguments",
        )
        self.assertNotIn(response, str(report))
        self.assertNotIn(response, str(runner.ENVIRONMENT))
        self.assertEqual(native_input.response.call_count, 5)
        supplied = [call.args[0] for call in native_input.response.call_args_list]
        self.assertTrue(
            supplied[:3] == [response] * 3, "account and consent input order differs"
        )
        self.assertTrue(
            supplied[3] != response, "negative case reused the correct response"
        )
        self.assertTrue(supplied[4] == response, "final unlock response differs")
        self.assertEqual(
            [call.args[0] for call in self.sleep.call_args_list],
            [runner.NATIVE_DENIAL_SETTLE_SECONDS] * 3,
        )
        self.assertGreater(runner.NATIVE_DENIAL_SETTLE_SECONDS, 5)
        self.assertIs(report["s17_complete"], False)
        self.assertIs(report["release_support_promotion"], False)
        self.assertTrue(all(report["checks"].values()))
        self.assertEqual(report["lock_resource"], LOCK)
        self.assertEqual(
            set(report["receipts"]),
            {
                "lock",
                "lock-recovery",
                "consent-enable",
                "consent-revoke",
                "consent-enable-history",
                "unlock",
                "unlock-history",
            },
        )
        self.assertEqual(set(report["assistive_probes"]), {"locked", "unlock-prompt"})
        runner.require_same_retained_effect(
            report["receipts"]["lock"], report["receipts"]["lock-recovery"]
        )

    def test_valid_looking_recovery_or_history_substitution_is_not_accepted(self):
        for command_part, key, replacement in (
            ("recover-session-lock", "transaction_id", "transaction:v1:" + "c" * 64),
            ("recover-session-lock", "effect_digest", "c" * 64),
            (
                "protective-lock-setting-status",
                "revision_id",
                "policy:protective-lock:v1:" + "c" * 64,
            ),
            ("protective-lock-setting-status", "confirmed_at_unix_ms", "43"),
            ("session-lock-status", "transaction_id", "transaction:v1:" + "c" * 64),
        ):
            guest = FakeGuest()
            original = guest.run

            def substitute(command, *args, **kwargs):
                value = original(command, *args, **kwargs)
                if command_part in command:
                    fields = runner.fields(value)
                    fields[key] = replacement
                    return wire(fields)
                return value

            with (
                self.subTest(command=command_part, key=key),
                patch.object(guest, "run", side_effect=substitute),
                self.assertRaises(RuntimeError),
            ):
                runner.qualify(guest, Mock(), LOCK, SOURCE)
            self.assertFalse(guest.configured)
            self.assertEqual(
                guest.commands[-1], runner.FIXTURE_COMMAND + "clear-response"
            )

    def test_retired_consent_or_elapsed_denial_cannot_leave_a_sticky_prompt(self):
        for trigger in (
            "s17-native-account-locked-",
            "configure-protective-lock enable ",
            "configure-protective-lock revoke ",
            "s17-native-cancel-",
            "s17-native-incorrect-",
        ):

            class StickyGuest(FakeGuest):
                stuck = False

                def run(self, command, *args, **kwargs):
                    value = super().run(command, *args, **kwargs)
                    if trigger in command:
                        self.stuck = True
                    if self.stuck and command == runner.ASSISTIVE_COMMAND + "locked":
                        return json.dumps(assistive("unlock-prompt")).encode("ascii")
                    return value

            guest = StickyGuest()
            with self.subTest(trigger=trigger), self.assertRaises(RuntimeError):
                runner.qualify(guest, Mock(), LOCK, SOURCE)
            self.assertFalse(guest.configured)
            self.assertEqual(
                guest.commands[-1], runner.FIXTURE_COMMAND + "clear-response"
            )

    def test_every_ordinary_runner_failure_cleans_up_and_cannot_emit_positive_report(
        self,
    ):
        # Derive the complete inventory so new metadata/denial cases cannot
        # silently fall outside cleanup failure coverage. Includes the nested
        # prompt callback and every restored-presentation read.
        complete = FakeGuest()
        runner.qualify(complete, Mock(), LOCK, SOURCE)
        for fail_at in range(1, len(complete.commands)):
            guest = FakeGuest(fail_at)
            with self.subTest(fail_at=fail_at), self.assertRaises(RuntimeError):
                runner.qualify(guest, Mock(), LOCK, SOURCE)
            self.assertEqual(
                guest.commands[-1], runner.FIXTURE_COMMAND + "clear-response"
            )
            self.assertFalse(guest.configured)
        guest = FakeGuest(len(complete.commands))  # Cleanup must fail the run too.
        with self.assertRaises(RuntimeError):
            runner.qualify(guest, Mock(), LOCK, SOURCE)

    def test_assistive_reports_require_exact_phase_owner_and_partial_claim(self):
        for phase in ("locked", "unlock-prompt"):
            valid = assistive(phase)
            runner.validate_assistive_report(json.dumps(valid).encode(), LOCK, phase)
            changes = (
                {"schema_version": True},
                {"schema_version": 2},
                {"claim": "complete"},
                {"phase": "wrong"},
                {"native_owner_pid": True},
                {"native_owner_pid": 1},
                {"native_owner_pid": 2**31},
                {"native_owner_invocation": "0" * 32},
                {"native_owner_start_ticks": 42},
                {"native_owner_start_ticks": "0"},
                {"native_owner_start_ticks": str(2**64)},
                {"checks": {}},
                {"checks": {key: 1 for key in valid["checks"]}},
                {"s17_complete": True},
                {"release_support_promotion": True},
                {"extra": "unreviewed"},
            )
            for change in changes:
                with (
                    self.subTest(phase=phase, change=change),
                    self.assertRaises(RuntimeError),
                ):
                    runner.validate_assistive_report(
                        json.dumps({**valid, **change}).encode(), LOCK, phase
                    )
        for malformed in (
            b"{}",
            b"null",
            b"[]",
            b"\xff",
            b"{" + b'"schema_version":1,' + b'"schema_version":1}',
            b"[" * 1100 + b"]" * 1100,
            b"x" * 16385,
        ):
            with self.subTest(length=len(malformed)), self.assertRaises(RuntimeError):
                runner.validate_assistive_report(malformed, LOCK, "locked")

    def test_wrong_guest_or_existing_password_prevents_secret_installation(self):
        with (
            patch.object(
                fixture, "require_guest", side_effect=RuntimeError("wrong guest")
            ),
            patch.object(fixture.subprocess, "run") as execute,
        ):
            with self.assertRaises(RuntimeError):
                fixture.operate("set-response", b"a" * 24 + b"\n")
            execute.assert_not_called()
        with (
            patch.object(fixture, "require_guest"),
            patch.object(
                fixture,
                "require_locked_fixture_account",
                side_effect=RuntimeError("existing password"),
            ),
            patch.object(fixture.subprocess, "run") as execute,
        ):
            with self.assertRaises(RuntimeError):
                fixture.operate("set-response", b"a" * 24 + b"\n")
            execute.assert_not_called()
        for malformed in (
            b"",
            b"a" * 24,
            b"a" * 25 + b"\n",
            b"A" * 24 + b"\n",
            b"a" * 24 + b"\nextra",
        ):
            with (
                self.subTest(length=len(malformed)),
                patch.object(fixture, "require_guest"),
                patch.object(fixture, "require_locked_fixture_account"),
                patch.object(fixture.subprocess, "run") as execute,
            ):
                with self.assertRaises(RuntimeError):
                    fixture.operate("set-response", malformed)
                execute.assert_not_called()

    def test_fixed_guest_account_commands_use_stdin_only_and_refuse_errors(self):
        with (
            patch.object(fixture, "require_guest"),
            patch.object(fixture, "require_locked_fixture_account"),
            patch.object(
                fixture.subprocess,
                "run",
                return_value=subprocess.CompletedProcess([], 0),
            ) as execute,
        ):
            response = b"a" * 24 + b"\n"
            fixture.operate("set-response", response)
            self.assertEqual(execute.call_args.args[0], ["/usr/bin/chpasswd"])
            self.assertEqual(execute.call_args.kwargs["input"], b"linura:" + response)
            self.assertEqual(execute.call_args.kwargs["stdout"], subprocess.DEVNULL)
            self.assertEqual(execute.call_args.kwargs["stderr"], subprocess.DEVNULL)
            fixture.operate("clear-response")
            self.assertEqual(
                execute.call_args.args[0], ["/usr/bin/passwd", "--lock", "linura"]
            )
        with (
            patch.object(fixture, "require_guest"),
            patch.object(
                fixture,
                "require_locked_fixture_account",
                side_effect=RuntimeError("cleanup did not restore account lock"),
            ),
            patch.object(
                fixture.subprocess,
                "run",
                return_value=subprocess.CompletedProcess([], 0),
            ) as execute,
        ):
            with self.assertRaises(RuntimeError):
                fixture.operate("clear-response")
            execute.assert_called_once()
        for failure in (
            OSError("component"),
            subprocess.TimeoutExpired("fixed", 10),
            subprocess.CompletedProcess([], 1),
        ):
            with (
                patch.object(fixture, "require_guest"),
                patch.object(fixture, "require_locked_fixture_account"),
                patch.object(fixture.subprocess, "run") as execute,
            ):
                if isinstance(failure, Exception):
                    execute.side_effect = failure
                else:
                    execute.return_value = failure
                with self.assertRaises(RuntimeError):
                    fixture.operate("set-response", b"a" * 24 + b"\n")

    def test_runner_streaming_bounds_and_ssh_failure_are_not_native_denial_evidence(
        self,
    ):
        with tempfile.TemporaryDirectory() as directory:
            identity = Path(directory) / "component-identity"
            identity.touch(mode=0o600)
            guest = runner.Guest(identity)
            self.assertIn("IdentitiesOnly=yes", guest.ssh)
            self.assertIn("IdentityAgent=none", guest.ssh)
            for program, expected, failure in (
                ("print('bounded')", b"bounded\n", False),
                ("raise SystemExit(1)", b"", True),
            ):
                guest.ssh = [sys.executable, "-c", program]
                self.assertEqual(
                    guest.run("component-only", expect_failure=failure), expected
                )
            for program, denial in (
                ("import sys; sys.stdout.write('x' * 16385)", False),
                ("raise SystemExit(255)", True),
                ("raise SystemExit(0)", True),
                ("raise SystemExit(1)", False),
            ):
                guest.ssh = [sys.executable, "-c", program]
                with self.subTest(denial=denial), self.assertRaises(RuntimeError):
                    guest.run("component-only", expect_failure=denial)
            guest.ssh = [sys.executable, "-c", "import time; time.sleep(10)"]
            with (
                patch.object(runner.time, "monotonic", side_effect=[0, 86]),
                self.assertRaises(RuntimeError),
            ):
                guest.run("component-only")
            identity.chmod(0o644)
            with self.assertRaises(RuntimeError):
                runner.Guest(identity)

    def test_completion_requires_exact_managed_identity_stages_and_freshly_verified_result(
        self,
    ):
        sample = lock_receipt("component", True, False)
        runner.validate_lock_receipt(wire(sample), "component", LOCK, True, False)
        for key, wrong in (
            ("request_id", "request:v010:session-lock:other"),
            ("resource", LOCK + ":extra"),
            ("desired_secure", "false"),
            ("completion", "acknowledged"),
            ("recovered", "true"),
            ("stages", "request-intent,execute,commit"),
            ("transaction_id", "other"),
            ("effect_digest", "unknown"),
        ):
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                runner.validate_lock_receipt(
                    wire(sample | {key: wrong}), "component", LOCK, True, False
                )
        for malformed in (
            b"state=committed\nstate=committed\n",
            b"bad\n",
            b"x" * 16385,
            b"state=\xff\n",
        ):
            with self.assertRaises(RuntimeError):
                runner.fields(malformed)
        for bad in (
            LOCK.replace(":1000:", ":0:"),
            LOCK.replace(":1000:", ":01000:"),
            LOCK.replace(":1000:", ":4294967296:"),
            LOCK.replace(":9:", ":0:"),
            LOCK.replace(":c1:", ":../:"),
            LOCK + ":extra",
        ):
            with self.assertRaises(RuntimeError):
                runner.lock_resource(bad)

    def test_unlock_history_requires_exact_request_decision_and_no_native_claim(self):
        sample = {
            "request_id": "request:v010:session-lock:component",
            "transaction_id": "transaction:v1:" + "a" * 64,
            "resource": LOCK,
            "desired_secure": "false",
            "historical_transaction_state": "committed",
            "current_native_coverage": "not-queried",
        }
        runner.validate_unlock_history(wire(sample), "component", LOCK)
        for key, wrong in (
            ("request_id", "request:v010:session-lock:other"),
            ("transaction_id", "other"),
            ("resource", LOCK + ":extra"),
            ("desired_secure", "true"),
            ("historical_transaction_state", "dispatched"),
            ("current_native_coverage", "secure"),
        ):
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                runner.validate_unlock_history(
                    wire(sample | {key: wrong}), "component", LOCK
                )
        with self.assertRaises(RuntimeError):
            runner.validate_unlock_history(
                wire(sample | {"extra": "field"}), "component", LOCK
            )

    def test_bootstrap_reader_rejects_ambiguous_unbounded_and_unqualified_inputs(self):
        sample = {
            "schema_version": 1,
            "claim": "native-session-bootstrap-only",
            "s17_complete": False,
            "release_support_promotion": False,
            "automatic_owner_activation": True,
            "lock_resource": LOCK,
            "native_polkit_supervision": {
                "pid": 4390,
                "uid": 996,
                "invocation": "c" * 32,
                "image": "/usr/lib/polkit-1/polkitd",
                "argv": [
                    "/usr/lib/polkit-1/polkitd",
                    "--no-debug",
                    "--log-level=notice",
                ],
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bootstrap.json"
            path.write_text(json.dumps(sample))
            self.assertEqual(runner.bootstrap_lock(path), LOCK)
            for key, wrong in (
                ("schema_version", True),
                ("claim", "complete"),
                ("s17_complete", True),
                ("release_support_promotion", True),
                ("automatic_owner_activation", False),
                ("lock_resource", LOCK + ":extra"),
            ):
                path.write_text(json.dumps(sample | {key: wrong}))
                with self.subTest(key=key), self.assertRaises(RuntimeError):
                    runner.bootstrap_lock(path)
            record = sample["native_polkit_supervision"]
            for mutation in (
                {"native_polkit_supervision": None},
                {"native_polkit_supervision": dict(record, pid=0)},
                {"native_polkit_supervision": dict(record, uid=0)},
                {"native_polkit_supervision": dict(record, invocation="0" * 32)},
                {"native_polkit_supervision": dict(record, argv=["/tmp/polkitd"])},
                {"native_polkit_supervision": dict(record, extra="unattested")},
            ):
                path.write_text(json.dumps(sample | mutation))
                with self.subTest(mutation=mutation), self.assertRaises(RuntimeError):
                    runner.bootstrap_lock(path)
            for malformed in (
                b"[]",
                b'{"s17_complete": false, "s17_complete": true}',
                b"[" * 2000 + b"]" * 2000,
                b"x" * 16385,
                b"\xff",
            ):
                path.write_bytes(malformed)
                with self.assertRaises(RuntimeError):
                    runner.bootstrap_lock(path)
            link = Path(directory) / "symlink.json"
            link.symlink_to(path)
            with self.assertRaises(RuntimeError):
                runner.bootstrap_lock(link)

    def test_consent_history_must_bind_exact_decision_and_supersession_without_protection_claim(
        self,
    ):
        sample = setting("component", True, False)
        runner.validate_setting(wire(sample), "component", LOCK, True, False)
        for key, wrong in (
            ("request_id", "other"),
            ("confirmation_lock", LOCK + ":extra"),
            ("recorded_consent", "revoked"),
            ("latest_for_recorded_epoch", "true"),
            ("current_native_protection", "protected"),
            ("intent_id", "intent:s17:protective-lock:" + "0" * 64),
            ("revision_id", "policy:other"),
            ("confirmed_at_unix_ms", "0"),
            ("confirmed_at_unix_ms", str(2**63)),
        ):
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                runner.validate_setting(
                    wire(sample | {key: wrong}), "component", LOCK, True, False
                )


if __name__ == "__main__":
    unittest.main()
