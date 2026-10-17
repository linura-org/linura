"""Native runner component/adversarial tests, NEVER actual PAM qualification."""

from __future__ import annotations

import importlib.util
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

    def test_response_cannot_reach_argv_environment_or_retained_report_and_cleanup_runs(
        self,
    ):
        guest = FakeGuest()
        native_input = Mock()
        report = runner.qualify(guest, native_input, LOCK, SOURCE)
        self.assertFalse(guest.configured)
        self.assertEqual(guest.commands[-1], runner.FIXTURE_COMMAND + "clear-response")
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
        self.assertEqual(supplied[:2], [response, response])
        self.assertNotEqual(supplied[2], response)
        self.assertEqual(supplied[3], response)
        self.assertEqual(supplied[4], response)
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

    def test_every_ordinary_runner_failure_cleans_up_and_cannot_emit_positive_report(
        self,
    ):
        # Includes both native metadata probes, including the nested prompt
        # callback. Neither a failed probe nor cleanup may produce success.
        for fail_at in range(1, 17):
            guest = FakeGuest(fail_at)
            with self.subTest(fail_at=fail_at), self.assertRaises(RuntimeError):
                runner.qualify(guest, Mock(), LOCK, SOURCE)
            self.assertEqual(
                guest.commands[-1], runner.FIXTURE_COMMAND + "clear-response"
            )
            self.assertFalse(guest.configured)
        guest = FakeGuest(17)  # cleanup itself must be a failing run too
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
