"""Terminating runner component tests; never real native qualification evidence."""

from __future__ import annotations

import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2] / "qualification/v010/session-security"


def load(name):
    spec = importlib.util.spec_from_file_location(
        "test_ending_" + name.replace("-", "_"), ROOT / (name + ".py")
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


runner = load("qualify-native-transition")
fixture = load("native-transition-fixture")
codec = runner.codec
BOOT = "12345678-1234-1234-1234-123456789abc"
NEW_BOOT = "22345678-1234-1234-1234-123456789abc"
LOCK = "session:lock:" + BOOT + ":1000:c1:9:" + BOOT + ":2"


def pending(purpose):
    return {
        "purpose": purpose,
        "operation": "s17-native-" + purpose + "-" + "a" * 16,
        "resource": LOCK,
        "target": "session:transition:"
        + purpose
        + ":0:"
        + LOCK.removeprefix("session:lock:"),
    }


def handoff(purpose):
    return {
        "schema_version": 1,
        "source_sha": "a" * 40,
        "pending": pending(purpose),
        "cleanup_required": True,
        "s17_complete": False,
        "release_support_promotion": False,
    }


def wire(values):
    return "".join(f"{key}={value}\n" for key, value in values.items()).encode("ascii")


def receipt(purpose):
    return {
        "request_id": "request:v010:session-transition:"
        + pending(purpose)["operation"],
        "resource": pending(purpose)["target"],
        "transaction_id": "transaction:v1:" + "b" * 64,
        "effect_digest": "c" * 64,
        "completion": "verified-committed-reconciled",
        "postcondition": "original-session-ended"
        if purpose == "logout"
        else "original-boot-ended",
        "current_native_power_state": "not-inferred",
        "recovered": "true",
        "stages": codec.STAGES,
    }


class Guest:
    def __init__(self, purpose, fail_at=None, current_boot=None):
        self.purpose = purpose
        self.fail_at = fail_at
        self.current_boot = current_boot or (BOOT if purpose == "logout" else NEW_BOOT)
        self.commands = []
        self.response = None
        self.configured = False
        self.recovery = receipt(purpose)

    def run(self, command, interaction=None, payload=None):
        self.commands.append(command)
        if len(self.commands) == self.fail_at:
            raise RuntimeError("component transport failure")
        if command.endswith("set-response"):
            self.response = payload
            self.configured = True
        if command.endswith("clear-response"):
            self.configured = False
        if interaction:
            interaction()
        if command.endswith("own-session-lock"):
            return wire({"resource": LOCK})
        if "lock-session " in command:
            operation = command.split("lock-session ")[1].split()[0]
            return wire(
                {
                    "request_id": "request:v010:session-lock:" + operation,
                    "transaction_id": "transaction:v1:" + "b" * 64,
                    "effect_digest": "c" * 64,
                    "resource": LOCK,
                    "desired_secure": "true",
                    "recovered": "false",
                    "completion": "verified-committed-reconciled",
                    "stages": codec.STAGES,
                }
            )
        if "queue " in command and "--sync-token " in command:
            return json.dumps(pending(self.purpose)).encode()
        if "status " in command:
            return json.dumps(
                {
                    **pending(self.purpose),
                    "boot": self.current_boot,
                    "original_session_present": False,
                }
            ).encode()
        if "recover-session-transition " in command:
            return wire(self.recovery)
        return b""


class NativeTransitionTests(unittest.TestCase):
    def test_prepare_is_incomplete_keeps_response_private_and_never_directly_submits_effect(
        self,
    ):
        for purpose in runner.PURPOSES:
            with self.subTest(purpose=purpose), patch.object(runner.time, "sleep"):
                guest, native_input = Guest(purpose), Mock()
                prompt_log = Mock()
                value = runner.prepare(
                    guest, native_input, prompt_log, purpose, "a" * 40
                )
                self.assertEqual(value, handoff(purpose))
                self.assertTrue(value["cleanup_required"])
                self.assertFalse(value["s17_complete"])
                self.assertTrue(
                    guest.configured,
                    "cleanup is mandatory after boot, not a prepare success",
                )
                assert guest.response is not None
                response = guest.response.decode().strip()
                self.assertNotIn(response, str(value))
                self.assertTrue(
                    all(response not in command for command in guest.commands)
                )
                self.assertFalse(
                    any("transition-session " in command for command in guest.commands)
                )
                prompt_log.wait.assert_called_once()
                phase, token, resource, port = prompt_log.wait.call_args.args
                self.assertEqual(resource, pending(purpose)["resource"])
                self.assertIs(port, native_input)
                self.assertEqual(phase, runner.suspend.PROMPT_PHASES[purpose])
                self.assertRegex(token, r"^[0-9a-f]{32}$")
                if purpose == "logout":
                    native_input.wait_guest_termination.assert_not_called()
                else:
                    native_input.wait_guest_termination.assert_called_once_with(purpose)

    def test_prepare_errors_require_cleanup_and_cannot_emit_a_handoff(self):
        for failure in range(1, 5):
            with (
                self.subTest(failure=failure),
                patch.object(runner.time, "sleep"),
                self.assertRaises(RuntimeError),
            ):
                guest = Guest("reboot", failure)
                runner.prepare(guest, Mock(), Mock(), "reboot", "a" * 40)
            self.assertEqual(
                guest.commands[-1], codec.FIXTURE_COMMAND + "clear-response"
            )
            self.assertFalse(guest.configured)
        native_input = Mock()
        native_input.wait_guest_termination.side_effect = RuntimeError(
            "not a native event"
        )
        guest = Guest("power-off")
        with patch.object(runner.time, "sleep"), self.assertRaises(RuntimeError):
            runner.prepare(guest, native_input, Mock(), "power-off", "a" * 40)
        self.assertFalse(guest.configured)

    def test_prequeue_failure_retains_only_closed_owner_state_and_original_failure(
        self,
    ):
        state = {
            "ActiveState": "active",
            "SubState": "running",
            "Result": "success",
            "ExecMainCode": "0",
            "ExecMainStatus": "0",
            "MainPID": "12345",
            "InvocationID": "a" * 32,
        }

        class DiagnosticGuest(Guest):
            def run(self, command, *args, **kwargs):
                if "systemctl show linura-security-owner@" in command:
                    self.commands.append(command)
                    if state["Result"] == "diagnostic-transport-failure":
                        raise OSError("private-wire-marker")
                    return wire(state)
                if "/usr/bin/journalctl " in command:
                    self.commands.append(command)
                    return b'{"EXIT_CODE":"exited","EXIT_STATUS":"72"}\n'
                return super().run(command, *args, **kwargs)

        for result in (
            "success",
            "private-wire-marker",
            "diagnostic-transport-failure",
        ):
            state["Result"] = result
            guest, output = DiagnosticGuest("logout", fail_at=3), io.StringIO()
            with (
                self.subTest(result=result),
                patch.object(runner.sys, "stderr", output),
                self.assertRaisesRegex(RuntimeError, "component transport failure"),
            ):
                runner.prepare(guest, Mock(), Mock(), "logout", "a" * 40)
            diagnostic = output.getvalue()
            self.assertIn("native-owner-failure-state=", diagnostic)
            self.assertIn('"claim": "failure-diagnostics-only"', diagnostic)
            self.assertNotIn("private-wire-marker", diagnostic)
            self.assertNotIn("12345", diagnostic)
            self.assertIn('"exits": [{"code": "exited", "status": 72}]', diagnostic)
            if result == "success":
                self.assertIn('"same_invocation": false', diagnostic)
            self.assertFalse(any("queue " in command for command in guest.commands))
            self.assertFalse(guest.configured)
            self.assertEqual(
                guest.commands[-1], codec.FIXTURE_COMMAND + "clear-response"
            )

    def test_verify_requires_exact_recovery_twice_and_independently_relocked_account(
        self,
    ):
        for purpose in runner.PURPOSES:
            guest = Guest(purpose)
            value = runner.verify(guest, handoff(purpose), purpose, "a" * 40)
            self.assertEqual(
                sum(
                    "recover-session-transition " in command
                    for command in guest.commands
                ),
                2,
            )
            self.assertFalse(
                any("transition-session " in command for command in guest.commands)
            )
            self.assertEqual(
                guest.commands[-1], codec.FIXTURE_COMMAND + "clear-response"
            )
            self.assertTrue(all(value["checks"].values()))
            self.assertFalse(value["s17_complete"])
            self.assertFalse(value["release_support_promotion"])
        for failure in range(2, 7):
            guest = Guest("logout", failure)
            with self.subTest(failure=failure), self.assertRaises(RuntimeError):
                runner.verify(guest, handoff("logout"), "logout", "a" * 40)
            self.assertEqual(
                guest.commands[-1], codec.FIXTURE_COMMAND + "clear-response"
            )

    def test_wrong_boot_cannot_qualify_and_is_never_replayed(self):
        for purpose in runner.PURPOSES:
            guest = Guest(
                purpose, current_boot=NEW_BOOT if purpose == "logout" else BOOT
            )
            with self.subTest(purpose=purpose), self.assertRaises(RuntimeError):
                runner.verify(guest, handoff(purpose), purpose, "a" * 40)
            self.assertFalse(
                any(
                    "recover-session-transition " in command
                    for command in guest.commands
                )
            )
            self.assertEqual(
                guest.commands[-1], codec.FIXTURE_COMMAND + "clear-response"
            )

    def test_handoff_substitution_type_aliases_and_claim_promotion_are_rejected(self):
        value = handoff("reboot")
        for key, wrong in (
            ("schema_version", True),
            ("source_sha", "b" * 40),
            ("cleanup_required", False),
            ("s17_complete", True),
            ("release_support_promotion", True),
            ("pending", {}),
        ):
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                runner.validate_handoff(value | {key: wrong}, "reboot", "a" * 40)
        for key, wrong in (
            ("purpose", "power-off"),
            ("resource", LOCK + ":extra"),
            ("target", pending("power-off")["target"]),
            ("operation", "s17-native-reboot-unsafe\n"),
        ):
            item = pending("reboot") | {key: wrong}
            for validate in (
                runner.validate_pending,
                lambda item, purpose: fixture.validate_pending(item, purpose, codec),
            ):
                with self.subTest(key=key), self.assertRaises(RuntimeError):
                    validate(item, "reboot")

    def test_acknowledgement_current_power_and_incomplete_stages_cannot_qualify(self):
        sample = receipt("power-off")
        for key, wrong in (
            ("completion", "acknowledged"),
            ("postcondition", "resumed-securely"),
            ("current_native_power_state", "powered-off"),
            ("recovered", "false"),
            ("stages", "execute,commit"),
            ("request_id", "other"),
            ("resource", pending("reboot")["target"]),
            ("transaction_id", "unknown"),
            ("effect_digest", "unknown"),
        ):
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                runner.validate_receipt(
                    wire(sample | {key: wrong}), pending("power-off")
                )

    def test_worker_original_boot_and_write_once_submission_precede_only_production_request(
        self,
    ):
        purpose = "reboot"
        state = SimpleNamespace(
            read_record=Mock(return_value=pending(purpose)),
            wait_for_only_target_session=Mock(),
            command=Mock(
                side_effect=[wire({"resource": pending(purpose)["target"]}), b"receipt"]
            ),
            write_record=Mock(),
        )
        with patch.object(fixture, "boot", return_value=BOOT):
            fixture.worker(state, codec, purpose)
        state.wait_for_only_target_session.assert_called_once()
        self.assertEqual(
            state.wait_for_only_target_session.call_args.args[:2],
            (pending(purpose)["resource"], codec),
        )
        self.assertEqual(
            state.command.call_args_list[-1].args[0],
            [
                "/usr/bin/linuractl",
                "transition-session",
                purpose,
                pending(purpose)["operation"],
                "S17-native-terminating-qualification",
            ],
        )
        self.assertTrue(state.command.call_args_list[-1].kwargs["owner"])
        self.assertEqual(
            state.write_record.call_args_list[0].args[0], "submission.json"
        )
        state.command.reset_mock(side_effect=True)
        with (
            patch.object(fixture, "boot", return_value=NEW_BOOT),
            self.assertRaises(RuntimeError),
        ):
            fixture.worker(state, codec, purpose)
        state.command.assert_not_called()
        state.command.side_effect = [wire({"resource": pending(purpose)["target"]})]
        state.write_record.side_effect = RuntimeError(
            "write-once record already exists"
        )
        with (
            patch.object(fixture, "boot", return_value=BOOT),
            self.assertRaises(RuntimeError),
        ):
            fixture.worker(state, codec, purpose)
        self.assertEqual(
            state.command.call_count,
            1,
            "must not replay after an existing submission record",
        )


if __name__ == "__main__":
    unittest.main()
