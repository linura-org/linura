"""Suspend harness component tests. Mocked cases are NOT native evidence."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "qualification/v010/session-security"


def load(name):
    spec = importlib.util.spec_from_file_location(
        "component_" + name.replace("-", "_"), FIXTURE / (name + ".py")
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


runner = load("qualify-native-suspend")
fixture = load("native-suspend-fixture")
codec = runner.codec
LOCK = "session:lock:12345678-1234-1234-1234-123456789abc:1000:c1:9:12345678-1234-1234-1234-123456789abc:2"
TARGET = "session:transition:suspend:0:" + LOCK.removeprefix("session:lock:")
OPERATION = "s17-native-suspend-" + "a" * 16


def wire(values):
    return "".join(f"{key}={value}\n" for key, value in values.items()).encode("ascii")


def transition(recovered=False):
    return {
        "request_id": "request:v010:session-transition:" + OPERATION,
        "transaction_id": "transaction:v1:" + "a" * 64,
        "effect_digest": "b" * 64,
        "resource": TARGET,
        "completion": "verified-committed-reconciled",
        "postcondition": "resumed-securely",
        "current_native_power_state": "not-inferred",
        "recovered": str(recovered).lower(),
        "stages": codec.STAGES,
    }


class FakeGuest:
    def __init__(self, fail_at=None, status=None):
        self.commands = []
        self.fail_at = fail_at
        self.response: bytes | None = None
        self.configured = False
        self.status = status

    def run(self, command, interaction=None, payload=None, expect_failure=False):
        self.commands.append(command)
        if len(self.commands) == self.fail_at:
            raise RuntimeError("component transport failure")
        if command.endswith("set-response"):
            self.configured = True
            self.response = payload
        elif command.endswith("clear-response"):
            self.configured = False
        if interaction:
            interaction()
        if command.endswith("own-session-lock"):
            return wire({"resource": LOCK})
        if command.endswith("queue"):
            return json.dumps({"operation": OPERATION, "resource": LOCK}).encode()
        if command.endswith(" status"):
            value = (
                self.status
                if self.status is not None
                else {
                    "state": "completed",
                    "operation": OPERATION,
                    "lock_resource": LOCK,
                    "target": TARGET,
                    "receipt": wire(transition()).decode(),
                }
            )
            return json.dumps(value).encode()
        if "recover-session-transition" in command:
            return wire(transition(True))
        fields = command.split()
        for action, secure in (("lock-session", True), ("unlock-session", False)):
            if action in fields:
                operation = fields[fields.index(action) + 1]
                return wire(
                    {
                        "request_id": "request:v010:session-lock:" + operation,
                        "transaction_id": "transaction:v1:" + "a" * 64,
                        "effect_digest": "b" * 64,
                        "resource": LOCK,
                        "desired_secure": str(secure).lower(),
                        "recovered": "false",
                        "completion": "verified-committed-reconciled",
                        "stages": codec.STAGES,
                    }
                )
        return b""


class NativeSuspendTests(unittest.TestCase):
    def qualify(self, guest, native_input=None):
        with patch.object(runner.time, "sleep"):
            return runner.qualify(guest, native_input or Mock(), "a" * 40)

    def test_response_is_private_and_success_requires_wake_verified_receipt_recovery_and_cleanup(
        self,
    ):
        guest, native_input = FakeGuest(), Mock()
        value = self.qualify(guest, native_input)
        self.assertFalse(guest.configured)
        self.assertIsNotNone(guest.response)
        assert guest.response is not None
        response = guest.response.decode().strip()
        self.assertTrue(all(response not in command for command in guest.commands))
        self.assertNotIn(response, str(value))
        native_input.wait_suspended_and_wake.assert_called_once_with()
        self.assertEqual(native_input.response.call_count, 2)
        self.assertTrue(all(value["checks"].values()))
        self.assertFalse(value["s17_complete"])
        self.assertFalse(value["release_support_promotion"])
        self.assertEqual(
            sum("transition-session " in command for command in guest.commands),
            0,
            "host must never directly submit or retry the guest service action",
        )
        self.assertEqual(guest.commands[-1], codec.FIXTURE_COMMAND + "clear-response")
        self.assertEqual(value["lock_resource"], LOCK)
        self.assertEqual(
            set(value["receipts"]), {"lock", "suspend", "suspend-recovery", "unlock"}
        )
        codec.require_same_retained_effect(
            value["receipts"]["suspend"], value["receipts"]["suspend-recovery"]
        )

    def test_recovery_cannot_allocate_a_different_valid_transaction_or_effect(self):
        for key, replacement in (
            ("transaction_id", "transaction:v1:" + "c" * 64),
            ("effect_digest", "c" * 64),
        ):
            guest = FakeGuest()
            original = guest.run

            def substitute(command, *args, **kwargs):
                value = original(command, *args, **kwargs)
                if "recover-session-transition" in command:
                    fields = codec.fields(value)
                    fields[key] = replacement
                    return wire(fields)
                return value

            with (
                self.subTest(key=key),
                patch.object(guest, "run", side_effect=substitute),
                self.assertRaises(RuntimeError),
            ):
                self.qualify(guest)
            self.assertFalse(guest.configured)

    def test_all_ordinary_failures_and_failed_cleanup_prevent_positive_report(self):
        for fail_at in range(1, 9):
            guest = FakeGuest(fail_at)
            with self.subTest(fail_at=fail_at), self.assertRaises(RuntimeError):
                self.qualify(guest)
            self.assertEqual(
                guest.commands[-1], codec.FIXTURE_COMMAND + "clear-response"
            )
            self.assertFalse(guest.configured)
        with self.assertRaises(RuntimeError):
            self.qualify(FakeGuest(9))
        native_input = Mock()
        native_input.require_suspend_wakeup.side_effect = RuntimeError(
            "unsupported wake"
        )
        guest = FakeGuest()
        with self.assertRaises(RuntimeError):
            self.qualify(guest, native_input)
        self.assertEqual(guest.commands, [])
        native_input = Mock()
        native_input.wait_suspended_and_wake.side_effect = RuntimeError("no suspend")
        guest = FakeGuest()
        with self.assertRaises(RuntimeError):
            self.qualify(guest, native_input)
        self.assertFalse(guest.configured)

    def test_acknowledgements_ended_boot_stale_coverage_and_substitution_cannot_pass(
        self,
    ):
        sample = transition()
        runner.validate_receipt(wire(sample), OPERATION, TARGET, LOCK, False)
        for key, wrong in (
            ("request_id", "request:v010:session-transition:other"),
            ("transaction_id", "unknown"),
            ("effect_digest", "unknown"),
            ("resource", TARGET + ":extra"),
            ("completion", "acknowledged"),
            ("postcondition", "original-boot-ended"),
            ("current_native_power_state", "awake"),
            ("recovered", "true"),
            ("stages", "execute,commit"),
        ):
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                runner.validate_receipt(
                    wire(sample | {key: wrong}), OPERATION, TARGET, LOCK, False
                )
        for target in (
            TARGET.replace(":suspend:", ":reboot:"),
            TARGET.replace(":0:", ":00:"),
            TARGET.replace(":0:", ":18446744073709551615:"),
            TARGET + ":extra",
        ):
            with self.assertRaises(RuntimeError):
                runner.validate_receipt(wire(sample), OPERATION, target, LOCK, False)
        for status in (
            {"state": "failed"},
            {"state": "completed"},
            {
                "state": "completed",
                "operation": "other",
                "lock_resource": LOCK,
                "target": TARGET,
                "receipt": wire(sample).decode(),
            },
        ):
            with self.assertRaises(RuntimeError):
                self.qualify(FakeGuest(status=status))
        for malformed in (
            b"[]",
            b"x" * 16385,
            b'{"state":"pending","state":"completed"}',
            b"\xff",
        ):
            with self.assertRaises(RuntimeError):
                runner.report(malformed)

    def test_guest_refuses_untrusted_context_before_any_process_or_file_creation(self):
        with (
            patch.object(fixture.os, "geteuid", return_value=1000),
            patch.object(fixture, "command") as command,
        ):
            with self.assertRaises(RuntimeError):
                fixture.shared()
            command.assert_not_called()
        with (
            patch.object(
                sys,
                "argv",
                ["native-suspend-fixture.py", "queue"],
            ),
            patch.object(fixture, "shared", side_effect=RuntimeError("wrong guest")),
            patch.object(fixture, "command") as command,
            patch.object(fixture.Path, "mkdir") as create,
        ):
            with self.assertRaises(RuntimeError):
                fixture.main()
            command.assert_not_called()
            create.assert_not_called()

    def test_guest_session_generation_unknown_and_additional_logins_fail_closed(self):
        target = {
            "User": "1000",
            "Class": "user",
            "Type": "wayland",
            "Active": "yes",
            "Remote": "no",
            "State": "active",
            "TimestampMonotonic": "9",
        }
        with patch.object(
            fixture, "command", side_effect=[b"c1 fixture\n", wire(target)]
        ):
            self.assertTrue(
                fixture.only_target_session(LOCK, codec, fixture.time.monotonic() + 20)
            )
        for field, wrong in (
            ("User", "1001"),
            ("Type", "tty"),
            ("Active", "no"),
            ("Remote", "yes"),
            ("State", "closing"),
            ("TimestampMonotonic", "10"),
        ):
            with (
                patch.object(
                    fixture,
                    "command",
                    side_effect=[b"c1 fixture\n", wire(target | {field: wrong})],
                ),
                self.assertRaises(RuntimeError),
            ):
                fixture.only_target_session(LOCK, codec, fixture.time.monotonic() + 20)
        with patch.object(
            fixture,
            "command",
            side_effect=[
                b"c1 fixture\nc2 ssh\n",
                wire(target),
                wire({"Class": "user"}),
            ],
        ):
            self.assertFalse(
                fixture.only_target_session(LOCK, codec, fixture.time.monotonic() + 20)
            )
        with (
            patch.object(
                fixture,
                "command",
                side_effect=[b"c1 fixture\nc1 duplicate\n", wire(target)],
            ),
            self.assertRaises(RuntimeError),
        ):
            fixture.only_target_session(LOCK, codec, fixture.time.monotonic() + 20)
        with (
            patch.object(
                fixture,
                "read_record",
                return_value={"operation": OPERATION, "resource": LOCK},
            ),
            patch.object(fixture, "only_target_session", return_value=True),
            patch.object(fixture.time, "monotonic", side_effect=[0, 21]),
            patch.object(fixture, "command") as command,
            self.assertRaises(RuntimeError),
        ):
            fixture.worker(codec)
        command.assert_not_called()

    def test_worker_uses_only_exact_typed_owner_commands_and_never_retries(self):
        receipt = wire(transition())
        pending = {"operation": OPERATION, "resource": LOCK}
        with (
            patch.object(fixture, "read_record", return_value=pending),
            patch.object(fixture, "only_target_session", return_value=True),
            patch.object(
                fixture, "command", side_effect=[wire({"resource": TARGET}), receipt]
            ) as command,
            patch.object(fixture, "write_record") as retained,
        ):
            fixture.worker(codec)
            self.assertEqual(
                command.call_args_list[0].args[0],
                ["/usr/bin/linuractl", "own-session-transition", "suspend"],
            )
            self.assertEqual(
                command.call_args_list[1].args[0],
                [
                    "/usr/bin/linuractl",
                    "transition-session",
                    "suspend",
                    OPERATION,
                    "S17-native-suspend-qualification",
                ],
            )
            self.assertTrue(
                all(call.kwargs["owner"] is True for call in command.call_args_list)
            )
            retained.assert_called_once_with(
                "result.json",
                {
                    "state": "completed",
                    "operation": OPERATION,
                    "lock_resource": LOCK,
                    "target": TARGET,
                    "receipt": receipt.decode("ascii"),
                },
            )
        for pending in (
            {"operation": True, "resource": LOCK},
            {"operation": OPERATION, "resource": False},
            {"operation": OPERATION + ";untrusted", "resource": LOCK},
            {"operation": OPERATION, "resource": LOCK, "command": "untrusted"},
        ):
            with (
                patch.object(fixture, "read_record", return_value=pending),
                patch.object(fixture, "command") as command,
                self.assertRaises(RuntimeError),
            ):
                fixture.worker(codec)
            command.assert_not_called()
        with (
            patch.object(
                fixture.pwd,
                "getpwnam",
                return_value=SimpleNamespace(pw_uid=1000, pw_gid=1000),
            ),
            patch.object(
                fixture.subprocess,
                "Popen",
                side_effect=OSError("component launch failure"),
            ) as launch,
        ):
            with self.assertRaises(OSError):
                fixture.command(["/usr/bin/linuractl", "own-session-lock"], owner=True)
            self.assertEqual(launch.call_args.kwargs["user"], 1000)
            self.assertEqual(launch.call_args.kwargs["group"], 1000)
            self.assertEqual(launch.call_args.kwargs["extra_groups"], ())
            self.assertEqual(
                launch.call_args.kwargs["stdin"], fixture.subprocess.DEVNULL
            )
            self.assertEqual(launch.call_args.kwargs["env"], fixture.ENVIRONMENT)

    def test_private_records_are_bounded_atomic_and_never_overwrite(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(fixture, "STATE", Path(directory)),
            patch.object(fixture, "directory"),
        ):
            fixture.write_record("pending.json", {"operation": OPERATION})
            path = Path(directory) / "pending.json"
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertFalse((Path(directory) / "pending.json.writing").exists())
            native_fstat = os.fstat

            def root_fstat(fd):
                metadata = native_fstat(fd)
                return SimpleNamespace(
                    st_mode=metadata.st_mode,
                    st_uid=0,
                    st_nlink=metadata.st_nlink,
                    st_size=metadata.st_size,
                )

            with patch.object(fixture.os, "fstat", side_effect=root_fstat):
                self.assertEqual(
                    fixture.read_record("pending.json", codec), {"operation": OPERATION}
                )
            with self.assertRaises(RuntimeError):
                fixture.write_record("pending.json", {"operation": "replacement"})
            self.assertEqual(json.loads(path.read_bytes()), {"operation": OPERATION})
            for name in ("../outside", "unknown.json"):
                with self.assertRaises(RuntimeError):
                    fixture.write_record(name, {})
                with self.assertRaises(RuntimeError):
                    fixture.read_record(name, codec)
            with self.assertRaises(RuntimeError):
                fixture.write_record("result.json", {"oversize": "x" * 16385})
            with (
                patch.object(
                    fixture.os,
                    "fstat",
                    return_value=SimpleNamespace(
                        st_mode=0o100600, st_uid=1000, st_nlink=1, st_size=1
                    ),
                ),
                self.assertRaises(RuntimeError),
            ):
                fixture.read_record("pending.json", codec)

    def test_guest_output_and_deadlines_are_bounded_without_secret_or_shell_interfaces(
        self,
    ):
        with patch.object(
            fixture.pwd,
            "getpwnam",
            return_value=SimpleNamespace(pw_uid=1000, pw_gid=1000),
        ):
            self.assertEqual(
                fixture.command([sys.executable, "-c", "print('bounded')"]),
                b"bounded\n",
            )
            for program in ("raise SystemExit(1)", "print('x' * 16385)"):
                with self.assertRaises(RuntimeError):
                    fixture.command([sys.executable, "-c", program])
            with (
                patch.object(fixture.time, "monotonic", side_effect=[0, 16]),
                self.assertRaises(RuntimeError),
            ):
                fixture.command([sys.executable, "-c", "import time; time.sleep(10)"])
            for budget in (0, -1, 91):
                with self.assertRaises(RuntimeError):
                    fixture.command(["/usr/bin/true"], budget=budget)


if __name__ == "__main__":
    unittest.main()
