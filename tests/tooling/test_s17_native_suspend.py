"""Suspend harness component tests. Mocked cases are NOT native evidence."""

from __future__ import annotations

import importlib.util
import io
import json
import os
import stat
import subprocess
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
        if "queue --sync-token " in command:
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
    def qualify(self, guest, native_input=None, prompt_log=None):
        with patch.object(runner.time, "sleep"):
            return runner.qualify(
                guest,
                native_input or Mock(),
                prompt_log or Mock(),
                "a" * 40,
            )

    def test_response_is_private_and_success_requires_wake_verified_receipt_recovery_and_cleanup(
        self,
    ):
        guest, native_input = FakeGuest(), Mock()
        prompt_log = Mock()
        value = self.qualify(guest, native_input, prompt_log)
        self.assertFalse(guest.configured)
        self.assertIsNotNone(guest.response)
        assert guest.response is not None
        response = guest.response.decode().strip()
        self.assertTrue(all(response not in command for command in guest.commands))
        self.assertNotIn(response, str(value))
        native_input.wait_suspended_and_wake.assert_called_once_with()
        prompt_log.wait.assert_called_once()
        phase, token, resource, port = prompt_log.wait.call_args.args
        self.assertEqual(resource, LOCK)
        self.assertIs(port, native_input)
        self.assertEqual(phase, "suspend-prompt")
        self.assertRegex(token, r"^[0-9a-f]{32}$")
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

    def test_failed_suspend_retains_closed_owner_diagnostics_and_original_failure(self):
        guest = FakeGuest(status={"state": "failed"})
        diagnostic = {
            "claim": "failure-diagnostics-only",
            "same_invocation": False,
            "lock_progress": ["requested", "surface-configured", "frame-flushed"],
        }
        output = io.StringIO()
        with (
            patch.object(
                codec, "owner_failure_diagnostics", return_value=diagnostic
            ) as owner,
            patch.object(runner.sys, "stderr", output),
            self.assertRaisesRegex(RuntimeError, "did not retain exact completion"),
        ):
            self.qualify(guest)
        owner.assert_called_once_with(guest, LOCK)
        self.assertIn(
            "native-owner-failure-state=" + json.dumps(diagnostic, sort_keys=True),
            output.getvalue(),
        )
        self.assertFalse(guest.configured)
        self.assertEqual(guest.commands[-1], codec.FIXTURE_COMMAND + "clear-response")
        assert guest.response is not None
        self.assertNotIn(guest.response.decode().strip(), output.getvalue())

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

    def test_prompt_log_is_fixed_fd_bounded_and_rejects_symlink_or_bad_marker(self):
        token = "a" * 32
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "qemu.log"
            path.write_bytes(b"earlier output\n")
            path.chmod(0o600)
            with runner.PromptLog(path) as prompt:
                with path.open("ab") as target:
                    target.write(
                        b"LINURA-S17-PROMPT-STATE suspend-prompt "
                        + token.encode()
                        + b" 1 response 1000 0 0\n"
                    )
                prompt.wait("suspend-prompt", token, LOCK, Mock(), budget=1)
            link = Path(directory) / "link.log"
            link.symlink_to(path)
            with self.assertRaises(RuntimeError):
                runner.PromptLog(link)
        with self.assertRaises(RuntimeError):
            runner.PromptLog(Path("relative.log"))

    def test_prompt_log_requires_complete_exact_fresh_line_and_stable_metadata(self):
        token = "a" * 32
        marker = (
            b"LINURA-S17-PROMPT-STATE suspend-prompt "
            + token.encode()
            + b" 1 response 1000 0 0"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private-wire-marker.log"
            for wire in (
                marker,
                b"prefix " + marker + b"\n",
                marker + b"suffix\n",
                marker.replace(b"suspend", b"reboot") + b"\n",
            ):
                path.write_bytes(b"")
                path.chmod(0o600)
                with runner.PromptLog(path) as prompt:
                    path.write_bytes(wire)
                    with self.assertRaises(RuntimeError) as caught:
                        prompt.wait("suspend-prompt", token, LOCK, Mock(), budget=0.01)
                    self.assertNotIn("private-wire-marker", str(caught.exception))
            path.write_bytes(marker + b"\n")
            with runner.PromptLog(path) as prompt, self.assertRaises(RuntimeError):
                prompt.wait("suspend-prompt", token, LOCK, Mock(), budget=0.01)
            path.write_bytes(b"")
            with runner.PromptLog(path) as prompt:
                path.write_bytes(marker + b"\r\n")
                prompt.wait("suspend-prompt", token, LOCK, Mock(), budget=1)
            for change in ("truncate", "writable", "hardlink", "oversize"):
                path.write_bytes(b"old\n")
                path.chmod(0o600)
                with runner.PromptLog(path) as prompt:
                    if change == "truncate":
                        path.write_bytes(b"")
                    elif change == "writable":
                        path.chmod(0o622)
                    elif change == "hardlink":
                        os.link(path, Path(directory) / "alias")
                    else:
                        with path.open("ab") as target:
                            target.write(b"x" * (256 * 1024 + 1))
                    with self.subTest(change=change), self.assertRaises(RuntimeError):
                        prompt.wait("suspend-prompt", token, LOCK, Mock(), budget=2)
                alias = Path(directory) / "alias"
                alias.unlink(missing_ok=True)

    def test_prompt_log_rejects_fifo_without_blocking(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private-wire-marker.fifo"
            os.mkfifo(path, 0o600)
            code = (
                "import importlib.util,pathlib,sys; "
                "s=importlib.util.spec_from_file_location('probe',sys.argv[1]); "
                "m=importlib.util.module_from_spec(s);s.loader.exec_module(m); "
                "m.PromptLog(pathlib.Path(sys.argv[2]))"
            )
            result = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-S",
                    "-c",
                    code,
                    str(FIXTURE / "qualify-native-suspend.py"),
                    str(path),
                ],
                capture_output=True,
                timeout=3,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                b"native prompt synchronization log is unavailable", result.stderr
            )
            self.assertNotIn(b"private-wire-marker", result.stderr)

    def test_prompt_watcher_requires_exact_root_private_record_and_serial_device(self):
        codec_mock = Mock()
        codec_mock.validate_assistive_report.return_value = {
            "native_owner_pid": 123,
            "native_owner_invocation": "a" * 32,
            "native_owner_start_ticks": "42",
            "native_prompt": {"kind": "response", "uid": 1000, "index": 0, "count": 0},
        }
        codec_mock.validate_power_prompt = codec.validate_power_prompt
        with (
            patch.object(
                fixture,
                "read_record",
                return_value={
                    "phase": "suspend-prompt",
                    "token": "a" * 32,
                    "resource": LOCK,
                },
            ),
            patch.object(fixture, "command", return_value=b"{}") as command,
            patch.object(fixture.os, "open", return_value=9),
            patch.object(
                fixture.os,
                "fstat",
                return_value=SimpleNamespace(
                    st_mode=stat.S_IFCHR | 0o620,
                    st_uid=0,
                    st_nlink=1,
                    st_rdev=os.makedev(4, 64),
                ),
            ),
            patch.object(
                fixture.os, "write", side_effect=lambda fd, wire: len(wire)
            ) as write,
            patch.object(fixture.os, "close"),
        ):
            fixture.prompt_watch(codec_mock, "suspend-prompt", "a" * 32)
        self.assertIn(
            "native-assistive-fixture.py", " ".join(command.call_args.args[0])
        )
        self.assertIn(b"suspend-prompt", write.call_args.args[1])
        codec_mock.validate_assistive_report.assert_called_once_with(
            b"{}", LOCK, "suspend-prompt"
        )
        for phase, token in (("unlock-prompt", "a" * 32), ("suspend-prompt", "bad")):
            with (
                self.subTest(phase=phase, token=token),
                self.assertRaises(RuntimeError),
            ):
                fixture.prompt_watch(codec_mock, phase, token)

    def test_prompt_owner_substitution_or_malformed_report_never_signals_readiness(
        self,
    ):
        for failure in ("replaced owner", "malformed metadata", "wrong phase"):
            codec_mock = Mock()
            codec_mock.validate_assistive_report.side_effect = RuntimeError(failure)
            with (
                self.subTest(failure=failure),
                patch.object(
                    fixture,
                    "read_record",
                    return_value={
                        "phase": "suspend-prompt",
                        "token": "a" * 32,
                        "resource": LOCK,
                    },
                ),
                patch.object(fixture, "command", return_value=b"{}") as command,
                patch.object(fixture.os, "open") as opened,
                self.assertRaises(RuntimeError),
            ):
                fixture.prompt_watch(codec_mock, "suspend-prompt", "a" * 32)
            command.assert_called_once()
            opened.assert_not_called()

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
            "Id": "c1",
            "User": "1000",
            "Class": "user",
            "Type": "wayland",
            "Active": "yes",
            "Remote": "no",
            "State": "active",
            "TimestampMonotonic": "9",
        }
        with patch.object(
            fixture,
            "command",
            side_effect=[
                json.dumps([{"session": "c1", "uid": 1000}]).encode(),
                wire(target),
            ],
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
                    side_effect=[
                        json.dumps([{"session": "c1", "uid": 1000}]).encode(),
                        wire(target | {field: wrong}),
                    ],
                ),
                self.assertRaises(RuntimeError),
            ):
                fixture.only_target_session(LOCK, codec, fixture.time.monotonic() + 20)
        with patch.object(
            fixture,
            "command",
            side_effect=[
                json.dumps(
                    [{"session": "c1", "uid": 1000}, {"session": "c2", "uid": 1000}]
                ).encode(),
                wire(target),
                wire({**target, "Id": "c2"}),
            ],
        ):
            self.assertFalse(
                fixture.only_target_session(LOCK, codec, fixture.time.monotonic() + 20)
            )
        with (
            patch.object(
                fixture,
                "command",
                side_effect=[
                    json.dumps([{"session": "c1", "uid": 1000}] * 2).encode(),
                    wire(target),
                ],
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
            self.assertEqual(retained.call_count, 2)
            self.assertEqual(
                retained.call_args_list[0].args,
                ("submission.json", {"state": "submitting", **pending}),
            )
            self.assertEqual(
                retained.call_args.args,
                (
                    "result.json",
                    {
                        "state": "completed",
                        "operation": OPERATION,
                        "lock_resource": LOCK,
                        "target": TARGET,
                        "receipt": receipt.decode("ascii"),
                    },
                ),
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
            with self.assertRaises(fixture.CommandRefused) as caught:
                fixture.command(
                    [
                        sys.executable,
                        "-c",
                        "import sys; sys.stderr.write('private-wire-marker'); sys.exit(17)",
                    ]
                )
            self.assertEqual(caught.exception.returncode, 17)
            self.assertNotIn("private-wire-marker", str(caught.exception))
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
