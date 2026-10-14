"""Private QMP component tests, not native session/authentication evidence."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import subprocess
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "s17_native_input", ROOT / "qualification/v010/session-security/native_input.py"
)
assert spec and spec.loader
native_input = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native_input)


class QmpServer:
    def __init__(self, root: Path, reply=None, greeting=None):
        self.path = root / "qmp.sock"
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.bind(str(self.path))
        self.path.chmod(0o600)
        self.socket.listen(1)
        self.socket.settimeout(3)
        self.requests = []
        self.errors = []
        self.reply = reply
        self.greeting = greeting or b'{"QMP":{"version":{},"capabilities":[]}}\n'
        self.worker = threading.Thread(target=self.run)
        self.worker.start()

    def run(self):
        try:
            connection, _ = self.socket.accept()
            with connection:
                connection.settimeout(3)
                connection.sendall(self.greeting)
                with connection.makefile("rb") as reader:
                    while wire := reader.readline(16385):
                        request = json.loads(wire)
                        self.requests.append(request)
                        if self.reply is not None:
                            response = self.reply(request)
                        else:
                            result = (
                                {"running": True, "status": "running"}
                                if request["execute"] == "query-status"
                                else {}
                            )
                            response = (
                                json.dumps(
                                    {"return": result, "id": request["id"]}
                                ).encode()
                                + b"\n"
                            )
                        connection.sendall(response)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as error:
            self.errors.append(type(error).__name__)

    def close(self):
        self.worker.join(4)
        self.socket.close()
        if self.worker.is_alive() or self.errors:
            raise AssertionError("component QMP server failed")


class NativeInputTests(unittest.TestCase):
    def test_termination_requires_guest_event_not_disconnect_host_action_or_type_alias(
        self,
    ):
        client = object.__new__(native_input.NativeInput)
        client._request = Mock()
        for purpose, event, reason in (
            ("reboot", "RESET", "guest-reset"),
            ("power-off", "SHUTDOWN", "guest-shutdown"),
        ):
            sample = {
                "event": event,
                "data": {"guest": True, "reason": reason},
                "timestamp": {"seconds": 1, "microseconds": 0},
            }
            client._read = Mock(return_value=sample)
            client.wait_guest_termination(purpose)
            client._request.assert_not_called()
            for wrong in (
                sample | {"data": {"guest": False, "reason": reason}},
                sample | {"data": {"guest": 1, "reason": reason}},
                sample | {"data": {"guest": True, "reason": "host-signal"}},
                sample | {"event": "WATCHDOG"},
                sample | {"id": 1},
            ):
                client._read = Mock(return_value=wrong)
                with self.subTest(purpose=purpose), self.assertRaises(RuntimeError):
                    client.wait_guest_termination(purpose)
            client._read = Mock(side_effect=RuntimeError("disconnected"))
            with self.assertRaises(RuntimeError):
                client.wait_guest_termination(purpose)
        for purpose, budget in (
            ("suspend", 80),
            ("reboot", True),
            ("reboot", 81),
            ("power-off", 0),
        ):
            client._read = Mock()
            with self.assertRaises(RuntimeError):
                client.wait_guest_termination(purpose, budget)
            client._read.assert_not_called()
        client._read = Mock(return_value={"event": "STOP"})
        with self.assertRaises(RuntimeError):
            client.wait_guest_termination("power-off")
        self.assertEqual(client._read.call_count, 32)
        client._read = Mock()
        with (
            patch.object(native_input.time, "monotonic", side_effect=[0, 81]),
            self.assertRaises(RuntimeError),
        ):
            client.wait_guest_termination("reboot")
        client._read.assert_not_called()

    def test_vm_qmp_is_opt_in_and_never_accepts_public_reused_or_remote_paths(self):
        launcher = ROOT / "qualification/v010/shell-runtime/start-vm.sh"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "image.qcow2").touch()
            (root / "seed.img").touch()
            stub = root / "qemu-system-x86_64"
            stub.write_text("#!/bin/bash\nprintf '%s\\n' \"$@\"\n", encoding="ascii")
            stub.chmod(0o700)
            base = [
                "bash",
                str(launcher),
                "--image",
                str(root / "image.qcow2"),
                "--seed",
                str(root / "seed.img"),
                "--nic-mac",
                "52:54:00:12:34:56",
            ]
            environment = dict(os.environ, PATH=f"{root}:/usr/bin:/bin")

            def launch(*extra):
                return subprocess.run(
                    base + list(extra),
                    env=environment,
                    text=True,
                    capture_output=True,
                    timeout=5,
                    check=False,
                )

            ordinary = launch()
            self.assertEqual(ordinary.returncode, 0, ordinary.stderr)
            self.assertNotIn("-qmp", ordinary.stdout)
            private = root / "qmp.sock"
            active = launch("--qmp-socket", str(private))
            self.assertEqual(active.returncode, 0, active.stderr)
            self.assertIn(f"unix:{private},server=on,wait=off", active.stdout)
            self.assertIn("usb-tablet,bus=linura-s17-input-usb.0", active.stdout)
            for value in (
                "tcp:127.0.0.1:9000",
                "relative.sock",
                f"{root}/bad,server=off",
                f"{root}/bad\npath",
            ):
                with self.subTest(value=value):
                    self.assertEqual(launch("--qmp-socket", value).returncode, 2)
            private.touch()
            self.assertEqual(launch("--qmp-socket", str(private)).returncode, 2)
            root.chmod(0o755)
            self.assertEqual(
                launch("--qmp-socket", str(root / "unused.sock")).returncode, 2
            )
            root.chmod(0o700)

    def test_real_local_wire_only_allows_fixed_hardware_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            server = QmpServer(root)
            try:
                with native_input.NativeInput(server.path) as client:
                    client.key("ret")
                    client.click(1200, 2000)
                    count = len(server.requests)
                    for key in (
                        "return",
                        "shift-a",
                        "cmd",
                        "a\n",
                        "secret-value",
                        "",
                        "F1",
                    ):
                        with self.subTest(key=key), self.assertRaises(RuntimeError):
                            client.key(key)
                    for x, y in ((-1, 0), (0, 32768), (True, 0), (0, 1.5)):
                        with self.subTest(x=x, y=y), self.assertRaises(RuntimeError):
                            client.click(x, y)
                    for method in (
                        "human-monitor-command",
                        "guest-exec",
                        "system_reset",
                        "quit",
                    ):
                        with (
                            self.subTest(method=method),
                            self.assertRaises(RuntimeError),
                        ):
                            client._request(method)
                    with self.assertRaises(RuntimeError):
                        client.response("not-a-credential-fixture")
                    self.assertEqual(len(server.requests), count)
                self.assertEqual(
                    [item["execute"] for item in server.requests],
                    [
                        "qmp_capabilities",
                        "query-status",
                        "input-send-event",
                        "input-send-event",
                    ],
                )
                events = server.requests[2]["arguments"]["events"]
                self.assertEqual(
                    [event["data"]["down"] for event in events], [True, False]
                )
                self.assertEqual(
                    [
                        event["type"]
                        for event in server.requests[3]["arguments"]["events"]
                    ],
                    ["abs", "abs", "btn", "btn"],
                )
            finally:
                server.close()

    def test_suspend_wake_requires_supported_machine_and_independent_suspended_state(
        self,
    ):
        client = object.__new__(native_input.NativeInput)
        client._request = Mock(
            side_effect=[
                {"wakeup-suspend-support": True},
                {"running": True, "status": "running"},
                {"running": False, "status": "suspended"},
                {},
                {"running": False, "status": "suspended"},
                {"running": True, "status": "running"},
            ]
        )
        with patch.object(native_input.time, "sleep"):
            client.wait_suspended_and_wake()
        self.assertEqual(
            [call.args[0] for call in client._request.call_args_list],
            [
                "query-current-machine",
                "query-status",
                "query-status",
                "system_wakeup",
                "query-status",
                "query-status",
            ],
        )
        for machine in (
            {},
            {"wakeup-suspend-support": False},
            {"wakeup-suspend-support": 1},
            [],
        ):
            client._request = Mock(return_value=machine)
            with self.subTest(machine=machine), self.assertRaises(RuntimeError):
                client.wait_suspended_and_wake()
            self.assertEqual(client._request.call_count, 1)

    def test_suspend_wake_rejects_unknown_status_bad_ack_and_expired_original_budget(
        self,
    ):
        client = object.__new__(native_input.NativeInput)
        for status in (
            {},
            {"running": False, "status": "paused"},
            {"running": True, "status": "suspended"},
            {"running": 0, "status": "suspended"},
            {"running": False, "status": "shutdown"},
        ):
            client._request = Mock(
                side_effect=[{"wakeup-suspend-support": True}, status]
            )
            with self.assertRaises(RuntimeError):
                client.wait_suspended_and_wake()
            self.assertNotIn(
                "system_wakeup",
                [call.args[0] for call in client._request.call_args_list],
            )
        client._request = Mock(
            side_effect=[
                {"wakeup-suspend-support": True},
                {"running": False, "status": "suspended"},
                {"acknowledged": True},
            ]
        )
        with self.assertRaises(RuntimeError):
            client.wait_suspended_and_wake()
        self.assertEqual(
            [call.args[0] for call in client._request.call_args_list].count(
                "system_wakeup"
            ),
            1,
        )
        client._request = Mock(return_value={"wakeup-suspend-support": True})
        with (
            patch.object(native_input.time, "monotonic", side_effect=[0, 81]),
            self.assertRaises(RuntimeError),
        ):
            client.wait_suspended_and_wake()
        self.assertEqual(client._request.call_count, 1)
        for budget in (0, -1, 81, True, 1.5):
            client._request = Mock()
            with self.assertRaises(RuntimeError):
                client.wait_suspended_and_wake(budget)
            client._request.assert_not_called()
        client._request = Mock(
            side_effect=[
                {"wakeup-suspend-support": True},
                {"running": False, "status": "suspended"},
            ]
        )
        with (
            patch.object(native_input.time, "monotonic", side_effect=[0, 1, 81]),
            self.assertRaises(RuntimeError),
        ):
            client.wait_suspended_and_wake()
        self.assertNotIn(
            "system_wakeup", [call.args[0] for call in client._request.call_args_list]
        )

    def test_untrusted_socket_and_parent_are_rejected_before_connection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ordinary = root / "ordinary"
            ordinary.touch()
            for path in (ordinary, root / "missing", Path("relative.sock")):
                with self.subTest(path=path), self.assertRaises(RuntimeError):
                    native_input.validate_socket(path)
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
                path = root / "qmp.sock"
                server.bind(str(path))
                path.chmod(0o600)
                native_input.validate_socket(path)
                path.chmod(0o660)
                with self.assertRaises(RuntimeError):
                    native_input.validate_socket(path)
                path.chmod(0o600)
                root.chmod(0o755)
                with self.assertRaises(RuntimeError):
                    native_input.validate_socket(path)
                root.chmod(0o700)
                link = root / "link"
                link.symlink_to(path)
                with self.assertRaises(RuntimeError):
                    native_input.validate_socket(link)

    def test_malformed_error_mismatched_and_flooded_replies_fail_without_wire_diagnostics(
        self,
    ):
        replies = (
            b'{"id":1,"error":{"desc":"untrusted-wire-marker"}}\n',
            b'{"id":999,"return":{}}\n',
            b'{"id":true,"return":{}}\n',
            b'{"id":1,"id":1,"return":{}}\n',
            b"[]\n",
            b"x" * 16385,
            b'{"event":"STOP"}\n' * 33,
        )
        for reply in replies:
            with (
                self.subTest(reply_length=len(reply)),
                tempfile.TemporaryDirectory() as directory,
            ):
                server = QmpServer(Path(directory), reply=lambda _: reply)
                try:
                    with self.assertRaisesRegex(
                        RuntimeError, "native input QMP initialization failed"
                    ) as caught:
                        native_input.NativeInput(server.path)
                    self.assertNotIn("untrusted-wire-marker", str(caught.exception))
                finally:
                    server.close()

    def test_stopped_vm_is_not_native_input_readiness(self):
        def reply(request):
            result = (
                {"running": False, "status": "paused"}
                if request["execute"] == "query-status"
                else {}
            )
            return json.dumps({"id": request["id"], "return": result}).encode() + b"\n"

        with tempfile.TemporaryDirectory() as directory:
            server = QmpServer(Path(directory), reply=reply)
            try:
                with self.assertRaises(RuntimeError):
                    native_input.NativeInput(server.path)
            finally:
                server.close()


if __name__ == "__main__":
    unittest.main()
