"""Power-prompt selection/failure cases; component tests, NOT PAM evidence."""

from __future__ import annotations

import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "qualification/v010/session-security"


def load(path):
    spec = importlib.util.spec_from_file_location(path.stem.replace("-", "_"), path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


runner = load(FIXTURE / "qualify-native-suspend.py")
fixture = load(FIXTURE / "native-suspend-fixture.py")
assistive = load(FIXTURE / "native-assistive-fixture.py")
wire_fixture = load(ROOT / "tests/tooling/test_s17_native_input.py")
codec = runner.codec
LOCK = "session:lock:12345678-1234-1234-1234-123456789abc:1000:c1:9:12345678-1234-1234-1234-123456789abc:2"
TOKEN = "a" * 32


def state(sequence, kind="response", uid=1000, index=0, count=0):
    return f"\nLINURA-S17-PROMPT-STATE suspend-prompt {TOKEN} {sequence} {kind} {uid} {index} {count}\n".encode()


def metadata(prompt):
    return {
        "schema_version": 1,
        "claim": "native-assistive-metadata-cases-only",
        "phase": "suspend-prompt",
        "native_owner_pid": 123,
        "native_owner_invocation": LOCK.split(":")[6].replace("-", ""),
        "native_owner_start_ticks": "42",
        "checks": dict.fromkeys(assistive.CHECKS, True),
        "s17_complete": False,
        "release_support_promotion": False,
        "native_prompt": prompt,
    }


class NativePowerPromptTests(unittest.TestCase):
    def test_sleep_failure_journal_exports_only_closed_categories_and_preserves_records(
        self,
    ):
        worker = {
            "stage": "submission",
            "exit": 1,
            "categories": "verification-unsatisfied,native",
        }
        wire = b"private-wire-marker\nnative-sleep-gate-denied stage=attestation reason=helper-image\n"
        with (
            patch.object(fixture, "STATE", Path("/run/linura-s17-suspend-case")),
            patch.object(fixture, "read_record", side_effect=[None, worker]),
            patch.object(fixture, "command", return_value=wire) as command,
            patch.object(fixture, "sleep_unit_diagnostics", return_value=set()),
        ):
            value = fixture.failure_diagnostics(codec)
        record = value["records"]["worker-failure.json"]
        self.assertEqual(record["stage"], "submission")
        self.assertEqual(record["exit"], 1)
        self.assertEqual(
            set(record["categories"].split(",")),
            {
                "verification-unsatisfied",
                "native",
                "sleep-gate-attestation-helper-image",
            },
        )
        self.assertEqual(worker["categories"], "verification-unsatisfied,native")
        self.assertNotIn("private-wire-marker", json.dumps(value))
        self.assertEqual(command.call_args.kwargs, {"budget": 3})
        arguments = command.call_args.args[0]
        self.assertEqual(arguments[0], "/usr/bin/journalctl")
        self.assertIn("--boot=0", arguments)
        self.assertIn("--lines=64", arguments)
        self.assertEqual(
            [arg for arg in arguments if arg.startswith("--unit=")],
            [
                "--unit=systemd-suspend.service",
                "--unit=linura-authorityd.service",
                "--unit=linura-security-owner@1000.service",
            ],
        )
        guest = Mock()
        guest.run.return_value = json.dumps(value).encode()
        with patch.object(sys, "stderr", new_callable=io.StringIO) as output:
            runner.failure_diagnostics(guest, "fixed diagnostics")
        self.assertIn("sleep-gate-attestation-helper-image", output.getvalue())
        self.assertNotIn('"unavailable": true', output.getvalue())

    def test_sleep_owner_failure_labels_never_forward_native_or_private_text(self):
        worker = {"stage": "submission", "exit": 1, "categories": "native"}
        for label, marker in codec.SLEEP_GATE_FAILURE_MARKERS:
            if not label.startswith("sleep-owner-"):
                continue
            with (
                patch.object(fixture, "STATE", Path("/run/linura-s17-suspend-case")),
                patch.object(fixture, "read_record", side_effect=[None, worker]),
                patch.object(
                    fixture,
                    "command",
                    return_value=b"private-wire-marker\n" + marker + b"\n",
                ),
                patch.object(fixture, "sleep_unit_diagnostics", return_value=set()),
            ):
                value = fixture.failure_diagnostics(codec)
            record = value["records"]["worker-failure.json"]
            self.assertEqual(record["stage"], "submission")
            self.assertEqual(record["exit"], 1)
            self.assertEqual(set(record["categories"].split(",")), {"native", label})
            self.assertNotIn("private-wire-marker", json.dumps(value))
            self.assertEqual(worker["categories"], "native")
            guest = Mock()
            guest.run.return_value = json.dumps(value).encode()
            with patch.object(sys, "stderr", new_callable=io.StringIO) as output:
                runner.failure_diagnostics(guest, "fixed diagnostics")
            self.assertIn(label, output.getvalue())
            self.assertNotIn('"unavailable": true', output.getvalue())

        with (
            patch.object(fixture, "STATE", Path("/run/linura-s17-suspend-case")),
            patch.object(fixture, "read_record", side_effect=[None, worker]),
            patch.object(
                fixture,
                "command",
                return_value=b"native-sleep-owner-denied reason=peer-private-wire-marker\n",
            ),
            patch.object(fixture, "sleep_unit_diagnostics", return_value=set()),
        ):
            value = fixture.failure_diagnostics(codec)
        self.assertEqual(value["records"]["worker-failure.json"], worker)
        self.assertNotIn("private-wire-marker", json.dumps(value))

    def test_sleep_journal_failure_or_excess_cannot_mask_original_failure(self):
        for failure in (
            OSError("private-wire-marker"),
            RuntimeError("private-wire-marker"),
            fixture.CommandRefused(1),
            b"private-wire-marker" + b"x" * fixture.LIMIT,
        ):
            worker = {"stage": "submission", "exit": 7, "categories": "native"}
            result = (
                Mock(side_effect=failure)
                if isinstance(failure, Exception)
                else Mock(return_value=failure)
            )
            with (
                patch.object(fixture, "STATE", Path("/run/linura-s17-suspend-case")),
                patch.object(fixture, "read_record", side_effect=[None, worker]),
                patch.object(fixture, "command", new=result),
                patch.object(fixture, "sleep_unit_diagnostics", return_value=set()),
            ):
                value = fixture.failure_diagnostics(codec)
            record = value["records"]["worker-failure.json"]
            self.assertEqual(record["exit"], 7)
            self.assertEqual(
                record["categories"], "native,sleep-gate-diagnostics-unavailable"
            )
            self.assertNotIn("private-wire-marker", json.dumps(value))

    def test_sleep_unit_context_is_bounded_closed_and_never_replaces_failure(self):
        for pid in ("0", "42"):
            wire = f"ActiveState=inactive\nSubState=dead\nResult=success\nExecMainPID={pid}\n".encode()
            worker = {"stage": "submission", "exit": 7, "categories": "native"}
            with (
                patch.object(fixture, "STATE", Path("/run/linura-s17-suspend-case")),
                patch.object(fixture, "read_record", side_effect=[None, worker]),
                patch.object(
                    fixture,
                    "command",
                    side_effect=[
                        fixture.CommandRefused(1)
                        if pid == "0"
                        else b"private-wire-marker",
                        wire,
                    ],
                ) as command,
            ):
                value = fixture.failure_diagnostics(codec)
            record = value["records"]["worker-failure.json"]
            labels = set(record["categories"].split(","))
            self.assertEqual(record["exit"], 7)
            self.assertIn("native", labels)
            self.assertIn("sleep-unit-result-success", labels)
            if pid == "0":
                self.assertIn("sleep-gate-diagnostics-unavailable", labels)
            self.assertIn(
                "sleep-unit-main-pid-" + ("zero" if pid == "0" else "present"), labels
            )
            self.assertNotIn("private-wire-marker", json.dumps(value))
            self.assertEqual(command.call_count, 2)
            self.assertEqual(command.call_args.kwargs, {"budget": 2})
            self.assertEqual(
                command.call_args.args[0],
                [
                    "/usr/bin/systemctl",
                    "show",
                    "systemd-suspend.service",
                    "--no-pager",
                    "--property=ActiveState",
                    "--property=SubState",
                    "--property=Result",
                    "--property=ExecMainPID",
                ],
            )
            guest = Mock()
            guest.run.return_value = json.dumps(value).encode()
            with patch.object(sys, "stderr", new_callable=io.StringIO) as output:
                runner.failure_diagnostics(guest, "fixed diagnostics")
            self.assertIn("sleep-unit-result-success", output.getvalue())
            self.assertNotIn('"unavailable": true', output.getvalue())

    def test_unknown_malformed_excess_or_refused_unit_context_stays_unavailable(self):
        valid = (
            b"ActiveState=failed\nSubState=failed\nResult=exit-code\nExecMainPID=0\n"
        )
        for wire in (
            b"",
            b"\xff",
            b"x" * (fixture.LIMIT + 1),
            valid + b"private-wire-marker=private-wire-marker\n",
            valid.replace(b"Result=exit-code", b"SubState=failed"),
            valid.replace(b"exit-code", b"private-wire-marker"),
            valid.replace(b"ExecMainPID=0", b"ExecMainPID=00"),
            valid.replace(b"ExecMainPID=0", b"ExecMainPID=1"),
            valid.replace(b"ExecMainPID=0", b"ExecMainPID=4294967296"),
            valid.replace(b"ExecMainPID=0", b"ExecMainPID=-1"),
        ):
            with patch.object(fixture, "command", return_value=wire):
                self.assertEqual(
                    fixture.sleep_unit_diagnostics(codec),
                    {"sleep-unit-diagnostics-unavailable"},
                )
        for error in (
            OSError("private-wire-marker"),
            RuntimeError("private-wire-marker"),
            fixture.CommandRefused(1),
            fixture.subprocess.TimeoutExpired(
                "fixed", 2, output=b"private-wire-marker"
            ),
        ):
            with patch.object(fixture, "command", side_effect=error):
                self.assertEqual(
                    fixture.sleep_unit_diagnostics(codec),
                    {"sleep-unit-diagnostics-unavailable"},
                )

    def test_sleep_journal_is_not_read_for_other_power_cases_or_success(self):
        for state, worker in (
            (
                Path("/var/lib/linura-s17-transition-cases/reboot"),
                {"stage": "submission", "categories": "native"},
            ),
            (Path("/run/linura-s17-suspend-case"), None),
            (
                Path("/run/linura-s17-suspend-case"),
                {"stage": "target-query", "categories": "native"},
            ),
        ):
            with (
                patch.object(fixture, "STATE", state),
                patch.object(fixture, "read_record", side_effect=[None, worker]),
                patch.object(fixture, "command") as command,
            ):
                value = fixture.failure_diagnostics(codec)
            command.assert_not_called()
            self.assertEqual(value["records"]["worker-failure.json"], worker)

    def test_restarted_suspend_worker_cannot_repeat_an_uncertain_submission(self):
        pending = {"operation": "s17-native-suspend-" + "a" * 16, "resource": LOCK}
        with (
            patch.object(fixture, "read_record", return_value=pending),
            patch.object(fixture, "only_target_session", return_value=True),
            patch.object(
                fixture,
                "command",
                return_value=b"resource=session:transition:suspend:0:"
                + LOCK.removeprefix("session:lock:").encode()
                + b"\n",
            ) as command,
            patch.object(
                fixture, "write_record", side_effect=RuntimeError("already submitted")
            ) as write,
            self.assertRaisesRegex(RuntimeError, "already submitted"),
        ):
            fixture.worker(codec)
        self.assertEqual(command.call_count, 1)
        self.assertEqual(
            command.call_args.args[0],
            ["/usr/bin/linuractl", "own-session-transition", "suspend"],
        )
        self.assertEqual(write.call_args.args[0], "submission.json")

    def test_actual_qmp_selects_owner_in_every_supported_menu_position(self):
        # Serial state follows the actual physical-key request. No preloaded
        # successful response can let a password-only implementation pass.
        for count in range(1, 9):
            for position in range(count):
                with (
                    self.subTest(count=count, position=position),
                    tempfile.TemporaryDirectory(dir="/tmp") as directory,
                ):
                    root = Path(directory)
                    path = root / "qemu.log"
                    path.touch(mode=0o600)
                    eligible = list(range(2000, 2000 + count))
                    eligible[position] = 1000
                    keys = []
                    current = [0]

                    def publish(wire):
                        with path.open("ab") as output:
                            output.write(wire)

                    def choice():
                        index = current[0]
                        return state(
                            index + 1,
                            "identity-selection",
                            eligible[index],
                            index + 1,
                            count,
                        )

                    def reply(request):
                        if request["execute"] == "query-status":
                            result = {"running": True, "status": "running"}
                        else:
                            result = {}
                        if request["execute"] == "input-send-event":
                            events = request["arguments"]["events"]
                            key = events[0]["data"]["key"]["data"]
                            self.assertEqual(
                                [event["data"]["down"] for event in events],
                                [True, False],
                            )
                            keys.append(key)
                            if key == "down":
                                current[0] += 1
                                publish(choice())
                            elif key == "ret":
                                self.assertEqual(eligible[current[0]], 1000)
                                publish(state(current[0] + 2))
                            else:
                                self.fail(
                                    "credential was sent before attested owner prompt"
                                )
                        return (
                            json.dumps({"return": result, "id": request["id"]}).encode()
                            + b"\n"
                        )

                    server = wire_fixture.QmpServer(root, reply=reply)
                    try:
                        with (
                            wire_fixture.native_input.NativeInput(server.path) as port,
                            runner.PromptLog(path) as prompt,
                        ):
                            publish(state(1) if count == 1 else choice())
                            prompt.wait("suspend-prompt", TOKEN, LOCK, port, budget=3)
                        self.assertEqual(
                            keys, [] if count == 1 else ["down"] * position + ["ret"]
                        )
                    finally:
                        server.close()

    def test_zero_eligible_or_missing_owner_and_selection_drift_never_accept_password(
        self,
    ):
        cases = [
            b"",
            state(1, uid=0),
            state(1, uid=2000),
            state(2),
            state(1, "identity-selection", 1000, 2, 2),
            state(1, "identity-selection", 2000, 1, 2)
            + state(2, "identity-selection", 2000, 2, 2),
            state(1, "identity-selection", 2000, 1, 2)
            + state(2, "identity-selection", 2001, 2, 3),
            state(1, "identity-selection", 2000, 1, 2)
            + state(2, "identity-selection", 2001, 2, 2),
            state(1, "identity-selection", 2000, 1, 2) + state(2),
            state(1, "identity-selection", 1000, 1, 2) + state(2, uid=2000),
            state(1, "identity-selection", 1000, 1, 2)
            + state(2, "identity-selection", 2000, 2, 2),
            state(1, "identity-selection", 2000, 1, 2) * 2,
            state(1).replace(b" 1000 ", b" 01000 "),
            state(1).replace(b"response", b"private-wire-marker"),
            state(1).removesuffix(b"\n"),
        ]
        for wire in cases:
            with self.subTest(wire=wire), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "qemu.log"
                path.touch(mode=0o600)
                port = Mock()
                with runner.PromptLog(path) as prompt:
                    path.write_bytes(wire)
                    with self.assertRaises(RuntimeError) as caught:
                        prompt.wait("suspend-prompt", TOKEN, LOCK, port, budget=0.01)
                    self.assertNotIn("private-wire-marker", str(caught.exception))
                port.response.assert_not_called()

    def test_selection_keeps_original_deadline_and_input_refusal_stops_progress(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "qemu.log"
            path.touch(mode=0o600)
            clock = [0.0]
            port = Mock()

            def delayed_key(_):
                clock[0] = 36
                with path.open("ab") as output:
                    output.write(state(2))

            port.key.side_effect = delayed_key
            with (
                runner.PromptLog(path) as prompt,
                patch.object(runner.time, "monotonic", side_effect=lambda: clock[0]),
            ):
                path.write_bytes(state(1, "identity-selection", 1000, 1, 2))
                with self.assertRaises(RuntimeError):
                    prompt.wait("suspend-prompt", TOKEN, LOCK, port)
            port.key.assert_called_once_with("ret")
            port.response.assert_not_called()
            path.write_bytes(b"")
            port.reset_mock()
            port.key.side_effect = RuntimeError("input refused")
            with runner.PromptLog(path) as prompt:
                path.write_bytes(state(1, "identity-selection", 1000, 1, 2))
                with self.assertRaisesRegex(RuntimeError, "input refused"):
                    prompt.wait("suspend-prompt", TOKEN, LOCK, port)
            port.key.assert_called_once_with("ret")
            port.response.assert_not_called()

    def test_power_reports_require_exact_prompt_shape_and_owner_binding(self):
        valid = {"kind": "identity-selection", "uid": 1000, "index": 1, "count": 2}
        for prompt in (
            valid,
            {"kind": "response", "uid": 1000, "index": 0, "count": 0},
        ):
            value = metadata(prompt)
            codec.validate_assistive_report(
                json.dumps(value).encode(), LOCK, "suspend-prompt"
            )
            probe = {
                key: value
                for key, value in value.items()
                if key not in {"native_owner_invocation", "native_owner_start_ticks"}
            }
            assistive.validate_report(probe, 123, "suspend-prompt", codec)
        for change in (
            {"uid": True},
            {"uid": -1},
            {"uid": 2**31},
            {"count": 0},
            {"count": 1},
            {"count": 9},
            {"index": 0},
            {"index": 3},
            {"index": True},
            {"kind": "response"},
            {"kind": "arbitrary"},
            {"extra": True},
        ):
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                codec.validate_assistive_report(
                    json.dumps(metadata({**valid, **change})).encode(),
                    LOCK,
                    "suspend-prompt",
                )
        for change in (
            {"native_prompt": None},
            {"native_owner_invocation": "b" * 32},
            {"phase": "logout-prompt"},
        ):
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                codec.validate_assistive_report(
                    json.dumps({**metadata(valid), **change}).encode(),
                    LOCK,
                    "suspend-prompt",
                )

    def test_watcher_deduplicates_menu_and_revalidates_owner_before_each_marker(self):
        first = metadata(
            {"kind": "identity-selection", "uid": 2000, "index": 1, "count": 2}
        )
        second = metadata(
            {"kind": "identity-selection", "uid": 1000, "index": 2, "count": 2}
        )
        final = metadata({"kind": "response", "uid": 1000, "index": 0, "count": 0})
        for replaced in (False, True):
            reports = [first, first, second, final]
            if replaced:
                reports[2] = {**second, "native_owner_start_ticks": "43"}
            with (
                self.subTest(replaced=replaced),
                patch.object(
                    fixture,
                    "read_record",
                    return_value={
                        "phase": "suspend-prompt",
                        "token": TOKEN,
                        "resource": LOCK,
                    },
                ),
                patch.object(
                    fixture,
                    "command",
                    side_effect=[json.dumps(value).encode() for value in reports],
                ),
                patch.object(fixture, "serial_state") as publish,
                patch.object(fixture.time, "sleep"),
            ):
                if replaced:
                    with self.assertRaises(RuntimeError):
                        fixture.prompt_watch(codec, "suspend-prompt", TOKEN)
                    self.assertEqual(publish.call_count, 1)
                else:
                    fixture.prompt_watch(codec, "suspend-prompt", TOKEN)
                    self.assertEqual(
                        [call.args[2] for call in publish.call_args_list], [1, 2, 3]
                    )
                    self.assertEqual(
                        [call.args[3]["kind"] for call in publish.call_args_list],
                        ["identity-selection", "identity-selection", "response"],
                    )

    def test_command_retains_only_closed_failure_categories_with_shared_output_bound(
        self,
    ):
        with patch.object(
            fixture.pwd, "getpwnam", return_value=Mock(pw_uid=1000, pw_gid=1000)
        ):
            with self.assertRaises(fixture.CommandRefused) as caught:
                fixture.command(
                    [
                        sys.executable,
                        "-I",
                        "-S",
                        "-c",
                        "import sys; sys.stderr.write('private-wire-marker native assistive probe failed: presentation-tree'); sys.exit(7)",
                    ],
                    codec=codec,
                )
            self.assertEqual(caught.exception.returncode, 7)
            self.assertIn(
                "assistive-presentation-tree", caught.exception.categories.split(",")
            )
            self.assertNotIn(
                "private-wire-marker",
                str(caught.exception) + caught.exception.categories,
            )
            with self.assertRaises(RuntimeError) as caught:
                fixture.command(
                    [
                        sys.executable,
                        "-I",
                        "-S",
                        "-c",
                        "import sys; sys.stdout.write('x' * 10000); sys.stderr.write('y' * 10000)",
                    ],
                    codec=codec,
                )
            self.assertIn("exceeds its bound", str(caught.exception))

    def test_diagnostics_reject_unknown_text_and_never_count_as_acceptance(self):
        valid = {
            "claim": "failure-diagnostics-only",
            "records": {
                "prompt-failure.json": {
                    "stage": "prompt-watch",
                    "exit": 1,
                    "categories": "assistive-presentation-tree,native",
                },
                "worker-failure.json": None,
            },
        }
        guest = Mock()
        guest.run.return_value = json.dumps(valid).encode()
        with patch.object(sys, "stderr", new_callable=io.StringIO) as output:
            runner.failure_diagnostics(guest, "fixed diagnostics")
            self.assertIn('"stage": "prompt-watch"', output.getvalue())
        for record in (
            {"stage": "private-wire-marker", "exit": 1, "categories": "native"},
            {"stage": "prompt-watch", "exit": True, "categories": "native"},
            {"stage": "prompt-watch", "exit": 1, "categories": "private-wire-marker"},
        ):
            guest.run.return_value = json.dumps(
                {
                    **valid,
                    "records": {
                        "prompt-failure.json": record,
                        "worker-failure.json": None,
                    },
                }
            ).encode()
            with patch.object(sys, "stderr", new_callable=io.StringIO) as output:
                runner.failure_diagnostics(guest, "fixed diagnostics")
                self.assertIn('"unavailable": true', output.getvalue())
                self.assertNotIn("private-wire-marker", output.getvalue())
