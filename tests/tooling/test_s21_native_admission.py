from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import Mock, call, patch

ROOT = Path(__file__).resolve().parents[2]
DIRECTORY = ROOT / "qualification/v010/session-security"


def load(name):
    spec = importlib.util.spec_from_file_location(
        name.replace("-", "_"), DIRECTORY / (name + ".py")
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


fixture = load("native-display-admission-fixture")
runner = load("qualify-native-auth")
LOCK = "session:lock:12345678-1234-1234-1234-123456789abc:1000:c1:9:12345678-1234-1234-1234-123456789abc:1"
INVOCATION = LOCK.split(":")[6].replace("-", "")


def probe():
    return {
        "schema_version": "1",
        "native_owner_pid": "123",
        "native_owner_uid": "1000",
        "native_owner_invocation": INVOCATION,
        **dict.fromkeys(fixture.CHECKS, "true"),
    }


class NativeDisplayAdmissionTests(unittest.TestCase):
    def test_exact_predicate_report_keeps_partial_scope(self):
        report = fixture.validate_report(probe(), 1000, 123, INVOCATION)
        self.assertIs(report["s21_2_complete"], False)
        self.assertIs(report["release_support_promotion"], False)
        self.assertEqual(set(report["checks"]), runner.DISPLAY_ADMISSION_CHECKS)
        self.assertEqual(
            runner.validate_display_owner_admission(
                json.dumps(report).encode(), LOCK, 123
            ),
            report,
        )

    def test_probe_refuses_absent_or_substituted_properties_and_failed_cases(self):
        original = probe()
        for field in original:
            for replacement in (None, "false", "1", "unknown"):
                if replacement == original[field]:
                    continue
                with self.subTest(field=field, replacement=replacement):
                    wrong = original.copy()
                    if replacement is None:
                        del wrong[field]
                    else:
                        wrong[field] = replacement
                    with self.assertRaises(RuntimeError):
                        fixture.validate_report(wrong, 1000, 123, INVOCATION)
        with self.assertRaises(RuntimeError):
            fixture.validate_report(
                {**original, "unexpected": "true"}, 1000, 123, INVOCATION
            )

    def test_outer_reader_binds_identity_case_inventory_and_nonpromotion(self):
        original = fixture.validate_report(probe(), 1000, 123, INVOCATION)
        cases = [
            ("native_owner_pid", 124),
            ("native_owner_pid", True),
            ("native_owner_uid", 1001),
            ("native_owner_uid", "1000"),
            ("native_owner_invocation", "a" * 32),
            ("schema_version", True),
            ("claim", "s21-complete"),
            ("s21_2_complete", True),
            ("release_support_promotion", True),
        ]
        for field, replacement in cases:
            with self.subTest(field=field, replacement=replacement):
                wrong = copy.deepcopy(original)
                wrong[field] = replacement
                with self.assertRaises(RuntimeError):
                    runner.validate_display_owner_admission(
                        json.dumps(wrong).encode(), LOCK, 123
                    )
        for check in fixture.CHECKS:
            for replacement in (None, False, 1):
                wrong = copy.deepcopy(original)
                if replacement is None:
                    del wrong["checks"][check]
                else:
                    wrong["checks"][check] = replacement
                with self.assertRaises(RuntimeError):
                    runner.validate_display_owner_admission(
                        json.dumps(wrong).encode(), LOCK, 123
                    )
        for wire in (
            b"x",
            b"[]",
            b"x" * (runner.MAXIMUM_OUTPUT + 1),
            json.dumps(original)
            .replace('"schema_version": 1', '"schema_version": 1, "schema_version": 1')
            .encode(),
        ):
            with self.assertRaises(RuntimeError):
                runner.validate_display_owner_admission(wire, LOCK, 123)

    def test_fixture_refuses_host_before_loading_any_guest_module(self):
        with (
            patch.object(fixture.os, "geteuid", return_value=1000),
            patch.object(fixture.importlib.util, "spec_from_file_location") as imported,
        ):
            with self.assertRaisesRegex(RuntimeError, "root disposable guest"):
                fixture.qualify()
            imported.assert_not_called()

    def test_guest_invokes_only_unprivileged_probe_and_rechecks_owner_lifetime(self):
        wire = "".join(f"{key}={value}\n" for key, value in probe().items()).encode()
        before = (123, INVOCATION, "42")
        for after, valid in (
            (before, True),
            ((123, INVOCATION, "43"), False),
            ((124, INVOCATION, "42"), False),
        ):
            assistive = Mock()
            assistive.identity.side_effect = [before, after]
            native = Mock()
            native.command.side_effect = [b"", wire]
            with patch.object(fixture.pwd, "getpwnam", return_value=Mock(pw_uid=1000)):
                if valid:
                    self.assertEqual(
                        fixture.run_probe(assistive, native, runner)[
                            "native_owner_pid"
                        ],
                        123,
                    )
                else:
                    with self.assertRaisesRegex(RuntimeError, "owner replacement"):
                        fixture.run_probe(assistive, native, runner)
            self.assertEqual(
                native.command.call_args_list,
                [
                    call(["/usr/bin/getcap", "-n", str(fixture.BINARY)]),
                    call([str(fixture.BINARY), "123"], budget=2, owner=True),
                ],
            )
            assistive.immutable.assert_called_once_with(fixture.BINARY, executable=True)

    def test_guest_rejects_capability_bearing_probe_before_execution(self):
        native = Mock()
        native.command.return_value = b"probe cap_ipc_lock=ep\n"
        with self.assertRaisesRegex(RuntimeError, "no file capabilities"):
            fixture.run_probe(Mock(), native, runner)
        self.assertEqual(native.command.call_count, 1)

    def test_missing_installed_probe_cannot_fall_back_to_a_fixture_pass(self):
        native, assistive = Mock(), Mock()
        assistive.immutable.side_effect = RuntimeError("missing immutable probe")
        with self.assertRaisesRegex(RuntimeError, "missing immutable probe"):
            fixture.run_probe(assistive, native, runner)
        native.command.assert_not_called()

    def test_required_admission_case_failure_aborts_native_runner_and_cleans_account(
        self,
    ):
        from tests.tooling.test_s17_native_authentication import FakeGuest

        class MissingAdmissionGuest(FakeGuest):
            def run(self, command, *args, **kwargs):
                if command == runner.DISPLAY_ADMISSION_COMMAND:
                    return b"{}"
                return super().run(command, *args, **kwargs)

        guest = MissingAdmissionGuest()
        with (
            self.assertRaisesRegex(RuntimeError, "exact owner and case scope"),
            patch.object(runner.time, "sleep"),
        ):
            runner.qualify(guest, Mock(), LOCK, "a" * 40)
        self.assertFalse(guest.configured)
        self.assertEqual(guest.commands[-1], runner.FIXTURE_COMMAND + "clear-response")


if __name__ == "__main__":
    unittest.main()
