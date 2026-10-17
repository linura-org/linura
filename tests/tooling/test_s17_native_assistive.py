"""Native assistive fixture negative tests; not screen-reader qualification."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "s17_native_assistive_fixture",
    ROOT / "qualification/v010/session-security/native-assistive-fixture.py",
)
assert spec and spec.loader
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


def report():
    return {
        "schema_version": 1,
        "claim": "native-assistive-metadata-cases-only",
        "phase": "locked",
        "native_owner_pid": 123,
        "checks": dict.fromkeys(fixture.CHECKS, True),
        "s17_complete": False,
        "release_support_promotion": False,
    }


class NativeAssistiveFixtureTests(unittest.TestCase):
    def test_guest_guard_precedes_process_probes_and_unprivileged_execution(self):
        with (
            patch.object(fixture, "shared", side_effect=RuntimeError("wrong guest")),
            patch.object(fixture, "identity") as identity,
        ):
            with self.assertRaises(RuntimeError):
                fixture.operate("locked")
            identity.assert_not_called()
        with (
            patch.object(fixture.os, "geteuid", return_value=1000),
            patch.object(fixture, "immutable") as immutable,
        ):
            with self.assertRaises(RuntimeError):
                fixture.shared()
            immutable.assert_not_called()

    def test_positive_partial_report_is_exact_and_owner_must_survive_the_probe(self):
        port = Mock()
        port.command.return_value = json.dumps(report()).encode()
        codec = Mock()
        codec.unique_object = dict
        before = (123, "a" * 32, "42")
        with (
            patch.object(fixture, "shared", return_value=(port, codec)),
            patch.object(fixture, "identity", return_value=before) as identity,
        ):
            value = fixture.operate("locked")
            self.assertEqual(value["native_owner_invocation"], before[1])
            self.assertIs(value["s17_complete"], False)
            self.assertEqual(identity.call_count, 2)
            port.command.assert_called_once_with(
                [str(fixture.BINARY), "123", "locked"], budget=12, owner=True
            )
        for after in (
            (124, before[1], "42"),
            (123, "b" * 32, "42"),
            (123, before[1], "43"),
        ):
            with (
                self.subTest(after=after),
                patch.object(fixture, "shared", return_value=(port, codec)),
                patch.object(fixture, "identity", side_effect=[before, after]),
                self.assertRaises(RuntimeError),
            ):
                fixture.operate("locked")

    def test_no_type_aliases_extra_fields_or_complete_support_claims_are_evidence(self):
        valid = report()
        fixture.validate_report(valid, 123, "locked")
        for change in (
            {"schema_version": True},
            {"native_owner_pid": True},
            {"native_owner_pid": 124},
            {"phase": "unlock-prompt"},
            {"checks": {}},
            {"checks": dict.fromkeys(fixture.CHECKS, 1)},
            {"s17_complete": True},
            {"release_support_promotion": True},
            {"extra": True},
        ):
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                fixture.validate_report({**valid, **change}, 123, "locked")
        with patch.object(fixture, "shared") as shared, self.assertRaises(RuntimeError):
            fixture.operate("arbitrary-action")
        shared.assert_not_called()

    def test_probe_namespace_rejects_writable_symlink_hardlink_or_privileged_files(
        self,
    ):
        path = Path("/fixed/probe")

        def facts(current):
            return SimpleNamespace(
                st_uid=0,
                st_mode=(stat.S_IFREG | 0o755)
                if current == path
                else (stat.S_IFDIR | 0o755),
                st_nlink=1,
            )

        with patch.object(Path, "lstat", autospec=True, side_effect=facts):
            fixture.immutable(path, executable=True)
        for uid, mode, links in (
            (1000, stat.S_IFREG | 0o755, 1),
            (0, stat.S_IFREG | 0o777, 1),
            (0, stat.S_IFLNK | 0o755, 1),
            (0, stat.S_IFREG | 0o4755, 1),
            (0, stat.S_IFREG | 0o755, 2),
            (0, stat.S_IFREG | 0o644, 1),
        ):

            def unsafe(current):
                return (
                    SimpleNamespace(st_uid=uid, st_mode=mode, st_nlink=links)
                    if current == path
                    else facts(current)
                )

            with (
                self.subTest(uid=uid, mode=mode, links=links),
                patch.object(Path, "lstat", autospec=True, side_effect=unsafe),
                self.assertRaises(RuntimeError),
            ):
                fixture.immutable(path, executable=True)


if __name__ == "__main__":
    unittest.main()
