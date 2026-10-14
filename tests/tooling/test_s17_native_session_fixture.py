"""Qualification fixture regression tests; not PAM/logind runtime evidence."""

from __future__ import annotations

import configparser
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import call, patch

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "qualification/v010/session-security"


def load(name: str):
    spec = importlib.util.spec_from_file_location(
        name.replace("-", "_"), FIXTURE / f"{name}.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


provision = load("provision-native-session")
probe = load("check-native-session")
same_uid = load("probe-same-uid")
same_uid_runner = load("run-same-uid-probes")


class S17NativeSessionFixtureTests(unittest.TestCase):
    def test_sleep_asset_reader_rejects_mutability_links_oversize_and_read_drift(self):
        path = Path("/usr/lib/linura/s17-test-asset")
        payload = b"bounded component bytes"
        directory = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)
        valid = dict(
            st_mode=stat.S_IFREG | 0o644, st_uid=0, st_nlink=1, st_size=len(payload)
        )

        def metadata(file):
            return [directory] * len(path.parents) + [file]

        with (
            patch.object(
                probe.Path, "lstat", side_effect=metadata(SimpleNamespace(**valid))
            ),
            patch.object(probe.Path, "open", return_value=io.BytesIO(payload)),
        ):
            self.assertEqual(probe.bounded_asset(path), payload)
        for field, wrong in (
            ("st_mode", stat.S_IFLNK | 0o777),
            ("st_mode", stat.S_IFREG | 0o666),
            ("st_uid", 1000),
            ("st_nlink", 2),
            ("st_size", 65537),
        ):
            with (
                self.subTest(field=field, wrong=wrong),
                patch.object(
                    probe.Path,
                    "lstat",
                    side_effect=metadata(SimpleNamespace(**(valid | {field: wrong}))),
                ),
                patch.object(probe.Path, "open") as read,
            ):
                with self.assertRaises(RuntimeError):
                    probe.bounded_asset(path)
                read.assert_not_called()
        for actual in (payload[:-1], payload + b"changed", b"x" * 65537):
            with (
                patch.object(
                    probe.Path, "lstat", side_effect=metadata(SimpleNamespace(**valid))
                ),
                patch.object(probe.Path, "open", return_value=io.BytesIO(actual)),
            ):
                with self.assertRaises(RuntimeError):
                    probe.bounded_asset(path)
        for wrong in (
            SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=0),
            SimpleNamespace(st_mode=stat.S_IFDIR | 0o777, st_uid=0),
            SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=1000),
        ):
            with (
                patch.object(probe.Path, "lstat", return_value=wrong),
                patch.object(probe.Path, "open") as read,
            ):
                with self.assertRaises(RuntimeError):
                    probe.bounded_asset(path)
                read.assert_not_called()

    def test_native_sleep_asset_check_binds_installed_bytes_not_enforcement(self):
        payload = b"component fixture, not native qualification\n"
        with patch.object(probe, "bounded_asset", return_value=payload) as read:
            digests = probe.inspect_sleep_gate_assets()
            self.assertEqual(len(digests), 4)
            self.assertEqual(read.call_count, 8)
            for source, installed in probe.SLEEP_GATE_ASSETS:
                self.assertIn(
                    call(Path("/opt/linura-source") / source), read.call_args_list
                )
                self.assertIn(call(Path("/") / installed), read.call_args_list)
                self.assertEqual(
                    digests[installed], probe.hashlib.sha256(payload).hexdigest()
                )
        with patch.object(
            probe, "bounded_asset", side_effect=[payload, payload + b"changed"]
        ):
            with self.assertRaisesRegex(RuntimeError, "differs from exact source"):
                probe.inspect_sleep_gate_assets()
        for error in (OSError("missing"), RuntimeError("mutable or oversized")):
            with patch.object(probe, "bounded_asset", side_effect=error):
                with self.assertRaises(type(error)):
                    probe.inspect_sleep_gate_assets()
        source = (FIXTURE / "check-native-session.py").read_text()
        self.assertIn('"native_sleep_gate_enforcement_qualified": False', source)

    def same_uid_report(self):
        return {
            "schema_version": 1,
            "claim": "native-same-uid-process-access-cases-only",
            "native_owner_pid": 100,
            "native_owner_invocation": "a" * 32,
            "owner_start_ticks": "12345",
            "ptrace_scope": 0,
            "checks": {
                f"same-uid-{name}-open-denied": True
                for name in ("mem", "environ", "auxv")
            }
            | {"same-uid-ptrace-seize-denied": True},
            "s17_complete": False,
            "native_authentication_qualified": False,
            "release_support_promotion": False,
        }

    def test_native_process_attack_probe_cannot_attach_before_guest_guard(self):
        with (
            patch.object(
                same_uid, "require_guest", side_effect=RuntimeError("wrong guest")
            ),
            patch.object(same_uid.ctypes, "CDLL") as libc,
            patch.object(same_uid, "service_identity") as service,
        ):
            with self.assertRaisesRegex(RuntimeError, "wrong guest"):
                same_uid.probe()
            libc.assert_not_called()
            service.assert_not_called()
        with (
            patch.object(same_uid_runner.os, "geteuid", return_value=1000),
            patch.object(same_uid_runner.subprocess, "run") as command,
            patch.object(
                same_uid_runner.importlib.util, "spec_from_file_location"
            ) as loader,
        ):
            with self.assertRaises(RuntimeError):
                same_uid_runner.require_guest()
            command.assert_not_called()
            loader.assert_not_called()

    def test_yama_is_restored_after_success_denial_malformed_report_or_timeout(self):
        report = self.same_uid_report()
        result = subprocess.CompletedProcess([], 0, json.dumps(report).encode())
        for failure in (
            None,
            RuntimeError("synthetic failure"),
            subprocess.TimeoutExpired("fixed probe", 20),
        ):
            with (
                self.subTest(failure=type(failure).__name__),
                patch.object(same_uid_runner, "require_guest"),
                patch.object(
                    same_uid_runner.Path, "open", return_value=io.StringIO("1\n")
                ),
                patch.object(same_uid_runner, "set_scope") as scope,
                patch.object(
                    same_uid_runner.subprocess,
                    "run",
                    return_value=result,
                    side_effect=failure,
                ),
            ):
                if failure:
                    with self.assertRaises(type(failure)):
                        same_uid_runner.run()
                else:
                    self.assertEqual(same_uid_runner.run(), report)
                self.assertEqual(
                    scope.call_args_list,
                    [call("0"), call("1")],
                )
        for result in (
            subprocess.CompletedProcess([], 1, b""),
            subprocess.CompletedProcess([], 0, b"[]"),
            subprocess.CompletedProcess([], 0, b"x" * 16385),
        ):
            with (
                self.subTest(code=result.returncode, length=len(result.stdout)),
                patch.object(same_uid_runner, "require_guest"),
                patch.object(
                    same_uid_runner.Path, "open", return_value=io.StringIO("1\n")
                ),
                patch.object(same_uid_runner, "set_scope") as scope,
                patch.object(same_uid_runner.subprocess, "run", return_value=result),
            ):
                with self.assertRaises(RuntimeError):
                    same_uid_runner.run()
                self.assertEqual(
                    scope.call_args_list,
                    [call("0"), call("1")],
                )
        with (
            patch.object(
                same_uid_runner,
                "require_guest",
                side_effect=RuntimeError("wrong guest"),
            ),
            patch.object(same_uid_runner, "set_scope") as scope,
        ):
            with self.assertRaises(RuntimeError):
                same_uid_runner.run()
            scope.assert_not_called()

    def test_native_process_report_rejects_missing_failure_coercion_or_scope_promotion(
        self,
    ):
        report = self.same_uid_report()
        self.assertEqual(same_uid_runner.validate_report(report), report)
        for field in report:
            changed = dict(report)
            del changed[field]
            with self.subTest(missing=field), self.assertRaises(RuntimeError):
                same_uid_runner.validate_report(changed)
        for field, value in (
            ("s17_complete", True),
            ("native_authentication_qualified", True),
            ("release_support_promotion", True),
            ("ptrace_scope", 1),
            ("ptrace_scope", False),
            ("native_owner_pid", True),
            ("owner_start_ticks", "0"),
        ):
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                same_uid_runner.validate_report(dict(report, **{field: value}))
        for key in report["checks"]:
            for value in (False, 1, "true", None):
                changed = dict(report, checks=dict(report["checks"], **{key: value}))
                with (
                    self.subTest(check=key, value=value),
                    self.assertRaises(RuntimeError),
                ):
                    same_uid_runner.validate_report(changed)
        with self.assertRaises(ValueError):
            same_uid_runner.unique_object([("checks", {}), ("checks", {})])

    def test_locked_native_power_recovery_never_dispatches_or_trusts_a_reply(self):
        source = (
            ROOT / "apps/linura-shell/security-owner/native_runtime.cpp"
        ).read_text()
        recovery = source.split("void NativeRuntime::recoverNativeTransition()", 1)[
            1
        ].split("void NativeRuntime::recoverNativeUnlock()", 1)[0]
        for method in (
            "GetSessionTransitionRequestStatus",
            "RecoverSessionTransition",
            "AcknowledgeSessionTransition",
        ):
            self.assertIn(f'QStringLiteral("{method}")', recovery)
        for forbidden in (
            "ConvergeSession",
            "dispatchPrepared",
            "commitSuspend(",
            "applyNative(",
            "protocol->dispatch",
        ):
            self.assertNotIn(forbidden, recovery)
        self.assertIn("transitionRecoveryAttempts >= 3", recovery)
        self.assertIn("decodeNativeTransitionStatus", recovery)
        self.assertIn("transitionFence.active()", recovery)
        self.assertIn(
            "stillCurrent(NativePeerPurpose::ControlApproval, control)", recovery
        )
        self.assertNotIn("reply->reply()", recovery)
        self.assertNotIn("reply->isError()", recovery)

    def test_provisioning_cannot_touch_a_non_guest_environment(self):
        with (
            patch.object(provision.os, "geteuid", return_value=1000),
            patch.object(provision, "command") as command,
        ):
            with self.assertRaisesRegex(RuntimeError, "root inside the disposable VM"):
                provision.provision()
            command.assert_not_called()
        for host in ("none", "docker", "podman", "microsoft", "oracle", "vmware"):
            with (
                self.subTest(host=host),
                patch.object(provision.os, "geteuid", return_value=0),
                patch.object(provision, "command", return_value=host),
                patch.object(
                    provision.importlib.util, "spec_from_file_location"
                ) as install,
            ):
                with self.assertRaisesRegex(RuntimeError, "non-QEMU"):
                    provision.provision()
                install.assert_not_called()
        with (
            patch.object(provision.os, "geteuid", return_value=0),
            patch.object(provision, "command", return_value="qemu"),
            patch.object(
                provision.os,
                "uname",
                return_value=SimpleNamespace(nodename="unrelated-qemu-guest"),
            ),
            patch.object(
                provision.importlib.util, "spec_from_file_location"
            ) as install,
        ):
            with self.assertRaisesRegex(RuntimeError, "dedicated qualification guest"):
                provision.provision()
            install.assert_not_called()

    def test_guest_identity_uses_kernel_hostname_without_optional_executable(self):
        directory = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)
        for virtualization in ("qemu", "kvm"):
            with (
                self.subTest(virtualization=virtualization),
                patch.object(provision.os, "geteuid", return_value=0),
                patch.object(
                    provision.os,
                    "uname",
                    return_value=SimpleNamespace(nodename="linura-v010-shell"),
                ),
                patch.object(
                    provision, "command", return_value=virtualization
                ) as command,
                patch.object(provision.Path, "read_text", return_value="ID=arch\n"),
                patch.object(provision.Path, "lstat", return_value=directory),
            ):
                provision.require_disposable_guest()
                command.assert_called_once_with("systemd-detect-virt", "--vm")
        for wrong in ("ID=ubuntu\n", "ID=arch-derivative\n", ""):
            with (
                self.subTest(os_release=wrong),
                patch.object(provision.os, "geteuid", return_value=0),
                patch.object(
                    provision.os,
                    "uname",
                    return_value=SimpleNamespace(nodename="linura-v010-shell"),
                ),
                patch.object(provision, "command", return_value="qemu"),
                patch.object(provision.Path, "read_text", return_value=wrong),
            ):
                with self.assertRaisesRegex(RuntimeError, "pinned Arch substrate"):
                    provision.require_disposable_guest()

    def test_compositor_is_the_real_pam_logind_leader_not_a_lingering_wrapper(self):
        unit = configparser.ConfigParser(interpolation=None, strict=False)
        unit.optionxform = lambda optionstr: optionstr
        unit.read(FIXTURE / "fixtures/linura-s17-session.service")
        service = unit["Service"]
        self.assertEqual(service["User"], "linura")
        self.assertEqual(service["PAMName"], "linura-s17-qualification")
        self.assertEqual(
            service["ExecStart"],
            "/usr/bin/Hyprland --config /etc/linura-qualification/s17-hyprland.conf",
        )
        self.assertEqual(service["StandardInput"], "tty")
        self.assertEqual(service["TTYPath"], "/dev/tty1")
        self.assertEqual(service["Restart"], "no")
        pam = (FIXTURE / "fixtures/linura-s17-qualification.pam").read_text()
        self.assertIn("auth required pam_deny.so", pam)
        self.assertIn("account include system-local-login", pam)
        self.assertIn("session include system-local-login", pam)
        self.assertNotIn("pam_permit", pam)

    def test_native_session_facts_fail_closed_on_each_missing_or_substituted_field(
        self,
    ):
        facts = {
            "User": "1000",
            "Leader": "123",
            "Type": "wayland",
            "Class": "user",
            "State": "active",
            "Active": "yes",
            "Remote": "no",
            "Seat": "seat0",
            "VTNr": "1",
            "Service": "linura-s17-qualification",
            "Id": "c2",
            "TimestampMonotonic": "123456",
        }
        probe.validate_session(facts, 1000, 123)
        for key in facts:
            for replacement in (None, "", "unknown"):
                changed = dict(facts)
                if replacement is None:
                    del changed[key]
                else:
                    changed[key] = replacement
                # Session IDs are bounded native labels; "unknown" can be a
                # valid label, but cannot substitute any qualified fact.
                if key == "Id" and replacement == "unknown":
                    continue
                with (
                    self.subTest(key=key, replacement=replacement),
                    self.assertRaises(RuntimeError),
                ):
                    probe.validate_session(changed, 1000, 123)
        for key, value in (
            ("User", "0"),
            ("Leader", "124"),
            ("Type", "tty"),
            ("Class", "manager"),
            ("Remote", "yes"),
            ("TimestampMonotonic", "0123"),
            ("Id", "../../tty1"),
        ):
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                probe.validate_session(dict(facts, **{key: value}), 1000, 123)

    def test_bootstrap_report_does_not_claim_full_s17_authentication_or_support(self):
        source = (FIXTURE / "check-native-session.py").read_text()
        self.assertIn('"claim": "native-session-bootstrap-only"', source)
        self.assertIn('"native_authentication_qualified": False', source)
        self.assertIn('"s17_complete": False', source)
        self.assertIn('"release_support_promotion": False', source)
        self.assertNotIn('"start", f"linura-security-owner', source)
        self.assertNotIn('"enable", f"linura-security-owner', source)
        self.assertIn('"own-session-lock"', source)
        self.assertIn('"NoNewPrivs") != "0"', source)


if __name__ == "__main__":
    unittest.main()
