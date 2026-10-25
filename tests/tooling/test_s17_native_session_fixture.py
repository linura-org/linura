"""Qualification fixture regression tests; not PAM/logind runtime evidence."""

from __future__ import annotations

import configparser
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, call, patch

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

    def test_exact_source_image_loader_supports_python312_dataclasses(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image_source = root / "tools/image.py"
            image_source.parent.mkdir(parents=True)
            image_source.write_text(
                "from dataclasses import dataclass\n"
                "@dataclass(frozen=True)\n"
                "class ExactSourceImage:\n"
                "    name: str\n",
                encoding="utf-8",
            )
            sys.modules.pop("linura_image", None)
            with patch.object(provision, "SOURCE_ROOT", root):
                loaded = provision.load_image_module()
            self.assertEqual(loaded.ExactSourceImage("s17").name, "s17")
            self.assertIs(sys.modules["linura_image"], loaded)

    def test_native_owner_build_uses_the_full_fixed_vm_cpu_envelope(self):
        self.assertEqual(
            provision.native_owner_build_command(Path("/tmp/native-build")),
            [
                "cmake",
                "--build",
                "/tmp/native-build",
                "--target",
                "linura-security-owner",
                "--parallel",
                "4",
            ],
        )

    def test_bounded_native_build_terminates_its_process_group_before_cleanup(self):
        process = SimpleNamespace(pid=4242)
        process.wait = Mock(
            side_effect=[
                subprocess.TimeoutExpired(["cmake"], 900),
                143,
                143,
            ]
        )
        with (
            patch.object(provision.subprocess, "Popen", return_value=process) as popen,
            patch.object(provision.os, "killpg") as killpg,
        ):
            with self.assertRaises(subprocess.TimeoutExpired):
                provision.run_bounded_process_group(["cmake"], timeout=900)
        popen.assert_called_once_with(["cmake"], start_new_session=True)
        self.assertEqual(
            process.wait.call_args_list,
            [call(timeout=900), call(timeout=5), call()],
        )
        self.assertEqual(
            killpg.call_args_list,
            [
                call(4242, provision.signal.SIGTERM),
                call(4242, provision.signal.SIGKILL),
            ],
        )

    def test_bounded_native_build_escalates_only_after_term_grace_expires(self):
        process = SimpleNamespace(pid=4343)
        process.wait = Mock(
            side_effect=[
                subprocess.TimeoutExpired(["cmake"], 900),
                subprocess.TimeoutExpired(["cmake"], 5),
                -9,
            ]
        )
        with (
            patch.object(provision.subprocess, "Popen", return_value=process),
            patch.object(provision.os, "killpg") as killpg,
        ):
            with self.assertRaises(subprocess.TimeoutExpired):
                provision.run_bounded_process_group(["cmake"], timeout=900)
        self.assertEqual(
            process.wait.call_args_list,
            [call(timeout=900), call(timeout=5), call()],
        )
        self.assertEqual(
            killpg.call_args_list,
            [
                call(4343, provision.signal.SIGTERM),
                call(4343, provision.signal.SIGKILL),
            ],
        )

    def test_bounded_native_build_preserves_nonzero_build_failure(self):
        process = SimpleNamespace(pid=4444)
        process.wait = Mock(return_value=7)
        with (
            patch.object(provision.subprocess, "Popen", return_value=process),
            patch.object(provision.os, "killpg") as killpg,
        ):
            with self.assertRaises(subprocess.CalledProcessError) as failure:
                provision.run_bounded_process_group(["cmake"], timeout=900)
        self.assertEqual(failure.exception.returncode, 7)
        self.assertEqual(failure.exception.cmd, ["cmake"])
        killpg.assert_not_called()

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
        self.assertEqual(unit["Unit"]["After"], "systemd-logind.service")
        self.assertEqual(unit["Unit"]["Requires"], "systemd-logind.service")
        environment = [
            line.removeprefix("Environment=")
            for line in (FIXTURE / "fixtures/linura-s17-session.service")
            .read_text()
            .splitlines()
            if line.startswith("Environment=")
        ]
        self.assertEqual(
            [value for value in environment if value.startswith("LIBSEAT_BACKEND=")],
            ["LIBSEAT_BACKEND=logind"],
        )
        self.assertEqual(
            [value for value in environment if value.startswith("AQ_TRACE=")],
            ["AQ_TRACE=1"],
        )
        self.assertFalse(
            any(
                value.startswith(("AQ_NO_ATOMIC=", "HYPRLAND_TRACE=", "WAYLAND_DEBUG="))
                for value in environment
            )
        )
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

    def test_native_polkit_127_bootstrap_attests_exact_launch_and_denies_substitution(
        self,
    ) -> None:
        # Old #224 bootstrap checks missed Polkit's final supervised process
        # and argv identity. Ensure this independent check fails closed before
        # accepting any newly merged #234-#240 native owner as bootstrapped.
        image = probe.POLKIT_IMAGE
        argv = (image, "--no-debug", "--log-level=notice")
        facts = {
            "ActiveState": "active",
            "SubState": "running",
            "FragmentPath": "/usr/lib/systemd/system/polkit.service",
            "DropInPaths": "",
            "MainPID": "4390",
            "InvocationID": "c" * 32,
            "ExecStart": (
                "{ path="
                + image
                + " ; argv[]="
                + " ".join(argv)
                + " ; ignore_errors=no ; pid=4390 }"
            ),
        }
        cmdline = b"\x00".join(part.encode() for part in argv) + b"\x00"
        status = {"Uid": "996\t996\t996\t996"}
        expected = {
            "pid": 4390,
            "uid": 996,
            "invocation": "c" * 32,
            "image": image,
            "argv": list(argv),
        }
        self.assertEqual(
            probe.validate_native_polkit_process(facts, cmdline, status, 996),
            expected,
        )
        substitutions = [
            (dict(facts, ActiveState="activating"), cmdline, status, 996),
            (dict(facts, FragmentPath="/tmp/polkit.service"), cmdline, status, 996),
            (
                dict(
                    facts,
                    DropInPaths="/etc/systemd/system/polkit.service.d/inject.conf",
                ),
                cmdline,
                status,
                996,
            ),
            (dict(facts, MainPID="0"), cmdline, status, 996),
            (dict(facts, InvocationID="0" * 32), cmdline, status, 996),
            (
                dict(
                    facts,
                    ExecStart=facts["ExecStart"].replace(
                        "--log-level=notice", "--log-level=debug"
                    ),
                ),
                cmdline,
                status,
                996,
            ),
            (
                dict(facts, ExecStart=facts["ExecStart"] + " { path=/tmp/evil }"),
                cmdline,
                status,
                996,
            ),
            (
                facts,
                cmdline.replace(b"--log-level=notice", b"--log-level=debug"),
                status,
                996,
            ),
            (facts, cmdline + b"--replace\x00", status, 996),
            (facts, cmdline, {"Uid": "0\t0\t0\t0"}, 996),
            (facts, cmdline, status, 0),
        ]
        for candidate in substitutions:
            case_facts, case_argv, case_status, case_uid = candidate
            with (
                self.subTest(source=case_facts, argv=case_argv, uid=case_uid),
                self.assertRaises(RuntimeError),
            ):
                probe.validate_native_polkit_process(
                    case_facts, case_argv, case_status, case_uid
                )

    def test_cold_boot_attests_polkit_after_automatic_owner_and_still_fails_closed(
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
        boot = "11111111-1111-1111-1111-111111111111"
        invocation = "a" * 32
        owner_uuid = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        lock = f"resource=session:lock:{boot}:1000:c2:123456:{owner_uuid}:1"
        capability = "/usr/lib/linura/linura-security-owner cap_ipc_lock=ep"
        replies = {
            ("id", "-u", "linura"): "1000",
            (
                "systemctl",
                "show",
                "--property=MainPID",
                "--value",
                "linura-s17-session.service",
            ): "123",
            ("loginctl", "list-sessions", "--no-legend", "--no-pager"): "c2",
            (
                "systemctl",
                "show",
                "--property=InvocationID",
                "--value",
                "linura-security-owner@1000.service",
            ): invocation,
            (
                "/usr/bin/getcap",
                "-n",
                "/usr/lib/linura/linura-security-owner",
            ): capability,
            (
                "systemctl",
                "show",
                "--property=MainPID",
                "--value",
                "linura-security-owner@1000.service",
            ): "456",
        }
        status = {"NoNewPrivs": "0"} | {
            name: "0000000000000000"
            for name in ("CapInh", "CapPrm", "CapEff", "CapAmb")
        }
        for failure in (None, "daemon unavailable", "supervised identity changed"):
            with self.subTest(failure=failure):
                guard = Mock()
                guest = SimpleNamespace(require_disposable_guest=guard)
                spec = SimpleNamespace(loader=SimpleNamespace(exec_module=Mock()))
                commands = []
                polkit_identity = {"pid": 789, "invocation": "b" * 32}

                def run(args, **kwargs):
                    guard.assert_called_once()
                    commands.append(args)
                    return SimpleNamespace(returncode=0, stdout=lock)

                def attest_polkit():
                    self.assertIn(
                        [
                            "runuser",
                            "-u",
                            "linura",
                            "--",
                            "/usr/bin/linuractl",
                            "own-session-lock",
                        ],
                        commands,
                    )
                    if failure:
                        raise RuntimeError(failure)
                    return polkit_identity

                with (
                    patch.object(
                        probe.importlib.util,
                        "spec_from_file_location",
                        return_value=spec,
                    ),
                    patch.object(
                        probe.importlib.util, "module_from_spec", return_value=guest
                    ),
                    patch.object(
                        probe, "command", side_effect=lambda *args: replies[args]
                    ),
                    patch.object(probe, "properties", return_value=facts),
                    patch.object(probe, "properties_from_proc", return_value=status),
                    patch.object(probe, "wait_for_automatic_watcher") as watcher,
                    patch.object(
                        probe, "inspect_native_polkit", side_effect=attest_polkit
                    ) as polkit,
                    patch.object(probe, "inspect_sleep_gate_assets", return_value={}),
                    patch.object(
                        probe.Path, "resolve", return_value=Path("/usr/bin/Hyprland")
                    ),
                    patch.object(probe.Path, "read_text", return_value=boot),
                    patch.object(probe.time, "monotonic", return_value=100),
                    patch.object(probe.subprocess, "run", side_effect=run),
                ):
                    if failure:
                        with self.assertRaisesRegex(RuntimeError, failure):
                            probe.inspect()
                    else:
                        report = probe.inspect()
                        self.assertEqual(
                            report["native_polkit_supervision"], polkit_identity
                        )
                    watcher.assert_called_once_with(1000)
                    polkit.assert_called_once()
                self.assertFalse(
                    any(
                        args[0] == "systemctl"
                        and any(
                            "polkit" in arg or "security-owner" in arg
                            for arg in args[1:]
                        )
                        for args in commands
                    )
                )

    def test_automatic_owner_requires_and_orders_polkit_on_cold_boot(self):
        unit = configparser.ConfigParser(interpolation=None, strict=False)
        unit.read(ROOT / "packaging/systemd/system/linura-security-owner@.service")
        for relationship in ("Requires", "After"):
            self.assertIn("polkit.service", unit["Unit"][relationship].split())

    def test_automatic_watcher_retains_only_closed_failure_categories(self):
        for outcome in (
            "success",
            "resources",
            "start-limit-hit",
            "unit-start-limit-hit",
            "trigger-limit-hit",
        ):
            self.assertEqual(
                probe.automatic_watcher_state(
                    f"Result={outcome}\nActiveState=failed\n"
                ),
                ("failed", outcome),
            )
        for wire in (
            "ActiveState=active\n",
            "ActiveState=active\nResult=success\nResult=success\n",
            "ActiveState=active\nResult=success\nExecStart=untrusted\n",
            "ActiveState=arbitrary\nResult=success\n",
            "ActiveState=failed\nResult=untrusted-payload\n",
            "ActiveState=active\nResult=success\n" + "x" * 128,
        ):
            with self.subTest(wire=wire), self.assertRaises(RuntimeError) as error:
                probe.automatic_watcher_state(wire)
            self.assertNotIn("untrusted", str(error.exception))

    def test_automatic_watcher_waits_only_for_observed_readiness(self):
        states = [
            SimpleNamespace(
                returncode=0,
                stdout=f"ActiveState={state}\nResult=success\n",
            )
            for state in ("deactivating", "inactive", "activating", "active")
        ]
        with (
            patch.object(probe.time, "monotonic", return_value=100),
            patch.object(probe.time, "sleep") as pause,
            patch.object(probe.subprocess, "run", side_effect=states) as run,
        ):
            probe.wait_for_automatic_watcher(1000)
        self.assertEqual(run.call_count, 4)
        self.assertEqual(pause.call_count, 3)
        for request in run.call_args_list:
            self.assertEqual(
                request.args[0],
                [
                    "systemctl",
                    "show",
                    "--property=ActiveState,Result",
                    "linura-security-owner@1000.path",
                ],
            )
            self.assertEqual(request.kwargs["timeout"], 10)

    def test_automatic_watcher_rejects_terminal_unknown_and_failed_reads(self):
        for result in (
            SimpleNamespace(
                returncode=0,
                stdout="ActiveState=failed\nResult=trigger-limit-hit\n",
            ),
            SimpleNamespace(
                returncode=0,
                stdout="ActiveState=unknown\nResult=success\n",
            ),
            SimpleNamespace(
                returncode=4,
                stdout="ActiveState=active\nResult=success\n",
            ),
            SimpleNamespace(
                returncode=-15,
                stdout="ActiveState=active\nResult=success\n",
            ),
            SimpleNamespace(
                returncode=0,
                stdout="ActiveState=active\nResult=success\n" + " " * 128,
            ),
        ):
            with (
                self.subTest(result=result),
                patch.object(probe.time, "monotonic", return_value=100),
                patch.object(probe.time, "sleep") as pause,
                patch.object(probe.subprocess, "run", return_value=result) as run,
                self.assertRaises(RuntimeError),
            ):
                probe.wait_for_automatic_watcher(1000)
            run.assert_called_once()
            pause.assert_not_called()

    def test_automatic_watcher_cannot_renew_budget_or_accept_late_activity(self):
        for times in ([100, 110], [100, 100, 110]):
            with (
                self.subTest(times=times),
                patch.object(probe.time, "monotonic", side_effect=times),
                patch.object(probe.time, "sleep") as pause,
                patch.object(
                    probe.subprocess,
                    "run",
                    return_value=SimpleNamespace(
                        returncode=0,
                        stdout="ActiveState=active\nResult=success\n",
                    ),
                ) as run,
                self.assertRaises(RuntimeError),
            ):
                probe.wait_for_automatic_watcher(1000)
            self.assertEqual(run.call_count, len(times) - 2)
            pause.assert_not_called()
        with (
            patch.object(probe.time, "monotonic", return_value=100),
            patch.object(probe.time, "sleep"),
            patch.object(
                probe.subprocess,
                "run",
                return_value=SimpleNamespace(
                    returncode=0,
                    stdout="ActiveState=inactive\nResult=success\n",
                ),
            ) as run,
            self.assertRaises(RuntimeError),
        ):
            probe.wait_for_automatic_watcher(1000)
        self.assertEqual(run.call_count, 100)

    def test_automatic_watcher_charges_observations_to_one_budget(self):
        with (
            patch.object(
                probe.time, "monotonic", side_effect=[100, 100, 101, 102, 105, 106]
            ),
            patch.object(probe.time, "sleep"),
            patch.object(
                probe.subprocess,
                "run",
                side_effect=[
                    SimpleNamespace(
                        returncode=0,
                        stdout="ActiveState=inactive\nResult=success\n",
                    ),
                    SimpleNamespace(
                        returncode=0,
                        stdout="ActiveState=active\nResult=success\n",
                    ),
                ],
            ) as run,
        ):
            probe.wait_for_automatic_watcher(1000)
        self.assertEqual(
            [request.kwargs["timeout"] for request in run.call_args_list], [10, 5]
        )

    def test_automatic_watcher_transport_timeout_is_not_retried(self):
        with (
            patch.object(probe.time, "monotonic", return_value=100),
            patch.object(
                probe.subprocess,
                "run",
                side_effect=subprocess.TimeoutExpired("systemctl", 10),
            ) as run,
            self.assertRaises(subprocess.TimeoutExpired),
        ):
            probe.wait_for_automatic_watcher(1000)
        run.assert_called_once()

    def test_watcher_restarts_with_its_manager_without_widening_activation(self):
        unit = configparser.ConfigParser(interpolation=None, strict=False)
        unit.read(ROOT / "packaging/systemd/system/linura-security-owner@.path")
        for relationship in ("After", "BindsTo", "PartOf"):
            self.assertEqual(unit["Unit"][relationship], "user@%i.service")
        self.assertEqual(unit["Path"]["TriggerLimitIntervalSec"], "120s")
        self.assertEqual(unit["Path"]["TriggerLimitBurst"], "5")
        self.assertEqual(unit["Install"]["WantedBy"], "user@%i.service")

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
