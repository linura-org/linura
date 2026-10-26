from __future__ import annotations

import hashlib
import json
import os
import signal
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tools.codex import doctor  # noqa: E402


class CodexReadinessTests(unittest.TestCase):
    def test_missing_tools_are_aggregated_and_do_not_install(self) -> None:
        calls = []

        def missing(argv, env):
            calls.append(argv)
            self.assertEqual(env["RUSTUP_AUTO_INSTALL"], "0")
            self.assertEqual(env["CARGO_NET_OFFLINE"], "true")
            return None

        with (
            patch.object(doctor, "probe", side_effect=missing),
            patch.object(doctor, "probe_status", side_effect=missing),
            patch.object(doctor.shutil, "which", return_value=None),
        ):
            checks = doctor.inventory(set(doctor.PROFILES))
        failed = {check.name for check in checks if not check.ready}
        self.assertTrue(
            {
                "rustup-version",
                "cargo-audit-version",
                "actionlint-version",
                "locked-offline-cargo-graph",
                "qt6-development-modules",
                "qt6-qml-runtime-imports",
                "sdk-qmlls-runtime",
                "hash-locked-build-environment",
                "qemu-system-x86_64",
                "mkarchiso",
                "ffprobe",
                "curl",
                "tar",
                "getconf",
                "python3",
                "awk",
                "tr",
            }
            <= failed
        )
        self.assertTrue(calls)
        self.assertFalse(any("install" in argv or "fetch" in argv for argv in calls))

    def test_pinned_python_probe_uses_private_selection_even_with_newer_launcher(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tools = Path(directory) / "linura-tools"
            binary_dir = tools / "python312/bin"
            binary_dir.mkdir(parents=True, mode=0o700)
            selected = binary_dir / "python3"
            selected.symlink_to(sys.executable)
            env = {"PATH": "/usr/bin"}
            calls = []

            def fake_probe(argv, passed_env):
                calls.append((argv, passed_env["PATH"]))
                return "3.12"

            with patch.object(doctor, "probe", side_effect=fake_probe):
                self.assertTrue(doctor.pinned_python_ready(tools, env, "3.12"))
            self.assertEqual(calls[0][0][:3], [str(selected), "-I", "-S"])
            self.assertEqual(calls[0][1], "/usr/bin")
            self.assertEqual(env["PATH"], f"{binary_dir}:/usr/bin")

    def test_pinned_python_probe_rejects_missing_drifted_or_unsafe_selection(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tools = Path(directory) / "linura-tools"
            binary_dir = tools / "python312/bin"
            binary_dir.mkdir(parents=True, mode=0o700)
            selected = binary_dir / "python3"
            env = {"PATH": "/usr/bin"}
            with patch.object(doctor, "probe") as probe:
                self.assertFalse(doctor.pinned_python_ready(tools, env, "3.12"))
                selected.write_text("imposter", encoding="utf-8")
                self.assertFalse(doctor.pinned_python_ready(tools, env, "3.12"))
                selected.unlink()
                selected.symlink_to(binary_dir / "missing")
                self.assertFalse(doctor.pinned_python_ready(tools, env, "3.12"))
                selected.unlink()
                selected.symlink_to(sys.executable)
                binary_dir.chmod(0o755)
                self.assertFalse(doctor.pinned_python_ready(tools, env, "3.12"))
                binary_dir.chmod(0o700)
                probe.return_value = "3.14"
                self.assertFalse(doctor.pinned_python_ready(tools, env, "3.12"))
                probe.assert_called_once()
            self.assertEqual(env["PATH"], "/usr/bin")

    def test_readiness_reports_missing_tools_without_claiming_incompatibility(self):
        with (
            patch.object(doctor, "probe", return_value=None),
            patch.object(doctor, "probe_status", return_value=False),
            patch.object(doctor.shutil, "which", return_value=None),
            patch.object(doctor, "pinned_python_ready", return_value=False),
        ):
            checks = doctor.inventory({"core", "shell"})
        statuses = {check.name: check.status for check in checks}
        self.assertEqual(statuses["rustup"], "missing")
        self.assertEqual(statuses["qt6-module-core"], "unverified")
        self.assertEqual(statuses["cmake"], "missing")
        self.assertEqual(statuses["locked-offline-cargo-graph"], "unverified")
        self.assertEqual(statuses["rustup-version"], "unverified")
        self.assertTrue(
            all(check.ready == (check.status == "ready") for check in checks)
        )

    def test_rust_toolchain_inventory_rejects_absent_pin_and_override(self):
        pins = doctor.versions()
        toolchain = f"{pins['RUST_VERSION']}-x86_64-unknown-linux-gnu"

        def fake_probe(argv, _env):
            if argv == ["rustup", "toolchain", "list"]:
                return "1.97.0-x86_64-unknown-linux-gnu (default)"
            if argv == ["rustup", "show", "active-toolchain"]:
                return toolchain
            return None

        with (
            patch.dict(os.environ, {"RUSTUP_TOOLCHAIN": "stable"}),
            patch.object(doctor, "probe", side_effect=fake_probe),
            patch.object(doctor, "probe_status", return_value=False),
            patch.object(doctor.shutil, "which", return_value=None),
            patch.object(doctor, "pinned_python_ready", return_value=False),
        ):
            checks = doctor.inventory({"core"})
        statuses = {check.name: check.status for check in checks}
        self.assertEqual(statuses["installed-toolchain"], "missing")
        self.assertEqual(statuses["rust-toolchain-override"], "incompatible")
        self.assertEqual(statuses["active-toolchain"], "ready")
        self.assertEqual(statuses["locked-offline-cargo-graph"], "unverified")

    def test_vm_diagnostic_uses_selected_python_not_launcher(self):
        # The CI launcher may itself be the private pinned Python; simulate a
        # different host launcher to prove there is no interpreter fallback.
        observed = []

        def fake_probe(argv, _env):
            observed.append(argv)
            return None

        with (
            patch.object(doctor.sys, "executable", "/usr/bin/python3-host-launcher"),
            patch.object(doctor, "probe", side_effect=fake_probe),
            patch.object(doctor, "probe_status", return_value=False),
            patch.object(doctor.shutil, "which", return_value=None),
            patch.object(doctor, "pinned_python_ready", return_value=True),
        ):
            doctor.inventory({"core", "vm"})
        vm_calls = [args for args in observed if args[-2:] == ["tools/vm.py", "doctor"]]
        self.assertEqual(len(vm_calls), 1)
        self.assertTrue(vm_calls[0][0].endswith("/linura-tools/python312/bin/python3"))
        self.assertNotEqual(vm_calls[0][0], "/usr/bin/python3-host-launcher")

    def test_vm_diagnostic_never_runs_rejected_private_python(self):
        calls = []

        def fake_probe(argv, _env):
            calls.append(argv)
            if argv[-2:] == ["tools/vm.py", "doctor"]:
                return "forged success"
            return None

        with (
            patch.object(doctor, "probe", side_effect=fake_probe),
            patch.object(doctor, "probe_status", return_value=False),
            patch.object(doctor.shutil, "which", return_value=None),
            patch.object(doctor, "pinned_python_ready", return_value=False),
        ):
            checks = doctor.inventory({"core", "vm"})
        results = {check.name: check for check in checks}
        self.assertFalse(results["python"].ready)
        self.assertFalse(results["canonical-vm-doctor"].ready)
        self.assertEqual(results["canonical-vm-doctor"].status, "unverified")
        self.assertFalse(any(argv[-2:] == ["tools/vm.py", "doctor"] for argv in calls))

    def test_vm_doctor_rejects_regular_executable_python_substitution(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            binary_dir = home / ".local/linura-tools/python312/bin"
            binary_dir.mkdir(parents=True, mode=0o700)
            imposter = binary_dir / "python3"
            imposter.write_text("#!/bin/sh\necho forged\n", encoding="utf-8")
            imposter.chmod(0o700)
            calls = []

            def fake_probe(argv, _env):
                calls.append(argv)
                if argv[-2:] == ["tools/vm.py", "doctor"]:
                    return "forged success"
                return None

            with (
                patch.object(doctor.Path, "home", return_value=home),
                patch.object(doctor, "probe", side_effect=fake_probe),
                patch.object(doctor, "probe_status", return_value=False),
                patch.object(doctor.shutil, "which", return_value=None),
            ):
                checks = doctor.inventory({"core", "vm"})
            results = {check.name: check for check in checks}
            self.assertFalse(results["python"].ready)
            self.assertFalse(results["canonical-vm-doctor"].ready)
            self.assertEqual(results["canonical-vm-doctor"].status, "unverified")
            self.assertFalse(
                any(argv[-2:] == ["tools/vm.py", "doctor"] for argv in calls)
            )

    def test_qt_modules_and_editor_sdk_must_share_one_version(self):
        def check_versions(core_version, qml_version, sdk_version):
            versions = {module: core_version for module in doctor.QT_MODULES}
            versions["Qt6Qml"] = qml_version

            def fake_probe(argv, _env):
                if argv[:2] == ["pkg-config", "--modversion"]:
                    return versions[argv[2]]
                if argv[:2] == ["pkg-config", "--atleast-version=6.4"]:
                    return ""
                if argv == ["cmake", "--version"]:
                    return "cmake version 3.27.0"
                if argv[-1:] == ["--query"]:
                    return f"QT_VERSION:{sdk_version}\nQT_INSTALL_QML:/missing\nQT_INSTALL_BINS:/missing"
                return None

            with (
                patch.object(doctor, "probe", side_effect=fake_probe),
                patch.object(doctor, "probe_status", return_value=False),
                patch.object(doctor.shutil, "which", return_value="/usr/bin/probe"),
                patch.object(doctor, "pinned_python_ready", return_value=True),
            ):
                return {
                    check.name: check for check in doctor.inventory({"core", "editor"})
                }

        mixed = check_versions("6.4.2", "6.5.0", "6.4.2")
        self.assertTrue(mixed["qt6-module-qml"].ready)
        self.assertFalse(mixed["qt6-development-modules"].ready)
        self.assertEqual(mixed["qt6-development-modules"].status, "incompatible")
        self.assertFalse(mixed["qt6-sdk-version-alignment"].ready)

        mismatched_editor = check_versions("6.4.2", "6.4.2", "6.5.0")
        self.assertTrue(mismatched_editor["qt6-development-modules"].ready)
        self.assertFalse(mismatched_editor["qt6-sdk-version-alignment"].ready)
        self.assertEqual(
            mismatched_editor["qt6-sdk-version-alignment"].status, "incompatible"
        )

        aligned = check_versions("6.4.2", "6.4.2", "6.4.2")
        self.assertTrue(aligned["qt6-development-modules"].ready)
        self.assertTrue(aligned["qt6-sdk-version-alignment"].ready)

    def test_shell_requires_native_build_dependencies_without_claiming_runtime(self):
        calls = []

        def probe(argv, _env):
            calls.append(argv)
            if argv == ["pkg-config", "--exists", "xkbcommon >= 1.6"]:
                return None
            if argv[:2] == ["pkg-config", "--exists"]:
                return ""
            return None

        with (
            patch.object(doctor, "probe", side_effect=probe),
            patch.object(doctor, "probe_status", return_value=False),
            patch.object(doctor.shutil, "which", return_value=None),
        ):
            checks = {check.name: check for check in doctor.inventory({"shell"})}
        self.assertTrue(checks["native-module-wayland-protocols"].ready)
        self.assertFalse(checks["native-module-xkbcommon"].ready)
        self.assertFalse(checks["wayland-scanner"].ready)
        self.assertIn(["pkg-config", "--exists", "wayland-protocols >= 1.34"], calls)
        self.assertFalse(any("install" in argv for argv in calls))

    def test_editor_profile_requires_sdk_runtime_imports_and_working_qmlls(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bins = root / "bin"
            qml = root / "qml"
            bins.mkdir()
            server = bins / "qmlls"
            server.write_text("fixture", encoding="utf-8")
            for module in ("QtQuick", "QtQuick.Controls", "QtQuick.Layouts"):
                imported = qml.joinpath(*module.split("."))
                imported.mkdir(parents=True)
                (imported / "qmldir").write_text(f"module {module}\n", encoding="utf-8")
            query = f"QT_INSTALL_BINS:{bins}\nQT_INSTALL_QML:{qml}\nQT_VERSION:6.4.2"

            def fake_probe(argv, _env):
                if argv[-1] == "--query":
                    return query
                if argv[0] == str(server):
                    return "--build-dir --ignore-settings"
                return None

            def fake_which(name, path=None):
                del path
                return str(root / name)

            with (
                patch.object(doctor, "probe", side_effect=fake_probe),
                patch.object(doctor, "probe_status", return_value=False),
                patch.object(doctor.shutil, "which", side_effect=fake_which),
            ):
                checks = doctor.inventory({"core", "editor"})
            status = {check.name: check.ready for check in checks}
            self.assertTrue(status["qt6-qml-runtime-imports"])
            self.assertTrue(status["sdk-qmlls-runtime"])

    def test_guidance_changes_trigger_both_pr_and_main_environment_checks(self) -> None:
        workflow = (ROOT / ".github/workflows/codex-environment.yml").read_text()
        guidance = (
            "AGENTS.md",
            "**/AGENTS.md",
            "CONTRIBUTING.md",
            "docs/codex-development.md",
            "docs/development-infrastructure.md",
            "ruff.toml",
            "tools/python/ruff-requirements.lock",
            "tests/tooling/test_editor_tooling.py",
        )
        for path in guidance:
            self.assertEqual(workflow.count(f'      - "{path}"'), 2, path)
        self.assertIn("  pull_request:\n    paths:", workflow)
        self.assertIn("  push:\n    branches: [main]\n    paths:", workflow)

    def test_version_comparison_rejects_substrings(self) -> None:
        self.assertTrue(doctor.exact_version("actionlint v1.7.12", "1.7.12"))
        self.assertFalse(doctor.exact_version("actionlint v1.7.120", "1.7.12"))
        self.assertFalse(doctor.exact_version(None, "1.7.12"))

    def test_doctor_cli_reports_missing_profiles_without_qualification_claim(
        self,
    ) -> None:
        completed = subprocess.run(
            [sys.executable, str(ROOT / "tools/codex/doctor.py"), "--all", "--json"],
            capture_output=True,
            text=True,
            check=False,
            timeout=180,
        )
        self.assertIn(completed.returncode, (0, 1), completed.stderr)
        report = json.loads(completed.stdout)
        self.assertFalse(report["qualification_evidence"])
        self.assertEqual(set(report["profiles"]), set(doctor.PROFILES))
        self.assertEqual(
            report["ready"], all(check["ready"] for check in report["checks"])
        )

    def test_unknown_profile_is_rejected(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                str(ROOT / "tools/codex/doctor.py"),
                "--profile",
                "physical",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 2)

    def test_probe_is_bounded_and_hides_tool_errors(self) -> None:
        env = os.environ.copy()
        self.assertEqual(
            doctor.probe([sys.executable, "-c", "print('1.2.3')"], env), "1.2.3"
        )
        self.assertIsNone(
            doctor.probe(
                [
                    sys.executable,
                    "-c",
                    "import sys; print('secret'); sys.stderr.write('secret'); sys.exit(1)",
                ],
                env,
            )
        )
        with patch.object(doctor.subprocess, "Popen", side_effect=OSError):
            self.assertIsNone(doctor.probe(["not-found"], env))

    def test_successful_probe_terminates_descendants_with_redirected_stdio(
        self,
    ) -> None:
        # The outer probe's process group also owns this grandchild, which
        # deliberately redirects its own stdio so the parent's EOF/success
        # path completes before the grandchild would normally exit.
        child_script = "import time; time.sleep(60)"
        parent_script = (
            "import subprocess,sys; "
            "child = subprocess.Popen([sys.executable, '-c', "
            + repr(child_script)
            + "], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, "
            "stderr=subprocess.DEVNULL); print(child.pid, flush=True)"
        )
        output = doctor.probe([sys.executable, "-c", parent_script], os.environ.copy())
        self.assertIsNotNone(output)
        assert output is not None
        child_pid = int(output)
        try:
            proc = Path(f"/proc/{child_pid}/stat")
            for _ in range(40):
                if not proc.exists():
                    break
                try:
                    state = proc.read_text().rsplit(")", 1)[1].strip().split()[0]
                except FileNotFoundError:
                    break
                if state in {"Z", "X", "x"}:
                    break
                time.sleep(0.05)
            else:
                self.fail("successful probe left a runnable grandchild")
        finally:
            # Clean up even when the assertion fails.
            try:
                os.kill(child_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    def test_probe_rejects_excess_stdout_without_buffering_it(self) -> None:
        env = os.environ.copy()
        self.assertIsNone(
            doctor.probe(
                [
                    sys.executable,
                    "-c",
                    "import sys; sys.stdout.write('x' * 100000); sys.stdout.flush()",
                ],
                env,
            )
        )
        # Error output is discarded; it cannot consume the probe's memory cap.
        self.assertEqual(
            doctor.probe(
                [
                    sys.executable,
                    "-c",
                    "import sys; sys.stderr.write('x' * 100000); print('ok')",
                ],
                env,
            ),
            "ok",
        )

    def test_probe_times_out_and_terminates_nonresponding_process(self) -> None:
        with patch.object(doctor, "PROBE_TIMEOUT_SECONDS", 0.2):
            self.assertIsNone(
                doctor.probe(
                    [sys.executable, "-c", "import time; time.sleep(5)"],
                    os.environ.copy(),
                )
            )

    def test_status_probe_accepts_large_metadata_output_without_buffering(self) -> None:
        env = os.environ.copy()
        self.assertTrue(
            doctor.probe_status(
                [
                    sys.executable,
                    "-c",
                    "import sys; sys.stdout.write('x' * 1000000); sys.stderr.write('y' * 1000000)",
                ],
                env,
            )
        )
        self.assertFalse(
            doctor.probe_status(
                [
                    sys.executable,
                    "-c",
                    "import sys; sys.stdout.write('x' * 1000000); sys.exit(3)",
                ],
                env,
            )
        )

    def test_status_probe_timeout_and_launch_fail_closed(self) -> None:
        with patch.object(doctor, "PROBE_TIMEOUT_SECONDS", 0.2):
            self.assertFalse(
                doctor.probe_status(
                    [sys.executable, "-c", "import time; time.sleep(5)"],
                    os.environ.copy(),
                )
            )
        with patch.object(doctor.subprocess, "Popen", side_effect=OSError):
            self.assertFalse(doctor.probe_status(["not-found"], os.environ.copy()))

    def test_source_fingerprint_fails_when_git_state_is_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                [
                    "bash",
                    "-c",
                    'set -euo pipefail; source "$1"; codex_source_state',
                    "bash",
                    str(ROOT / "scripts/lib/codex_source_state.sh"),
                ],
                cwd=directory,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)

    def test_bindings_probe_uses_existing_lock_versions(self) -> None:
        calls = []
        with (
            patch.object(
                doctor, "probe", side_effect=lambda argv, env: calls.append(argv)
            ),
            patch.object(doctor.shutil, "which", return_value=None),
        ):
            doctor.inventory({"core", "bindings"})
        binding = next(
            argv
            for argv in calls
            if argv[0].endswith("linura-tools/python/bin/python3")
        )
        for line in (
            (ROOT / "bindings/python/build-requirements.lock").read_text().splitlines()
        ):
            if "==" in line and not line.startswith("#"):
                name, version = line.split()[0].split("==")
                self.assertIn(f"({name!r}, {version!r})", binding[2])
        self.assertIn("assert installed == expected", binding[2])

    def test_bindings_probe_rejects_duplicate_normalized_distributions(self) -> None:
        from types import SimpleNamespace

        probes = []
        with (
            patch.object(
                doctor, "probe", side_effect=lambda argv, _env: probes.append(argv)
            ),
            patch.object(doctor.shutil, "which", return_value=None),
        ):
            doctor.inventory({"core", "bindings"})
        command = next(
            argv[2]
            for argv in probes
            if argv[0].endswith("linura-tools/python/bin/python3")
        )
        lock = (ROOT / "bindings/python/build-requirements.lock").read_text()
        pinned = doctor.re.findall(r"(?m)^([a-zA-Z0-9-]+)==([^\s]+)", lock)
        installed = [
            SimpleNamespace(metadata={"Name": name}, version=version)
            for name, version in pinned
        ]

        with patch("importlib.metadata.distributions", return_value=installed):
            exec(command, {})  # Exactly the hash-locked distribution multiset.
        duplicate = SimpleNamespace(
            metadata={"Name": pinned[0][0].replace("-", "_").upper()},
            version=pinned[0][1],
        )
        with patch(
            "importlib.metadata.distributions", return_value=[*installed, duplicate]
        ):
            with self.assertRaises(AssertionError):
                exec(command, {})  # A second .dist-info with the same pin.
        with patch("importlib.metadata.distributions", return_value=installed[:-1]):
            with self.assertRaises(AssertionError):
                exec(command, {})  # Missing installed metadata fails closed.


class CodexPreflightExecutionTests(unittest.TestCase):
    def _run(
        self,
        *,
        dirty=False,
        staged=False,
        mutate=False,
        mutate_index=False,
        missing_component=False,
        full=False,
        validator_fails=False,
        invalid_ruff_lock=False,
    ):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo with spaces"
            root.mkdir()
            for path in (
                "scripts/preflight_codex_environment.sh",
                "scripts/lib/codex_source_state.sh",
                "tools/codex/versions.env",
                "tools/check_toolchain_env.py",
                "tools/python/ruff-requirements.lock",
                "rust-toolchain.toml",
            ):
                target = root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / path, target)
            watched = root / "watched"
            watched.write_text("baseline\n")

            def git(*args):
                return subprocess.run(
                    ["git", "-C", str(root), *args],
                    check=True,
                    capture_output=True,
                )

            git("init")
            git("add", ".")
            git(
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "commit",
                "-m",
                "fixture",
            )
            if dirty or staged:
                watched.write_text("existing edit\n")
            if staged:
                git("add", "watched")
            home = Path(directory) / "home"
            cargo = Path(directory) / "custom cargo"
            fake_bin = cargo / "bin"
            fake_bin.mkdir(parents=True)
            pins = doctor.versions()
            toolchain = f"{pins['RUST_VERSION']}-x86_64-unknown-linux-gnu"

            def executable(path, text):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("#!/usr/bin/env bash\nset -euo pipefail\n" + text)
                path.chmod(0o755)

            executable(
                fake_bin / "python3",
                f"""case "${{1:-}}" in
  -c) echo '{pins["PYTHON_MAJOR_MINOR"]}' ;;
  --version) echo 'Python {pins["PYTHON_MAJOR_MINOR"]}.0' ;;
  *) echo '{pins["RUST_VERSION"]}' ;;
esac
""",
            )
            python_shim = home / ".local/linura-tools/python312/bin/python3"
            python_shim.parent.mkdir(parents=True, mode=0o700)
            python_shim.symlink_to(fake_bin / "python3")
            # Model the isolated, hash-locked tool and published PATH entry.
            ruff_home = home / ".local/linura-tools/ruff"
            ruff_binary = ruff_home / "bin/ruff"
            executable(ruff_binary, f"echo 'ruff {pins['RUFF_VERSION']}'\n")
            ruff_link = home / ".local/bin/ruff"
            ruff_link.parent.mkdir(parents=True, exist_ok=True)
            ruff_link.symlink_to(ruff_binary)
            lock_digest = hashlib.sha256(
                (root / "tools/python/ruff-requirements.lock").read_bytes()
            ).hexdigest()
            (ruff_home / ".linura-ruff-lock-sha256").write_text(
                ("0" * 64 if invalid_ruff_lock else lock_digest) + "\n",
                encoding="utf-8",
            )
            executable(
                fake_bin / "cargo-audit",
                f"echo 'cargo-audit {pins['CARGO_AUDIT_VERSION']}'\n",
            )
            executable(fake_bin / "rustc", f"echo 'rustc {pins['RUST_VERSION']}'\n")
            executable(fake_bin / "cargo", "exit 0\n")
            executable(
                fake_bin / "rustup",
                f"""case "$*" in
  --version) echo 'rustup {pins["RUSTUP_VERSION"]}' ;;
  'toolchain list') echo '{toolchain} (default)' ;;
  'show active-toolchain') echo '{toolchain} (overridden)' ;;
  'which --toolchain {toolchain} rustc') echo "$CARGO_HOME/bin/rustc" ;;
  'which --toolchain {toolchain} cargo') echo "$CARGO_HOME/bin/cargo" ;;
  'run {toolchain} cargo fmt --version') exit "${{MISSING_COMPONENT:-0}}" ;;
  'run {toolchain} cargo clippy --version') exit 0 ;;
  *) exit 90 ;;
esac
""",
            )
            executable(
                home
                / ".local/linura-tools/actionlint"
                / pins["ACTIONLINT_VERSION"]
                / "actionlint",
                f"""if [[ "$*" == '-version' ]]; then
  echo '{pins["ACTIONLINT_VERSION"]}'
elif [[ "${{MUTATE:-0}}" == 1 ]]; then
  echo 'unexpected edit' >> watched
  if [[ "${{MUTATE_INDEX:-0}}" == 1 ]]; then git add watched; fi
fi
if [[ "$*" == '-color' && "${{VALIDATOR_FAIL:-0}}" == 1 ]]; then exit 67; fi
""",
            )
            env = os.environ.copy()
            env.pop("RUSTUP_TOOLCHAIN", None)
            env.update(
                HOME=str(home),
                CARGO_HOME=str(cargo),
                MUTATE="1" if mutate else "0",
                MUTATE_INDEX="1" if mutate_index else "0",
                MISSING_COMPONENT="1" if missing_component else "0",
                VALIDATOR_FAIL="1" if validator_fails else "0",
                PATH="/usr/bin:/bin",
            )
            nested = root / "nested"
            nested.mkdir()
            result = subprocess.run(
                [
                    "bash",
                    str(root / "scripts/preflight_codex_environment.sh"),
                    *(["--full"] if full else []),
                ],
                cwd=nested,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            return result

    def test_preflight_denies_stale_ruff_lock_identity(self):
        result = self._run(invalid_ruff_lock=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Ruff lock identity mismatch", result.stderr)

    def test_preflight_accepts_existing_unstaged_task_edits(self):
        result = self._run(dirty=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_preflight_accepts_staged_task_edits_and_nested_cwd(self):
        result = self._run(staged=True, full=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_preflight_rejects_validator_source_mutation(self):
        result = self._run(dirty=True, mutate=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("changed tracked source or index state", result.stderr)

    def test_preflight_rejects_missing_quality_component(self):
        result = self._run(missing_component=True)
        self.assertNotEqual(result.returncode, 0)

    def test_preflight_rejects_validator_index_mutation(self):
        result = self._run(staged=True, mutate=True, mutate_index=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("changed tracked source or index state", result.stderr)

    def test_failed_validator_does_not_hide_tracked_mutation(self):
        result = self._run(dirty=True, mutate=True, validator_fails=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("changed tracked source or index state", result.stderr)

    def test_failed_validator_preserves_original_status_without_mutation(self):
        result = self._run(validator_fails=True)
        self.assertEqual(result.returncode, 67, result.stderr)
        self.assertNotIn("changed tracked source or index state", result.stderr)

    def test_wrapper_denies_missing_prepared_python_without_running_command(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                ["bash", str(ROOT / "scripts/run_codex.sh"), "python3", "--version"],
                env=dict(os.environ, HOME=directory),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Python 3.12 selection is missing", result.stderr)

    def test_wrapper_preserves_literal_arguments_and_custom_cargo_home(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            cargo = home / "custom cargo"
            (cargo / "bin").mkdir(parents=True)
            command = cargo / "bin/inspect-args"
            command.write_text(
                '#!/usr/bin/env python3\nimport json, os, sys\nprint(json.dumps([os.getcwd(), os.environ["CARGO_HOME"], os.environ["RUSTUP_AUTO_INSTALL"], sys.argv[1:]]))\n'
            )
            command.chmod(0o755)
            python_shim = home / ".local/linura-tools/python312/bin/python3"
            python_shim.parent.mkdir(parents=True, mode=0o700)
            python_shim.symlink_to(sys.executable)
            literal = "$(touch should-not-exist) ; space"
            env = dict(
                os.environ,
                HOME=str(home),
                CARGO_HOME=str(cargo),
                RUSTUP_AUTO_INSTALL="1",
            )
            result = subprocess.run(
                ["bash", str(ROOT / "scripts/run_codex.sh"), "inspect-args", literal],
                cwd=directory,
                env=env,
                capture_output=True,
                text=True,
                check=True,
            )
            self.assertEqual(
                json.loads(result.stdout), [str(ROOT), str(cargo), "0", [literal]]
            )
            self.assertFalse((ROOT / "should-not-exist").exists())


if __name__ == "__main__":
    unittest.main()
