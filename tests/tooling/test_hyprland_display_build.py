from __future__ import annotations

import argparse
from pathlib import Path
import hashlib
import io
import os
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch

from tools import hyprland_display_build as build


class HyprlandDisplayBuildTests(unittest.TestCase):
    def test_poweroff_reconciles_ssh_disconnect_with_clean_vm_exit(self) -> None:
        for ssh_code in (0, 255):
            with (
                self.subTest(ssh_code=ssh_code),
                patch.object(
                    build.subprocess,
                    "run",
                    return_value=subprocess.CompletedProcess([], ssh_code),
                ) as shutdown,
            ):
                vm = Mock()
                vm.wait.return_value = 0
                output = io.BytesIO()
                build.poweroff_guest(["ssh", "qualified-guest"], vm, output)
                vm.wait.assert_called_once_with(timeout=120)
                self.assertEqual(
                    shutdown.call_args.args[0],
                    ["ssh", "qualified-guest", "sudo", "-n", "systemctl", "poweroff"],
                )
                self.assertEqual(shutdown.call_args.kwargs["timeout"], 20)
                self.assertFalse(shutdown.call_args.kwargs["check"])

    def test_poweroff_never_accepts_disconnection_without_vm_completion(self) -> None:
        for ssh_code, vm_exit in ((255, 1), (0, -15), (0, 3)):
            with (
                self.subTest(ssh_code=ssh_code, vm_exit=vm_exit),
                patch.object(
                    build.subprocess,
                    "run",
                    return_value=subprocess.CompletedProcess([], ssh_code),
                ),
            ):
                vm = Mock()
                vm.wait.return_value = vm_exit
                with self.assertRaisesRegex(RuntimeError, "failed to power off"):
                    build.poweroff_guest(["ssh"], vm, io.BytesIO())
        with patch.object(
            build.subprocess,
            "run",
            return_value=subprocess.CompletedProcess([], 1),
        ):
            vm = Mock()
            with self.assertRaises(subprocess.CalledProcessError):
                build.poweroff_guest(["ssh"], vm, io.BytesIO())
            vm.wait.assert_not_called()
        with patch.object(
            build.subprocess,
            "run",
            return_value=subprocess.CompletedProcess([], 255),
        ):
            vm = Mock()
            vm.wait.side_effect = subprocess.TimeoutExpired("qemu", 120)
            with self.assertRaises(subprocess.TimeoutExpired):
                build.poweroff_guest(["ssh"], vm, io.BytesIO())

    def test_exact_ci_subruns_validate_existing_provider_root_and_reserve_fresh_roles(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = {
                "generated": {
                    "temporary": str(root / "temporary"),
                    "vm-disposable": str(root / "vm"),
                    "cmake-build": str(root / "cmake"),
                }
            }
            replies = [
                subprocess.CompletedProcess([], 0, "a" * 40 + "\n"),
                subprocess.CompletedProcess([], 0, b""),
            ]
            with (
                patch.dict(
                    os.environ, {"LINURA_STORAGE_CLASS": "github-hosted-ephemeral"}
                ),
                patch.object(build, "run", side_effect=replies),
                patch.object(
                    build.storage,
                    "arguments",
                    return_value=argparse.Namespace(storage_root=root),
                ),
                patch.object(build.storage, "run_layout", return_value=paths) as guard,
                patch.object(build.storage, "private_tree") as reserve,
                patch.object(build.storage, "prepare") as prepare,
            ):
                observed, sha, dirty = build.reserve_run("fresh-sdk-run", False)
                self.assertEqual(observed, paths)
                self.assertEqual(sha, "a" * 40)
                self.assertFalse(dirty)
                guard.assert_called_once_with(
                    build.ROOT, build.ENVIRONMENT, "fresh-sdk-run"
                )
                self.assertEqual(reserve.call_count, 3)
                self.assertTrue(
                    all(
                        call.kwargs == {"exclusive": True}
                        for call in reserve.call_args_list
                    )
                )
                prepare.assert_not_called()

    def test_existing_provider_root_cannot_bypass_guard_or_reuse_an_occupied_run(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = {
                "generated": {
                    "temporary": str(root / "temporary"),
                    "vm-disposable": str(root / "vm"),
                    "cmake-build": str(root / "cmake"),
                }
            }
            for failure in ("root", "occupied"):
                replies = [
                    subprocess.CompletedProcess([], 0, "a" * 40 + "\n"),
                    subprocess.CompletedProcess([], 0, b""),
                ]
                with (
                    self.subTest(failure=failure),
                    patch.dict(
                        os.environ, {"LINURA_STORAGE_CLASS": "github-hosted-ephemeral"}
                    ),
                    patch.object(build, "run", side_effect=replies),
                    patch.object(
                        build.storage,
                        "arguments",
                        return_value=argparse.Namespace(storage_root=root),
                    ),
                    patch.object(
                        build.storage,
                        "run_layout",
                        side_effect=ValueError("root rejected")
                        if failure == "root"
                        else None,
                        return_value=paths,
                    ),
                    patch.object(
                        build.storage,
                        "private_tree",
                        side_effect=FileExistsError("occupied"),
                    ) as reserve,
                    patch.object(build.storage, "prepare") as prepare,
                ):
                    with self.assertRaises((ValueError, FileExistsError)):
                        build.reserve_run("fresh-sdk-run", False)
                    self.assertEqual(reserve.call_count, 0 if failure == "root" else 1)
                    prepare.assert_not_called()

    def sdk_archive(self, root: Path, name: str, target: str | None = None) -> Path:
        archive = root / "sdk.tar"
        with tarfile.open(archive, "w") as stream:
            member = tarfile.TarInfo(name)
            if target is not None:
                member.type = tarfile.SYMTYPE
                member.linkname = target
                stream.addfile(member)
            else:
                member.size = 7
                stream.addfile(member, io.BytesIO(b"verified"))
        return archive

    def test_sdk_staging_rejects_hash_and_path_escape_before_extraction(self) -> None:
        for name, target in (
            ("../escape", None),
            ("usr/bin/compiler", "../../../../escape"),
            ("/usr/bin/compiler", None),
        ):
            with (
                self.subTest(name=name, target=target),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                archive = self.sdk_archive(root, name, target)
                digest = hashlib.sha256(archive.read_bytes()).hexdigest()
                with self.assertRaises(ValueError):
                    build.extract_sdk(archive, root / "sdk", digest)
                self.assertFalse((root / "sdk").exists())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = self.sdk_archive(root, "usr/bin/compiler")
            with self.assertRaisesRegex(ValueError, "checksum"):
                build.extract_sdk(archive, root / "sdk", "0" * 64)
            self.assertFalse((root / "sdk").exists())

    def test_sdk_absolute_package_links_remain_inside_staging_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = self.sdk_archive(
                root, "usr/bin/compiler", "/usr/bin/real-compiler"
            )
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            destination = root / "sdk"
            build.extract_sdk(archive, destination, digest)
            link = destination / "usr/bin/compiler"
            self.assertEqual(link.readlink(), Path("real-compiler"))
            self.assertTrue(link.resolve().is_relative_to(destination))

    def test_namespace_has_no_network_or_host_source_write_mount(self) -> None:
        command = build.namespace_command(
            Path("/private/sdk"), Path("/private/build"), Path("/private/doctor")
        )
        self.assertIn("--unshare-all", command)
        self.assertIn("--clearenv", command)
        self.assertIn("--die-with-parent", command)
        self.assertEqual(
            command[command.index("--ro-bind") + 1 : command.index("--ro-bind") + 3],
            ["/private/sdk", "/"],
        )
        writable = [
            command[index + 1 : index + 3]
            for index, arg in enumerate(command)
            if arg == "--bind"
        ]
        self.assertEqual(
            writable,
            [["/private/build/tmp", "/tmp"], ["/private/build", "/home/linura/s21"]],
        )
        self.assertNotIn(str(build.ROOT), command)
        self.assertNotIn("--share-net", command)

    def test_build_recipe_requires_native_dependencies_and_runs_component_checks(
        self,
    ) -> None:
        script = build.build_script(1)
        result = subprocess.run(
            ["bash", "-n"], input=script, text=True, capture_output=True, check=False
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("FETCHCONTENT_FULLY_DISCONNECTED=ON", script)
        self.assertIn("FETCHCONTENT_UPDATES_DISCONNECTED=ON", script)
        self.assertIn("-DCMAKE_SKIP_RPATH=ON", script)
        self.assertEqual(
            script.count(
                "-DLINURA_DISPLAY_RECOVERY_FIXTURE=/home/linura/s21/original-baseline.txt"
            ),
            2,
        )
        self.assertEqual(
            script.count(
                "-DLINURA_DISPLAY_FINALIZATION_FIXTURE=/home/linura/s21/original-finalization.txt"
            ),
            2,
        )
        self.assertIn("ctest --test-dir mechanism-build --output-on-failure", script)
        self.assertIn("ctest --test-dir compositor-build --output-on-failure", script)
        self.assertIn("cmake --build compositor-build --parallel 1", script)
        self.assertIn("./compositor-build/Hyprland --version", script)
        self.assertNotIn("sudo", script)
        self.assertNotIn("pacman", script)
        for jobs in (0, -1, 5, 999):
            with self.assertRaises(ValueError):
                build.build_script(jobs)

    def test_exact_source_change_is_a_build_failure(self) -> None:
        sha = "1" * 40
        for observed, dirty, valid in (
            (sha, b"", True),
            ("2" * 40, b"", False),
            (sha, b" M native.cpp", False),
        ):
            responses = [
                subprocess.CompletedProcess([], 0, observed + "\n"),
                subprocess.CompletedProcess([], 0, dirty),
            ]
            with (
                self.subTest(valid=valid, observed=observed, dirty=dirty),
                patch.object(build, "run", side_effect=responses),
            ):
                if valid:
                    build.require_source_unchanged(sha)
                else:
                    with self.assertRaisesRegex(ValueError, "source changed"):
                        build.require_source_unchanged(sha)

    def test_candidate_export_reads_only_fixed_bounded_public_build_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            commands = []

            def exported(command, **kwargs):
                commands.append(command)
                kwargs["stdout"].write(b"bounded build fixture")
                return subprocess.CompletedProcess(command, 0)

            record = {"source_sha": "1" * 40}
            with (
                patch.object(build, "run", side_effect=exported),
                patch.object(build.candidate, "retain") as retain,
            ):
                build.export_candidate(
                    ["ssh", "fixed-guest"],
                    root,
                    root / "prepared.json",
                    record,
                    io.BytesIO(),
                )
            self.assertEqual(len(commands), 2)
            self.assertEqual(
                commands[0][4:8],
                ["head", "-c", str(build.candidate.FILES["Hyprland"] + 1), "--"],
            )
            self.assertEqual(
                commands[0][:4], ["ssh", "-o", "ConnectTimeout=30", "fixed-guest"]
            )
            self.assertEqual(
                commands[0][-1], "/home/linura/s21/compositor-build/Hyprland"
            )
            self.assertEqual(
                commands[1][-1],
                "/home/linura/s21/compositor-build/linura-display/linura-display-integration-build.h",
            )
            retained = retain.call_args.args
            self.assertEqual(retained[1], root / "candidate")
            self.assertEqual(set(retained[3]), set(build.candidate.FILES))
            self.assertEqual(
                retained[3]["staged-source.json"],
                root / "upstream/linura-display-source.json",
            )

    def test_candidate_export_reconnect_discards_partial_stream_without_rebuilding(
        self,
    ):
        output = io.BytesIO()
        commands = []

        def exported(command, **kwargs):
            commands.append(command)
            self.assertEqual(kwargs["timeout"], 180)
            self.assertEqual(kwargs["stdout"].getvalue(), b"")
            if len(commands) == 1:
                kwargs["stdout"].write(b"unqualified partial stream")
                raise subprocess.CalledProcessError(255, command)
            kwargs["stdout"].write(b"complete public file")
            return subprocess.CompletedProcess(command, 0)

        with (
            patch.object(build, "run", side_effect=exported),
            patch.object(build.time, "monotonic", return_value=100),
        ):
            build.export_candidate_file(
                ["ssh", "-o", "ConnectTimeout=3", "fixed-guest"],
                "/home/linura/s21/compositor-build/Hyprland",
                512,
                output,
                io.BytesIO(),
            )
        self.assertEqual(len(commands), 2)
        self.assertEqual(commands[0], commands[1])
        self.assertEqual(
            commands[0][:5],
            ["ssh", "-o", "ConnectTimeout=30", "-o", "ConnectTimeout=3"],
        )
        self.assertEqual(output.getvalue(), b"complete public file")

    def test_candidate_export_never_retries_remote_failure_or_exceeds_attempt_budget(
        self,
    ):
        for code, attempts in ((1, 1), (2, 1), (255, 3)):
            with (
                self.subTest(code=code),
                patch.object(
                    build, "run", side_effect=subprocess.CalledProcessError(code, [])
                ) as read,
                patch.object(build.time, "monotonic", return_value=100),
                self.assertRaises(subprocess.CalledProcessError),
            ):
                try:
                    build.export_candidate_file(
                        ["ssh", "fixed-guest"],
                        "/fixed",
                        512,
                        io.BytesIO(),
                        io.BytesIO(),
                    )
                finally:
                    self.assertEqual(read.call_count, attempts)

    def test_candidate_export_reconnect_cannot_renew_original_wall_budget(self):
        with (
            patch.object(
                build, "run", side_effect=subprocess.CalledProcessError(255, [])
            ) as read,
            patch.object(build.time, "monotonic", side_effect=[100, 100, 280]),
            self.assertRaisesRegex(TimeoutError, "original read budget"),
        ):
            build.export_candidate_file(
                ["ssh", "fixed-guest"], "/fixed", 512, io.BytesIO(), io.BytesIO()
            )
        self.assertEqual(read.call_count, 1)

    def test_candidate_export_timeout_remains_failure_without_candidate_admission(self):
        with tempfile.TemporaryDirectory() as directory:
            with (
                patch.object(
                    build, "run", side_effect=subprocess.TimeoutExpired([], 180)
                ) as read,
                patch.object(build.time, "monotonic", return_value=100),
                patch.object(build.candidate, "retain") as retain,
                self.assertRaises(subprocess.TimeoutExpired),
            ):
                build.export_candidate(
                    ["ssh", "fixed-guest"],
                    Path(directory),
                    Path(directory) / "prepared.json",
                    {"source_sha": "1" * 40},
                    io.BytesIO(),
                )
            self.assertEqual(read.call_count, 3)
            retain.assert_not_called()

    def test_shared_original_baseline_is_packaged_without_repository_relative_paths(
        self,
    ) -> None:
        fixture_root = build.ROOT / "crates/linura-core/src/display_recovery/fixtures"
        canonical = {
            name: (fixture_root / name).read_bytes()
            for name in ("original-baseline.txt", "original-finalization.txt")
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            native = root / "apps/linura-hyprland-display"
            native.mkdir(parents=True)
            (native / "backend.cpp").write_text("native source")
            fixture_root = root / "crates/linura-core/src/display_recovery/fixtures"
            fixture_root.mkdir(parents=True)
            for name, content in canonical.items():
                (fixture_root / name).write_bytes(content)
            temporary = root / "outputs"
            (temporary / "upstream/hyprland-source").mkdir(parents=True)
            with patch.object(build, "ROOT", root), patch.object(build.source, "stage"):
                packed = build.package_inputs(
                    root / "verified-source.tar.gz", temporary
                )
            with tarfile.open(packed) as archive:
                for name, content in canonical.items():
                    with self.subTest(fixture=name):
                        member = archive.getmember(name)
                        self.assertTrue(member.isfile())
                        payload = archive.extractfile(member)
                        self.assertIsNotNone(payload)
                        assert payload is not None
                        self.assertEqual(payload.read(), content)
                self.assertTrue(
                    all(
                        not name.startswith("/") and ".." not in Path(name).parts
                        for name in archive.getnames()
                    )
                )

    def test_missing_substituted_or_oversized_original_fixture_refuses_packaging(
        self,
    ) -> None:
        for name, maximum in (
            ("original-baseline.txt", 12 * 1024),
            ("original-finalization.txt", 14 * 1024),
        ):
            for failure in ("missing", "symlink", "empty", "oversized", "directory"):
                with (
                    self.subTest(fixture=name, failure=failure),
                    tempfile.TemporaryDirectory() as directory,
                ):
                    root = Path(directory)
                    native = root / "apps/linura-hyprland-display"
                    native.mkdir(parents=True)
                    (native / "backend.cpp").write_text("native source")
                    fixture_root = (
                        root / "crates/linura-core/src/display_recovery/fixtures"
                    )
                    fixture_root.mkdir(parents=True)
                    other = (
                        "original-baseline.txt"
                        if name == "original-finalization.txt"
                        else "original-finalization.txt"
                    )
                    (fixture_root / other).write_bytes(b"bounded other fixture")
                    fixture = fixture_root / name
                    if failure == "symlink":
                        fixture.symlink_to(native / "backend.cpp")
                    elif failure == "directory":
                        fixture.mkdir()
                    elif failure != "missing":
                        fixture.write_bytes(
                            b"" if failure == "empty" else b"x" * (maximum + 1)
                        )
                    temporary = root / "outputs"
                    temporary.mkdir()
                    with (
                        patch.object(build, "ROOT", root),
                        patch.object(build.source, "stage"),
                    ):
                        with self.assertRaisesRegex(
                            ValueError, "canonical original display fixture"
                        ):
                            build.package_inputs(
                                root / "verified-source.tar.gz", temporary
                            )
                    self.assertFalse((temporary / "build-input.tar").exists())

    def test_native_symlink_is_never_copied_into_guest_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            native = root / "apps/linura-hyprland-display"
            native.mkdir(parents=True)
            outside = root / "outside"
            outside.write_text("must not enter build")
            (native / "backend.cpp").symlink_to(outside)
            temporary = root / "outputs"
            temporary.mkdir()
            with patch.object(build, "ROOT", root), patch.object(build.source, "stage"):
                with self.assertRaisesRegex(ValueError, "regular files"):
                    build.package_inputs(root / "verified-source.tar.gz", temporary)
            self.assertFalse((temporary / "build-input.tar").exists())

    def test_ci_rejects_development_or_unbounded_requests_before_preparation(
        self,
    ) -> None:
        for development, jobs, memory in (
            (True, 1, 4096),
            (False, 5, 4096),
            (False, 1, 99999),
        ):
            args = argparse.Namespace(
                diagnostics=Path("/checked/run"),
                development=development,
                jobs=jobs,
                memory_mib=memory,
            )
            with (
                self.subTest(development=development, jobs=jobs, memory=memory),
                patch.object(build, "prepare_environment") as prepare,
            ):
                with self.assertRaises(ValueError):
                    build.ci_build(args)
                prepare.assert_not_called()

    def test_ci_bad_source_digest_stops_before_sdk_preparation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            contract = root / build.source.PIN
            contract.parent.mkdir(parents=True)
            contract.write_text(
                'source_url="https://example.invalid/pinned-source"\nsource_sha256="'
                + "1" * 64
                + '"\n'
            )
            diagnostics = root / "diagnostics"
            diagnostics.mkdir()
            args = argparse.Namespace(
                diagnostics=diagnostics,
                development=False,
                jobs=1,
                memory_mib=4096,
                run="build",
                acceleration="kvm",
            )

            def commands(command, **kwargs):
                if command[0] == "git":
                    return subprocess.CompletedProcess(command, 0, "2" * 40 + "\n")
                (diagnostics / "hyprland-source.tar.gz").write_bytes(b"substituted")
                return subprocess.CompletedProcess(command, 0)

            with (
                patch.object(build, "ROOT", root),
                patch.object(
                    build.storage, "require_destination", return_value=diagnostics
                ),
                patch.object(build, "require_source_unchanged"),
                patch.object(build, "run", side_effect=commands),
                patch.object(build, "prepare_environment") as prepare,
            ):
                with self.assertRaisesRegex(ValueError, "source differs"):
                    build.ci_build(args)
                prepare.assert_not_called()


if __name__ == "__main__":
    unittest.main()
