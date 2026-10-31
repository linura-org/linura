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
from unittest.mock import patch

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
                vm = unittest.mock.Mock()
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
                vm = unittest.mock.Mock()
                vm.wait.return_value = vm_exit
                with self.assertRaisesRegex(RuntimeError, "failed to power off"):
                    build.poweroff_guest(["ssh"], vm, io.BytesIO())
        with patch.object(
            build.subprocess,
            "run",
            return_value=subprocess.CompletedProcess([], 1),
        ):
            vm = unittest.mock.Mock()
            with self.assertRaises(subprocess.CalledProcessError):
                build.poweroff_guest(["ssh"], vm, io.BytesIO())
            vm.wait.assert_not_called()
        with patch.object(
            build.subprocess,
            "run",
            return_value=subprocess.CompletedProcess([], 255),
        ):
            vm = unittest.mock.Mock()
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
                commands[0][2:6],
                ["head", "-c", str(build.candidate.FILES["Hyprland"] + 1), "--"],
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
