from __future__ import annotations

import argparse
from pathlib import Path
import hashlib
import io
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from tools import hyprland_display_build as build


class HyprlandDisplayBuildTests(unittest.TestCase):
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
