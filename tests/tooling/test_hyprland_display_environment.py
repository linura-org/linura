from __future__ import annotations

import copy
import json
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools import hyprland_display_environment as environment

ROOT = Path(__file__).resolve().parents[2]


class HyprlandDisplayEnvironmentTests(unittest.TestCase):
    def test_sdk_has_gles3_and_exact_compositor_build_dependencies(self) -> None:
        data = environment.load_contract(environment.CONTRACT)
        self.assertTrue(environment.REQUIRED <= {p["name"] for p in data["package"]})
        self.assertTrue(
            {"libglvnd", "mesa", "hyprland-protocols", "hyprwayland-scanner", "libei"}
            <= set(data["runtime_packages"])
        )
        self.assertTrue(data["archived_package"]["signature_required"])
        self.assertFalse(data["cache_policy"]["qualification_evidence"])
        self.assertFalse(data["cache_policy"]["linura_build_outputs"])

    def test_missing_mismatched_and_injected_sdk_records_fail_closed(self) -> None:
        original = environment.CONTRACT.read_text()
        mutations = [
            ('name = "libglvnd"', 'name = "missing-gles"'),
            ("signature_required = true", "signature_required = false"),
            (
                "fetchcontent_fully_disconnected = true",
                "fetchcontent_fully_disconnected = false",
            ),
            ('version = "0.56.2-3"', 'version = "0.56.3-1"'),
            ('name = "gcc"', 'name = "gcc;injected"'),
            ('version = "7.2.0-1"', 'version = "8.4.0-1"'),
            (
                "https://archive.archlinux.org/packages/g/glaze/",
                "http://untrusted.invalid/",
            ),
            ('build_type = "Debug"', 'build_type = "Release"'),
        ]
        with tempfile.TemporaryDirectory() as directory:
            contract = Path(directory) / "build.toml"
            for old, new in mutations:
                with self.subTest(new=new):
                    self.assertIn(old, original)
                    contract.write_text(original.replace(old, new, 1))
                    with self.assertRaises(ValueError):
                        environment.load_contract(contract)
            contract.write_text(
                original
                + '\n[[package]]\nname = "gcc"\nversion = "1"\nsha256 = "'
                + "1" * 64
                + '"\n'
            )
            with self.assertRaisesRegex(ValueError, "duplicate"):
                environment.load_contract(contract)

    def test_generated_guest_scripts_keep_signature_hash_and_build_checks(self) -> None:
        data = environment.load_contract(environment.CONTRACT)
        for script in (
            environment.repository_script(data),
            environment.dependency_script(data),
        ):
            result = subprocess.run(
                ["bash", "-n"],
                input=script,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn("SigLevel", script)
            self.assertNotIn("--skippgpcheck", script)
        dependencies = environment.dependency_script(data)
        for check in (
            "pacman-key --verify",
            "sha256sum --check --strict",
            "/usr/include/GLES3/gl3.h",
            "find_package(OpenGL REQUIRED COMPONENTS GLES3)",
            "find_package(glaze 7...<8 REQUIRED)",
            "FETCHCONTENT_FULLY_DISCONNECTED=ON",
        ):
            self.assertIn(check, dependencies)
        repositories = environment.repository_script(data)
        for digest in data["repository_sha256"].values():
            self.assertIn(digest, repositories)
        verification = shlex.split(repositories.split("python3 -c ", 1)[1])[0]
        self.assertIn("entry.get('SHA256SUM')", verification)
        compile(verification, "<guest repository verification>", "exec")

    def test_helper_dispatches_only_to_disposable_guest_with_deadlines(self) -> None:
        with (
            patch.object(
                sys,
                "argv",
                [
                    "environment",
                    "--ssh-key",
                    "/private/guest-key",
                    "--phase",
                    "dependencies",
                ],
            ),
            patch.object(environment.subprocess, "run") as run,
        ):
            environment.main()
        call = run.call_args
        self.assertIsNotNone(call)
        assert call is not None
        command = call.args[0]
        self.assertEqual(command[0], "ssh")
        self.assertIn("linura@127.0.0.1", command)
        self.assertIn("2223", command)
        self.assertEqual(command[-2:], ["bash", "-s"])
        self.assertEqual(call.kwargs["timeout"], 320)
        self.assertTrue(call.kwargs["check"])

    def test_prepared_image_verifier_rejects_sdk_version_or_helper_drift(self) -> None:
        import hashlib

        data = environment.load_contract(environment.CONTRACT)
        builder = ROOT / data["builder"]

        def digest(path: Path) -> str:
            return hashlib.sha256(path.read_bytes()).hexdigest()

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image = root / "prepared.qcow2"
            image.write_bytes(b"simulated image; not qualification evidence")
            manifest = {
                "schema_version": 1,
                "id": data["id"],
                "claim": "non-authoritative-prepared-substrate",
                "contract_sha256": digest(environment.CONTRACT),
                "builder_sha256": digest(builder),
                "build_dependency_verifier_sha256": digest(
                    ROOT / data["build_dependency_verifier"]
                ),
                "prepared_image_sha256": digest(image),
                "base_image": {
                    "url": data["base_image_url"],
                    "sha256": data["base_image_sha256"],
                },
                "arch_archive": {
                    "snapshot": data["arch_archive_snapshot"],
                    "url": data["arch_archive_url"],
                },
                "runtime_packages": data["runtime_packages"],
                "package_versions": [
                    r["name"] + " " + r["version"]
                    for r in [*data["package"], data["archived_package"]]
                ],
                "sanitized": True,
                "contains_linura_source": False,
                "contains_linura_build_outputs": False,
                "qualification_evidence": False,
                "release_support_promotion": False,
            }
            file = root / "manifest.json"
            for field in (
                "valid",
                "package_versions",
                "build_dependency_verifier_sha256",
                "base_image",
            ):
                changed = copy.deepcopy(manifest)
                if field == "package_versions":
                    changed[field] = ["libglvnd 0"]
                elif field == "build_dependency_verifier_sha256":
                    changed[field] = "0" * 64
                elif field == "base_image":
                    changed[field]["sha256"] = "0" * 64
                file.write_text(json.dumps(changed))
                result = subprocess.run(
                    [
                        sys.executable,
                        str(ROOT / data["verifier"]),
                        str(environment.CONTRACT),
                        str(builder),
                        str(image),
                        str(file),
                    ],
                    cwd=ROOT,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                if field == "valid":
                    self.assertEqual(result.returncode, 0, result.stderr)
                else:
                    self.assertNotEqual(result.returncode, 0, field)


if __name__ == "__main__":
    unittest.main()
