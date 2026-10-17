from __future__ import annotations

import contextlib
import io
import os
from pathlib import Path
import sys
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tools import development_storage as storage  # noqa: E402
from tools import development_workspace as workspace  # noqa: E402

IDENTITY = "a" * 64
HEAD = "b" * 40


class StoragePreparationTests(unittest.TestCase):
    """Mocked topology exercises plumbing only, never native qualification."""

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.volume = self.root / "volume"
        self.volume.mkdir(mode=0o700)
        self.paths = workspace.layout(self.volume, IDENTITY, HEAD, "native", "run-1")
        self.environment = patch.dict(
            os.environ, {"LINURA_STORAGE_ROOT": str(self.volume)}, clear=False
        )
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def prepare(self) -> dict[str, str]:
        with (
            patch.object(storage, "run_layout", return_value=self.paths),
            patch.object(
                workspace,
                "checkout",
                return_value=(self.source, HEAD, IDENTITY, [self.source]),
            ),
            patch.object(workspace, "git", return_value=""),
        ):
            return storage.prepare(self.source, "native", "run-1", HEAD)

    def test_prepare_creates_only_private_run_directories_and_no_evidence_claim(
        self,
    ) -> None:
        result = self.prepare()
        self.assertEqual(result["TMPDIR"], self.paths["generated"]["temporary"])
        self.assertEqual(
            result["ARTIFACT_DIR"], self.paths["protected"]["qualification-artifacts"]
        )
        vm_base = Path(result["LINURA_VM_BASE_DIR"])
        self.assertEqual(vm_base, Path(self.paths["prerequisite"]["vm-base"]))
        self.assertTrue(vm_base.is_dir())
        self.assertEqual(vm_base.stat().st_mode & 0o777, 0o700)
        for group in ("generated", "protected"):
            for role, value in self.paths[group].items():
                selected = Path(value)
                if role == "recovery":
                    self.assertFalse(selected.exists())
                    continue
                self.assertTrue(selected.is_dir())
                self.assertEqual(selected.stat().st_mode & 0o777, 0o700)
        self.assertNotIn("HOME", result)
        self.assertNotIn("RUNNER_TEMP", result)
        self.assertNotIn("CARGO_TARGET_DIR", result)

    def test_vm_base_cache_cannot_follow_a_symlink(self) -> None:
        base = Path(self.paths["prerequisite"]["vm-base"])
        outside = self.root / "outside-cache"
        outside.mkdir(mode=0o700)
        storage.private_tree(self.volume, base.parent)
        base.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(OSError):
            self.prepare()
        self.assertEqual(list(outside.iterdir()), [])

    def test_vm_base_cache_cannot_use_public_existing_directory(self) -> None:
        base = Path(self.paths["prerequisite"]["vm-base"])
        storage.private_tree(self.volume, base.parent)
        base.mkdir(mode=0o700)
        base.chmod(0o755)
        with self.assertRaises(workspace.WorkspaceError):
            self.prepare()
        self.assertEqual(base.stat().st_mode & 0o777, 0o755)

    def test_prepare_refuses_repeat_without_deleting_data(self) -> None:
        result = self.prepare()
        retained = Path(result["ARTIFACT_DIR"]) / "failure.json"
        retained.write_text("retain")
        before = sorted(self.volume.rglob("*"))
        with self.assertRaises(workspace.WorkspaceError):
            self.prepare()
        self.assertEqual(retained.read_text(), "retain")
        self.assertEqual(before, sorted(self.volume.rglob("*")))

    def test_existing_empty_run_cannot_be_reserved_twice(self) -> None:
        self.prepare()
        with self.assertRaises(workspace.WorkspaceError):
            self.prepare()

    def test_dirty_or_substituted_source_is_denied_before_any_creation(self) -> None:
        for head, status in ((HEAD, " M tools/tool.py"), ("c" * 40, "")):
            with (
                patch.object(storage, "run_layout", return_value=self.paths),
                patch.object(
                    workspace,
                    "checkout",
                    return_value=(self.source, head, IDENTITY, [self.source]),
                ),
                patch.object(workspace, "git", return_value=status),
                self.assertRaises(workspace.WorkspaceError),
            ):
                storage.prepare(self.source, "native", "run-1", HEAD)
            self.assertEqual(list(self.volume.iterdir()), [])

    def test_storage_denial_has_no_side_effects(self) -> None:
        with patch.object(
            storage, "run_layout", side_effect=workspace.WorkspaceError("unavailable")
        ):
            with self.assertRaises(workspace.WorkspaceError):
                storage.prepare(self.source, "native", "run-1", HEAD)
        self.assertEqual(list(self.volume.iterdir()), [])

    def test_source_drift_cannot_prepare_a_different_heads_namespace(self) -> None:
        self.paths = workspace.layout(
            self.volume, IDENTITY, "c" * 40, "native", "run-1"
        )
        with self.assertRaises(workspace.WorkspaceError):
            self.prepare()
        self.assertEqual(list(self.volume.iterdir()), [])

    def test_retained_evidence_is_denied_even_if_scratch_was_removed(self) -> None:
        evidence = storage.role_path(self.paths, "evidence")
        storage.private_tree(self.volume, evidence)
        retained = evidence / "retained.json"
        retained.write_bytes(b"preserve")
        with self.assertRaises(workspace.WorkspaceError):
            self.prepare()
        self.assertFalse(storage.role_path(self.paths, "temporary").exists())
        self.assertEqual(retained.read_bytes(), b"preserve")

    def test_private_creation_cannot_follow_existing_ancestor_links(self) -> None:
        outside = self.root / "outside"
        outside.mkdir()
        (self.volume / "builds").symlink_to(outside)
        with self.assertRaises(OSError):
            storage.private_tree(self.volume, storage.role_path(self.paths, "cargo"))
        self.assertEqual(list(outside.iterdir()), [])

    def test_private_creation_does_not_repair_public_permissions(self) -> None:
        builds = self.volume / "builds"
        builds.mkdir(mode=0o755)
        with self.assertRaises(workspace.WorkspaceError):
            storage.private_tree(self.volume, storage.role_path(self.paths, "cargo"))
        self.assertEqual(builds.stat().st_mode & 0o777, 0o755)
        self.assertEqual(list(builds.iterdir()), [])

    def test_private_creation_rejects_broad_or_escaping_targets(self) -> None:
        for selected in (
            self.volume,
            self.root / "elsewhere",
            self.volume / ".." / "escape",
        ):
            with self.subTest(path=selected), self.assertRaises(ValueError):
                storage.private_tree(self.volume, selected)

    def test_destination_can_derive_run_but_must_match_current_identity(self) -> None:
        self.prepare()
        evidence = storage.role_path(self.paths, "evidence")
        with patch.object(storage, "run_layout", return_value=self.paths) as inspect:
            self.assertEqual(
                storage.require_destination(
                    self.source, "native", evidence, "evidence"
                ),
                evidence,
            )
            self.assertEqual(inspect.call_args.args[2], "run-1")
            for selected in (
                evidence.parent / ("c" * 40),
                Path(self.paths["protected"]["recordings"]),
                self.source,
            ):
                with self.subTest(path=selected), self.assertRaises(ValueError):
                    storage.require_destination(
                        self.source, "native", selected, "evidence", run="run-1"
                    )

    def test_destination_rejects_public_descendants_links_and_traversal(self) -> None:
        self.prepare()
        evidence = storage.role_path(self.paths, "evidence")
        public = evidence / "public"
        public.mkdir(mode=0o755)
        link = evidence / "link"
        link.symlink_to(self.root)
        with patch.object(storage, "run_layout", return_value=self.paths):
            for selected in (public, link, evidence / ".." / "escape"):
                with self.subTest(path=selected), self.assertRaises(ValueError):
                    storage.require_destination(
                        self.source, "native", selected, "evidence", run="run-1"
                    )

    def test_fresh_capture_cannot_purge_previous_evidence(self) -> None:
        self.prepare()
        evidence = storage.role_path(self.paths, "evidence")
        retained = evidence / "hardware-other.mkv"
        retained.write_bytes(b"retain")
        with patch.object(storage, "run_layout", return_value=self.paths):
            with self.assertRaises(workspace.WorkspaceError):
                storage.require_destination(
                    self.source, "native", evidence, "evidence", fresh=True
                )
        self.assertEqual(retained.read_bytes(), b"retain")

    def test_vm_inputs_and_scratch_are_checked_and_not_provisioned(self) -> None:
        self.prepare()
        guest = storage.role_path(self.paths, "vm")
        image = guest / "guest.qcow2"
        seed = guest / "seed.img"
        image.write_bytes(b"test")
        seed.write_bytes(b"test")
        with patch.object(storage, "run_layout", return_value=self.paths):
            self.assertEqual(
                storage.check_vm(self.source, "native", "run-1", image, seed, True),
                storage.role_path(self.paths, "temporary"),
            )
            seed.unlink()
            with self.assertRaises(OSError):
                storage.check_vm(self.source, "native", "run-1", image, seed, True)
        self.assertFalse(seed.exists())

    def test_prepared_substrate_cache_uses_stable_verified_prerequisite_paths(
        self,
    ) -> None:
        workflow = (
            ROOT / ".github/workflows/v010-shell-runtime-qualification.yml"
        ).read_text(encoding="utf-8")
        # Three prepared-image files in three cache actions, plus the official
        # base image in its own stable prerequisite cache.
        self.assertEqual(workflow.count("env.LINURA_VM_BASE_DIR"), 10)
        self.assertIn("Stage restored prepared substrate into private run", workflow)
        self.assertIn(
            "Stage verified prepared substrate in stable prerequisite cache", workflow
        )
        self.assertIn(
            "Stage prepared substrate into private runtime namespace", workflow
        )
        self.assertEqual(
            workflow.count('[[ ! -e "$destination" && ! -L "$destination" ]]'),
            4,
        )
        self.assertLess(
            workflow.index("- name: Verify prepared runtime substrate\n"),
            workflow.index(
                "- name: Stage verified prepared substrate in stable prerequisite cache"
            ),
        )
        self.assertLess(
            workflow.index(
                "- name: Stage prepared substrate into private runtime namespace"
            ),
            workflow.index("- name: Verify prepared runtime substrate before boot"),
        )

    def test_github_hosted_ephemeral_root_is_exact_private_and_per_run(self) -> None:
        runner_temp = self.root / "runner-temp"
        runner_temp.mkdir(mode=0o700)
        provider_root = runner_temp / "linura-data"
        paths = workspace.layout(provider_root, IDENTITY, HEAD, "native", "run-1")
        values = {
            "GITHUB_ACTIONS": "true",
            "GITHUB_WORKSPACE": str(self.source),
            "LINURA_STORAGE_CLASS": "github-hosted-ephemeral",
            "LINURA_STORAGE_ROOT": str(provider_root),
            "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_OS": "Linux",
            "RUNNER_TEMP": str(runner_temp),
        }
        with (
            patch.dict(os.environ, values, clear=False),
            patch.object(storage, "run_layout", return_value=paths),
            patch.object(
                workspace,
                "checkout",
                return_value=(self.source, HEAD, IDENTITY, [self.source]),
            ),
            patch.object(workspace, "git", return_value=""),
        ):
            result = storage.prepare(self.source, "native", "run-1", HEAD)
        self.assertEqual(provider_root.stat().st_mode & 0o777, 0o700)
        self.assertEqual(result["LINURA_WORK_DIR"], paths["generated"]["temporary"])
        self.assertTrue(Path(result["ARTIFACT_DIR"]).is_dir())

    def test_provider_ephemeral_cannot_be_selected_by_local_or_self_hosted_env(
        self,
    ) -> None:
        runner_temp = self.root / "runner-temp"
        runner_temp.mkdir(mode=0o700)
        provider_root = runner_temp / "linura-data"
        common = {
            "GITHUB_WORKSPACE": str(self.source),
            "LINURA_STORAGE_CLASS": "github-hosted-ephemeral",
            "LINURA_STORAGE_ROOT": str(provider_root),
            "RUNNER_OS": "Linux",
            "RUNNER_TEMP": str(runner_temp),
        }
        for actions, runner in (("false", "github-hosted"), ("true", "self-hosted")):
            with (
                self.subTest(actions=actions, runner=runner),
                patch.dict(
                    os.environ,
                    {
                        **common,
                        "GITHUB_ACTIONS": actions,
                        "RUNNER_ENVIRONMENT": runner,
                    },
                    clear=False,
                ),
                patch.object(
                    workspace,
                    "checkout",
                    return_value=(self.source, HEAD, IDENTITY, [self.source]),
                ),
                patch.object(workspace, "git", return_value=""),
                self.assertRaises(workspace.WorkspaceError),
            ):
                storage.prepare(self.source, "native", "run-1", HEAD)
            self.assertFalse(provider_root.exists())

    def test_actual_cli_missing_volume_cannot_create_directories(self) -> None:
        missing = self.root / "missing"
        with (
            patch.dict(os.environ, {"LINURA_STORAGE_ROOT": str(missing)}),
            patch.object(
                sys,
                "argv",
                [
                    "development_storage.py",
                    "--environment",
                    "native",
                    "--run",
                    "run-1",
                    "prepare",
                    "--source-sha",
                    HEAD,
                ],
            ),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(storage.main(), 2)
        self.assertFalse(missing.exists())

    def test_native_vm_actual_entrypoint_denies_missing_storage_without_starting_qemu(
        self,
    ) -> None:
        image = self.root / "guest.qcow2"
        seed = self.root / "seed.img"
        image.write_bytes(b"not a VM")
        seed.write_bytes(b"not a seed")
        missing = self.root / "missing-volume"
        before = sorted(self.root.rglob("*"))
        result = subprocess.run(
            [
                "bash",
                str(ROOT / "qualification/v010/shell-runtime/start-vm.sh"),
                "--source-root",
                str(ROOT),
                "--run-id",
                "run-1",
                "--image",
                str(image),
                "--seed",
                str(seed),
                "--nic-mac",
                "52:54:00:12:34:56",
            ],
            env={**os.environ, "LINURA_STORAGE_ROOT": str(missing)},
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("dedicated storage", result.stderr)
        self.assertFalse(missing.exists())
        self.assertEqual(before, sorted(self.root.rglob("*")))


if __name__ == "__main__":
    unittest.main()
