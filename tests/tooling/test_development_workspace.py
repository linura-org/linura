from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tools import development_workspace as workspace  # noqa: E402
from tools import image, vm  # noqa: E402

IDENTITY = "a" * 64
HEAD = "b" * 40
STORAGE_ID = "12345678-1234-1234-1234-123456789abc"


class DevelopmentWorkspaceTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.worktree = self.root / "source"
        self.storage = self.root / "data"
        self.worktree.mkdir()
        self.storage.mkdir(mode=0o700)
        self.common = self.worktree / ".git"
        self.common.mkdir()
        self.inventory = (
            "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n"
            f"2 1 8:17 / {self.storage} rw - ext4 /dev/sdb1 rw\n"
        )
        self.usage = SimpleNamespace(
            f_bavail=100 * workspace.GIB,
            f_frsize=1,
            f_favail=1_000_000,
            f_files=2_000_000,
        )
        self.block_inventory = json.dumps(
            {
                "blockdevices": [
                    {
                        "maj:min": "8:0",
                        "type": "disk",
                        "children": [{"maj:min": "8:1", "type": "part"}],
                    },
                    {
                        "maj:min": "8:16",
                        "type": "disk",
                        "children": [{"maj:min": "8:17", "type": "part"}],
                    },
                ]
            }
        )

    def inspect(
        self, storage: Path | None = None, parallel: int = 1, fresh_run: bool = False
    ) -> workspace.StorageReport:
        with (
            patch.object(
                workspace,
                "checkout",
                return_value=(self.common, HEAD, IDENTITY, [self.worktree]),
            ),
            patch.object(workspace, "no_global_cargo_output", return_value=True),
            patch.object(workspace, "read_bounded", return_value=self.inventory),
            patch.object(workspace.os, "statvfs", return_value=self.usage),
            patch.object(
                workspace,
                "probe",
                side_effect=lambda argv, env: (
                    self.block_inventory if argv[0] == "lsblk" else STORAGE_ID
                ),
            ),
            patch.object(workspace, "mount_device_matches", return_value=True),
        ):
            return workspace.inspect(
                self.worktree,
                storage or self.storage,
                "coding",
                "run-1",
                8,
                parallel,
                STORAGE_ID,
                fresh_run=fresh_run,
            )

    def test_valid_layout_is_read_only_and_never_qualification(self) -> None:
        before = sorted(self.root.rglob("*"))
        report = self.inspect()
        self.assertTrue(report["layout_ready"])
        self.assertFalse(report["qualification_evidence"])
        self.assertFalse(report["execution_performed"])
        self.assertEqual(before, sorted(self.root.rglob("*")))

    def test_github_hosted_ephemeral_storage_is_explicit_and_job_local(self) -> None:
        runner_temp = self.root / "runner-temp"
        runner_temp.mkdir(mode=0o700)
        provider_root = runner_temp / "linura-data"
        provider_root.mkdir(mode=0o700)
        values = {
            "GITHUB_ACTIONS": "true",
            "GITHUB_WORKSPACE": str(self.worktree),
            "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_OS": "Linux",
            "RUNNER_TEMP": str(runner_temp),
        }
        with (
            patch.dict(os.environ, values, clear=False),
            patch.object(
                workspace,
                "checkout",
                return_value=(self.common, HEAD, IDENTITY, [self.worktree]),
            ),
            patch.object(workspace, "no_global_cargo_output", return_value=True),
            patch.object(
                workspace,
                "read_bounded",
                return_value="1 0 8:1 / / rw - ext4 /dev/sda1 rw\n",
            ),
            patch.object(workspace.os, "statvfs", return_value=self.usage),
            patch.object(workspace, "mount_device_matches", return_value=True),
        ):
            report = workspace.inspect(
                self.worktree,
                provider_root,
                "generic-vm",
                "run-1",
                8,
                1,
                storage_class="github-hosted-ephemeral",
            )
        self.assertTrue(report["layout_ready"])
        self.assertEqual(report.get("storage_class"), "github-hosted-ephemeral")
        self.assertNotIn("storage_uuid", report)
        self.assertTrue(
            any(
                check["name"] == "storage.github_hosted_ephemeral" and check["ready"]
                for check in report["checks"]
            )
        )

    def test_provider_ephemeral_rejects_self_hosted_and_noncanonical_roots(
        self,
    ) -> None:
        runner_temp = self.root / "runner-temp"
        runner_temp.mkdir(mode=0o700)
        provider_root = runner_temp / "linura-data"
        provider_root.mkdir(mode=0o700)
        common = {
            "GITHUB_ACTIONS": "true",
            "GITHUB_WORKSPACE": str(self.worktree),
            "RUNNER_OS": "Linux",
            "RUNNER_TEMP": str(runner_temp),
        }
        for runner, selected in (
            ("self-hosted", provider_root),
            ("github-hosted", self.storage),
        ):
            with (
                self.subTest(runner=runner, selected=selected),
                patch.dict(
                    os.environ,
                    {**common, "RUNNER_ENVIRONMENT": runner},
                    clear=False,
                ),
                patch.object(
                    workspace,
                    "checkout",
                    return_value=(self.common, HEAD, IDENTITY, [self.worktree]),
                ),
                patch.object(workspace, "no_global_cargo_output", return_value=True),
                patch.object(
                    workspace,
                    "read_bounded",
                    return_value="1 0 8:1 / / rw - ext4 /dev/sda1 rw\n",
                ),
                patch.object(workspace.os, "statvfs", return_value=self.usage),
                patch.object(workspace, "mount_device_matches", return_value=True),
            ):
                report = workspace.inspect(
                    self.worktree,
                    selected,
                    "generic-vm",
                    "run-1",
                    8,
                    1,
                    storage_class="github-hosted-ephemeral",
                )
            self.assertFalse(report["layout_ready"])
            self.assertNotIn("layout", report)

    def test_missing_storage_is_not_created(self) -> None:
        missing = self.root / "missing"
        report = self.inspect(missing)
        self.assertFalse(report["layout_ready"])
        self.assertFalse(missing.exists())
        self.assertNotIn("layout", report)

    def test_same_filesystem_directory_is_not_extra_capacity(self) -> None:
        self.inventory = "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n"
        report = self.inspect()
        self.assertFalse(report["layout_ready"])
        self.assertNotIn("layout", report)

    def test_root_filesystem_is_rejected_even_when_source_is_on_another_disk(
        self,
    ) -> None:
        self.inventory = (
            "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n"
            f"2 1 8:17 / {self.worktree} rw - ext4 /dev/sdb1 rw\n"
            f"3 1 8:1 / {self.storage} rw - ext4 /dev/sda1 rw\n"
        )
        self.assertFalse(self.inspect()["layout_ready"])

    def test_bind_mount_cannot_fake_independence(self) -> None:
        self.inventory = (
            "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n"
            f"2 1 8:1 /subdirectory {self.storage} rw - ext4 /dev/sda1 rw\n"
        )
        self.assertFalse(self.inspect()["layout_ready"])

    def test_same_physical_disk_partition_is_not_dedicated_storage(self) -> None:
        self.inventory = (
            "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n"
            f"2 1 8:2 / {self.storage} rw - ext4 /dev/sda2 rw\n"
        )
        self.block_inventory = json.dumps(
            {
                "blockdevices": [
                    {
                        "maj:min": "8:0",
                        "type": "disk",
                        "children": [
                            {"maj:min": "8:1", "type": "part"},
                            {"maj:min": "8:2", "type": "part"},
                        ],
                    }
                ]
            }
        )
        self.assertFalse(self.inspect()["layout_ready"])
        mapped = workspace.backing_disks(self.block_inventory)
        self.assertEqual(mapped["8:1"], mapped["8:2"])

    def test_loop_and_unknown_device_mapper_backing_never_prove_capacity(self) -> None:
        for kind in ("loop", "lvm", "crypt", "raid1", "rom"):
            with self.subTest(kind=kind):
                self.assertEqual(
                    workspace.backing_disks(
                        json.dumps(
                            {
                                "blockdevices": [
                                    {
                                        "maj:min": "7:0",
                                        "type": kind,
                                        "children": [
                                            {"maj:min": "259:1", "type": "part"}
                                        ],
                                    }
                                ]
                            }
                        )
                    ),
                    {},
                )

    def test_unknown_and_oversized_block_inventory_fails_closed(self) -> None:
        for value in (
            {},
            {"blockdevices": "unknown"},
            {"blockdevices": [{}]},
            {"blockdevices": [{"maj:min": "8:0", "type": "disk"}] * 257},
        ):
            with (
                self.subTest(value=type(value)),
                self.assertRaises(workspace.WorkspaceError),
            ):
                workspace.backing_disks(json.dumps(value))

    def test_block_inventory_explicitly_requests_tree_output(self) -> None:
        calls = []

        def inventory(argv, env):
            calls.append(argv)
            return self.block_inventory if argv[0] == "lsblk" else STORAGE_ID

        with (
            patch.object(
                workspace,
                "checkout",
                return_value=(self.common, HEAD, IDENTITY, [self.worktree]),
            ),
            patch.object(workspace, "no_global_cargo_output", return_value=True),
            patch.object(workspace, "read_bounded", return_value=self.inventory),
            patch.object(workspace.os, "statvfs", return_value=self.usage),
            patch.object(workspace, "probe", side_effect=inventory),
            patch.object(workspace, "mount_device_matches", return_value=True),
        ):
            report = workspace.inspect(
                self.worktree, self.storage, "coding", "run-1", 8, 1, STORAGE_ID
            )
        self.assertTrue(report["layout_ready"])
        self.assertIn(["lsblk", "--json", "--tree", "--output", "MAJ:MIN,TYPE"], calls)

    def test_overlay_tmpfs_unknown_filesystem_fail_closed(self) -> None:
        for filesystem in ("overlay", "tmpfs", "unknown", "nfs"):
            with self.subTest(filesystem=filesystem):
                self.inventory = (
                    "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n"
                    f"2 1 0:42 / {self.storage} rw - {filesystem} none rw\n"
                )
                report = self.inspect()
                self.assertFalse(report["layout_ready"])
                self.assertNotIn("layout", report)

    def test_same_btrfs_backing_device_is_not_additional_space(self) -> None:
        source = workspace.Mount("0:30", Path("/"), "btrfs", "/dev/sda1")
        storage = workspace.Mount("0:31", Path("/mnt"), "btrfs", "/dev/sda1")
        self.assertFalse(workspace.independent_mount(source, storage))

    def test_unknown_source_backing_cannot_establish_independence(self) -> None:
        source = workspace.Mount("0:30", Path("/"), "overlay", "overlay")
        storage = workspace.Mount("8:17", Path("/mnt"), "ext4", "/dev/sdb1")
        self.assertFalse(workspace.independent_mount(source, storage))

    def test_parent_traversal_is_not_normalized_past_a_symlink(self) -> None:
        link = self.root / "link"
        link.symlink_to(self.storage, target_is_directory=True)
        with self.assertRaises(workspace.WorkspaceError):
            workspace.directory(link / ".." / "source")

    def test_output_inspection_is_non_mutating_and_does_not_require_a_data_disk(
        self,
    ) -> None:
        before = sorted(self.root.rglob("*"))
        with (
            patch.object(
                workspace,
                "checkout",
                return_value=(self.common, HEAD, IDENTITY, [self.worktree]),
            ),
            patch.object(workspace, "no_global_cargo_output", return_value=True),
        ):
            report = workspace.inspect_outputs(self.worktree)
        self.assertTrue(report["layout_ready"])
        self.assertFalse(report["qualification_evidence"])
        self.assertEqual(report.get("development_mode"), "workspace-local")
        self.assertFalse(report.get("heavy_storage_required"))
        self.assertEqual(before, sorted(self.root.rglob("*")))

    def test_heavy_storage_selection_uses_only_declared_or_conventional_mounts(
        self,
    ) -> None:
        explicit = self.root / "explicit"
        self.assertEqual(
            workspace.select_storage_root(
                explicit,
                {"LINURA_STORAGE_ROOT": str(self.storage)},
                self.inventory,
            ),
            (explicit, "argument"),
        )
        self.assertEqual(
            workspace.select_storage_root(
                None,
                {"LINURA_STORAGE_ROOT": str(self.storage)},
                self.inventory,
            ),
            (self.storage, "environment"),
        )
        self.assertEqual(
            workspace.select_storage_root(
                None, {"LINURA_STORAGE_ROOT": "relative"}, self.inventory
            ),
            (None, "invalid-environment"),
        )
        conventional = (
            "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n"
            "2 1 8:17 / /mnt/linura-data rw - ext4 /dev/sdb1 rw\n"
        )
        self.assertEqual(
            workspace.select_storage_root(None, {}, conventional),
            (workspace.CONVENTIONAL_STORAGE_MOUNT, "conventional-mount"),
        )
        self.assertEqual(
            workspace.select_storage_root(None, {}, self.inventory),
            (None, "unavailable"),
        )

    def test_missing_heavy_storage_is_a_nonmutating_heavy_only_blocker(self) -> None:
        before = sorted(self.root.rglob("*"))
        with (
            patch.object(
                workspace,
                "checkout",
                return_value=(self.common, HEAD, IDENTITY, [self.worktree]),
            ),
            patch.object(workspace, "no_global_cargo_output", return_value=True),
        ):
            report = workspace.inspect(
                self.worktree,
                None,
                "coding",
                "run-1",
                8,
                1,
                storage_selection="unavailable",
            )
        self.assertFalse(report["layout_ready"])
        self.assertTrue(report.get("heavy_storage_required"))
        self.assertEqual(report.get("storage_selection"), "unavailable")
        self.assertEqual(report["checks"][-1]["name"], "storage.unavailable")
        self.assertIn(
            "Lightweight work remains available", report["checks"][-1]["remedy"]
        )
        self.assertEqual(before, sorted(self.root.rglob("*")))

    def test_output_inspection_rejects_regular_files_and_symlinks(self) -> None:
        target = self.worktree / "target"
        target.write_text("fixture")
        self.assertFalse(workspace.planned_directories_safe([target]))
        target.unlink()
        target.symlink_to(self.storage, target_is_directory=True)
        self.assertFalse(workspace.planned_directories_safe([target]))
        with (
            patch.object(
                workspace,
                "checkout",
                return_value=(self.common, HEAD, IDENTITY, [self.worktree]),
            ),
            patch.object(workspace, "no_global_cargo_output", return_value=True),
        ):
            self.assertFalse(workspace.inspect_outputs(self.worktree)["layout_ready"])

    def test_output_inspection_unknown_config_is_not_ready(self) -> None:
        with (
            patch.object(
                workspace,
                "checkout",
                return_value=(self.common, HEAD, IDENTITY, [self.worktree]),
            ),
            patch.object(workspace, "no_global_cargo_output", side_effect=ValueError),
        ):
            self.assertFalse(workspace.inspect_outputs(self.worktree)["layout_ready"])

    def test_insufficient_blocks_and_inodes_are_not_ready(self) -> None:
        self.usage.f_bavail = 7 * workspace.GIB
        self.assertFalse(self.inspect()["layout_ready"])
        self.usage.f_bavail = 100 * workspace.GIB
        self.usage.f_favail = 100
        self.assertFalse(self.inspect()["layout_ready"])
        self.usage.f_favail = 1_000_000
        self.usage.f_files = 0
        self.assertFalse(self.inspect()["layout_ready"])

    def test_capacity_budget_accounts_for_concurrent_builds(self) -> None:
        self.usage.f_bavail = 10 * workspace.GIB
        self.assertTrue(self.inspect()["layout_ready"])
        report = self.inspect(parallel=2)
        self.assertFalse(report["layout_ready"])
        self.assertEqual(report["required_free_bytes"], 16 * workspace.GIB)

    def test_symlink_storage_and_ancestor_are_rejected(self) -> None:
        link = self.root / "link"
        link.symlink_to(self.storage, target_is_directory=True)
        self.assertFalse(self.inspect(link)["layout_ready"])
        child = self.storage / "child"
        child.mkdir()
        self.assertFalse(self.inspect(link / "child")["layout_ready"])

    def test_source_and_git_metadata_are_not_storage(self) -> None:
        for selected in (self.worktree, self.common, self.root, Path("/")):
            with self.subTest(selected=selected):
                self.assertFalse(self.inspect(selected)["layout_ready"])

    def test_storage_cannot_overlap_another_registered_worktree(self) -> None:
        with patch.object(
            workspace,
            "checkout",
            return_value=(self.common, HEAD, IDENTITY, [self.worktree, self.storage]),
        ):
            # Do not use the fixture helper, which mocks the inventory itself.
            report = workspace.inspect(
                self.worktree, self.storage, "coding", "run-1", 8, 1
            )
        self.assertFalse(report["layout_ready"])

    def test_preexisting_layout_symlink_cannot_redirect_output(self) -> None:
        (self.storage / "builds").symlink_to(self.worktree, target_is_directory=True)
        report = self.inspect()
        self.assertFalse(report["layout_ready"])
        self.assertNotIn("layout", report)

    def test_preexisting_layout_file_is_not_an_output_directory(self) -> None:
        (self.storage / "builds").write_text("fixture")
        self.assertFalse(self.inspect()["layout_ready"])

    def test_layout_binds_worktree_environment_run_and_source(self) -> None:
        original = workspace.layout(self.storage, IDENTITY, HEAD, "coding", "run-1")
        for args in (
            ("c" * 64, HEAD, "coding", "run-1"),
            (IDENTITY, "c" * 40, "coding", "run-1"),
            (IDENTITY, HEAD, "other", "run-1"),
            (IDENTITY, HEAD, "coding", "run-2"),
        ):
            with self.subTest(args=args):
                changed = workspace.layout(self.storage, *args)
                self.assertNotEqual(original["generated"], changed["generated"])
                self.assertNotEqual(original["protected"], changed["protected"])

    def test_protected_generated_and_prerequisite_namespaces_do_not_overlap(
        self,
    ) -> None:
        result = workspace.layout(self.storage, IDENTITY, HEAD, "coding", "run-1")
        for first_group, first_paths in result.items():
            for second_group, second_paths in result.items():
                if first_group == second_group:
                    continue
                for first in first_paths.values():
                    for second in second_paths.values():
                        self.assertFalse(workspace.overlaps(Path(first), Path(second)))

    def test_layout_labels_and_identities_cannot_escape_storage(self) -> None:
        for value in ("../escape", "a/b", "", "a\n", "A", "a" * 65, "-option"):
            with self.subTest(value=value):
                with self.assertRaises(argparse.ArgumentTypeError):
                    workspace.layout(self.storage, IDENTITY, HEAD, value, "run-1")
        with self.assertRaises(workspace.WorkspaceError):
            workspace.layout(self.storage, "../escape", HEAD, "coding", "run-1")

    def test_actual_mountpoint_and_not_a_subdirectory_is_required(self) -> None:
        child = self.storage / "child"
        child.mkdir()
        self.assertFalse(self.inspect(child)["layout_ready"])

    def test_bind_alias_and_read_only_storage_are_rejected(self) -> None:
        for root, options in (("/bound", "rw"), ("/", "ro")):
            self.inventory = (
                "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n"
                f"2 1 8:17 {root} {self.storage} {options} - ext4 /dev/sdb1 {options}\n"
            )
            self.assertFalse(self.inspect()["layout_ready"])
        self.inventory = (
            "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n"
            f"2 1 8:17 / {self.storage} rw - ext4 /dev/sdb1 rw\n"
            "3 1 8:17 / /alias rw - ext4 /dev/sdb1 rw\n"
        )
        self.assertFalse(self.inspect()["layout_ready"])

    def test_unknown_wrong_and_missing_storage_identity_fail_closed(self) -> None:
        for value in (None, "", "changed-id", "12345678-1234-1234-1234-123456789abd"):
            with (
                patch.object(
                    workspace,
                    "checkout",
                    return_value=(self.common, HEAD, IDENTITY, [self.worktree]),
                ),
                patch.object(workspace, "read_bounded", return_value=self.inventory),
                patch.object(workspace, "no_global_cargo_output", return_value=True),
                patch.object(
                    workspace,
                    "probe",
                    side_effect=lambda argv, env: (
                        self.block_inventory if argv[0] == "lsblk" else STORAGE_ID
                    ),
                ),
                patch.object(workspace, "mount_device_matches", return_value=True),
            ):
                report = workspace.inspect(
                    self.worktree, self.storage, "coding", "run-1", 8, 1, value
                )
            self.assertFalse(report["layout_ready"])
            self.assertNotIn("layout", report)
            self.assertTrue(
                any(
                    check["name"] == "storage.identity" and not check["ready"]
                    for check in report["checks"]
                )
            )

    def test_world_writable_storage_and_public_protected_roots_fail_closed(
        self,
    ) -> None:
        self.storage.chmod(0o777)
        self.assertFalse(self.inspect()["layout_ready"])
        self.storage.chmod(0o700)
        evidence = self.storage / "evidence"
        evidence.mkdir(mode=0o755)
        self.assertFalse(self.inspect()["layout_ready"])
        evidence.chmod(0o700)
        self.assertTrue(self.inspect()["layout_ready"])

    def test_fresh_run_preserves_retained_evidence_and_requires_new_identity(
        self,
    ) -> None:
        planned = workspace.layout(self.storage, IDENTITY, HEAD, "coding", "run-1")
        evidence = Path(planned["protected"]["qualification-artifacts"])
        for part in reversed((evidence, *evidence.parents)):
            if part.is_relative_to(self.storage) and not part.exists():
                part.mkdir(mode=0o700)
        retained = evidence / "failed-run.json"
        retained.write_text("retained failure diagnostics")
        self.assertTrue(self.inspect()["layout_ready"])
        self.assertFalse(self.inspect(fresh_run=True)["layout_ready"])
        self.assertEqual(retained.read_text(), "retained failure diagnostics")

    def test_existing_generated_run_namespace_must_be_private(self) -> None:
        paths = workspace.layout(self.storage, IDENTITY, HEAD, "coding", "run-1")
        generated = Path(paths["generated"]["temporary"])
        for part in reversed((generated, *generated.parents)):
            if part.is_relative_to(self.storage) and not part.exists():
                part.mkdir(mode=0o700)
        self.assertTrue(self.inspect()["layout_ready"])
        generated.chmod(0o755)
        self.assertFalse(self.inspect()["layout_ready"])
        generated.chmod(0o700)
        self.assertTrue(self.inspect()["layout_ready"])

    def test_cmake_cache_cannot_be_reused_from_another_worktree(self) -> None:
        build = self.worktree / ".artifacts/cmake/ui"
        build.mkdir(parents=True)
        source = self.worktree / "apps/linura-shell/ui"
        cache = build / "CMakeCache.txt"
        cache.write_text(
            f"CMAKE_HOME_DIRECTORY:INTERNAL={source}\nCMAKE_CACHEFILE_DIR:INTERNAL={build}\n"
        )
        self.assertTrue(workspace.cmake_owner_matches(build, source))
        cache.write_text(
            f"CMAKE_HOME_DIRECTORY:INTERNAL={self.root}/other\nCMAKE_CACHEFILE_DIR:INTERNAL={build}\n"
        )
        self.assertFalse(workspace.cmake_owner_matches(build, source))
        cache.write_text("malformed cache\n")
        self.assertFalse(workspace.cmake_owner_matches(build, source))

    def test_editor_missing_sdk_is_not_readiness_and_never_installs(self) -> None:
        with (
            patch.object(
                workspace,
                "checkout",
                return_value=(self.common, HEAD, IDENTITY, [self.worktree]),
            ),
            patch.object(workspace, "no_global_cargo_output", return_value=True),
            patch.object(workspace, "probe", return_value=None),
        ):
            before = sorted(self.root.rglob("*"))
            report = workspace.inspect_editor(self.worktree)
            self.assertFalse(report["layout_ready"])
            self.assertFalse(report["qualification_evidence"])
            self.assertNotIn("editor_settings", report)
            self.assertEqual(before, sorted(self.root.rglob("*")))

    def test_existing_qt_sdk_and_modules_produce_namespace_local_settings(self) -> None:
        bins = self.root / "qt/bin"
        bins.mkdir(parents=True)
        server = bins / "qmlls"
        server.write_text("fixture")
        server.chmod(0o700)
        for module in ("QtQuick", "QtQuick.Controls", "QtQuick.Layouts"):
            imported = self.root.joinpath(*module.split("."))
            imported.mkdir(parents=True)
            (imported / "qmldir").write_text(f"module {module}\n")
        for component, module in (("ui", "UI"), ("bridge", "ShellBridge")):
            build = self.worktree / f".artifacts/cmake/{component}"
            generated = build / f"qml/org/linura/{module}"
            generated.mkdir(parents=True)
            (generated / "qmldir").write_text(f"module org.linura.{module}\n")
            source = self.worktree / f"apps/linura-shell/{component}"
            (build / "CMakeCache.txt").write_text(
                f"CMAKE_HOME_DIRECTORY:INTERNAL={source}\nCMAKE_CACHEFILE_DIR:INTERNAL={build}\n"
            )
            (build / "compile_commands.json").write_text(
                json.dumps(
                    [{"directory": str(build), "file": str(source / "fixture.cpp")}]
                )
            )
        query = f"QT_VERSION:6.4.2\nQT_INSTALL_BINS:{bins}\nQT_INSTALL_HEADERS:{self.root}\nQT_INSTALL_QML:{self.root}"
        with (
            patch.object(
                workspace,
                "checkout",
                return_value=(self.common, HEAD, IDENTITY, [self.worktree]),
            ),
            patch.object(workspace, "no_global_cargo_output", return_value=True),
            patch.object(
                workspace, "probe", side_effect=[query, "--build-dir --ignore-settings"]
            ),
        ):
            report = workspace.inspect_editor(self.worktree)
        self.assertTrue(report["layout_ready"])
        assert "editor_settings" in report
        settings = report["editor_settings"]
        self.assertTrue(settings["qt-qml.qmlls.enabled"])
        self.assertTrue(settings["qt-qml.doNotAskForQmllsDownload"])
        self.assertEqual(settings["qt-qml.qmlls.customExePath"], str(server))
        arguments = settings["qt-qml.qmlls.customArgs"]
        databases = settings["C_Cpp.default.compileCommands"]
        assert isinstance(arguments, list) and isinstance(databases, list)
        self.assertNotIn("-I", arguments)
        self.assertEqual(len(databases), 2)
        self.assertFalse(report["qualification_evidence"])

    def test_authority_host_accepts_root_sticky_tmp_and_root_recovery_binary(
        self,
    ) -> None:
        metadata = {
            "/": SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0),
            "/tmp": SimpleNamespace(
                st_mode=stat.S_IFDIR | stat.S_ISVTX | 0o777, st_uid=0
            ),
            "/usr/bin/bash": SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=0),
        }

        def lstat(path: Path):
            return metadata[str(path)]

        with patch.object(Path, "lstat", autospec=True, side_effect=lstat):
            self.assertTrue(
                workspace.trusted_authority_test_directory(Path("/tmp"), 1000)
            )
            self.assertTrue(
                workspace.trusted_native_recovery_program(Path("/usr/bin/bash"))
            )

    def test_authority_host_rejects_uid_remapping_and_untrusted_tmp(self) -> None:
        def remapped(path: Path):
            mode = stat.S_IFDIR | (0o1777 if str(path) == "/tmp" else 0o755)
            return SimpleNamespace(st_mode=mode, st_uid=65534)

        with patch.object(Path, "lstat", autospec=True, side_effect=remapped):
            self.assertFalse(
                workspace.trusted_authority_test_directory(Path("/tmp"), 1000)
            )

        metadata = {
            "/": SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0),
            "/unsafe": SimpleNamespace(st_mode=stat.S_IFDIR | 0o777, st_uid=1000),
        }
        with patch.object(
            Path,
            "lstat",
            autospec=True,
            side_effect=lambda path: metadata[str(path)],
        ):
            self.assertFalse(
                workspace.trusted_authority_test_directory(Path("/unsafe"), 1000)
            )

        with patch.object(
            Path,
            "lstat",
            autospec=True,
            return_value=SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=65534),
        ):
            self.assertFalse(
                workspace.trusted_native_recovery_program(Path("/usr/bin/bash"))
            )

    def test_interactive_launcher_without_mount_creates_no_scratch_or_evidence(
        self,
    ) -> None:
        # A real clean fixture checkout reaches the actual guard. No VM, SDK or
        # fabricated positive storage evidence is needed for this denial case.
        source = self.root / "clean"
        (source / "tools/codex").mkdir(parents=True)
        for name in ("tools/development_workspace.py", "tools/codex/doctor.py"):
            (source / name).write_bytes((ROOT / name).read_bytes())
        subprocess.run(["git", "init", "--quiet", str(source)], check=True)
        subprocess.run(["git", "-C", str(source), "add", "tools"], check=True)
        subprocess.run(
            [
                "git",
                "-C",
                str(source),
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "commit",
                "--quiet",
                "-m",
                "fixture",
            ],
            check=True,
        )
        image = self.root / "prepared.qcow2"
        image.write_bytes(b"not used")
        manifest = self.root / "prepared.json"
        manifest.write_text("{}")
        missing = self.root / "missing-volume"
        before = sorted(self.root.rglob("*"))
        result = subprocess.run(
            [
                "bash",
                str(
                    ROOT
                    / "qualification/v010/workstation-acceptance/launch-interactive.sh"
                ),
                "--source-root",
                str(source),
                "--prepared-image",
                str(image),
                "--prepared-manifest",
                str(manifest),
                "--storage-root",
                str(missing),
                "--storage-id",
                STORAGE_ID,
                "--run-id",
                "denied-run",
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("dedicated qualification storage", result.stderr)
        self.assertFalse(missing.exists())
        self.assertEqual(before, sorted(self.root.rglob("*")))

    def test_interactive_launcher_checks_storage_before_writes_and_no_fallback(
        self,
    ) -> None:
        script = (
            ROOT / "qualification/v010/workstation-acceptance/launch-interactive.sh"
        ).read_text()
        guard = script.index('tools/development_workspace.py" "${storage_args[@]}"')
        self.assertLess(guard, script.index('prepare --source-sha "$source_sha"'))
        self.assertLess(guard, script.index('mktemp -d -p "$temporary_root"'))
        self.assertNotIn('evidence_dir="$source_root/.artifacts/', script)
        self.assertNotIn("mktemp -d -t linura-workstation-live", script)
        self.assertIn(
            "unset CARGO_TARGET_DIR CARGO_BUILD_TARGET_DIR CARGO_BUILD_BUILD_DIR",
            script,
        )

    def test_unknown_and_malformed_mounts_are_explicit_failures(self) -> None:
        for value in ("", "bad line", "1 0 invalid / / rw - ext4 /dev/sda1 rw"):
            with self.subTest(value=value):
                with self.assertRaises(workspace.WorkspaceError):
                    workspace.mounts(value)
                self.inventory = value
                report = self.inspect()
                self.assertFalse(report["layout_ready"])
                names = [check["name"] for check in report["checks"]]
                self.assertEqual(len(names), len(set(names)))

    def test_mount_escapes_and_deepest_overmount_are_parsed(self) -> None:
        inventory = workspace.mounts(
            "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n"
            "2 1 8:17 / /mnt/with\\040space rw shared:2 - xfs /dev/sdb1 rw\n"
            "3 1 8:33 / /mnt/with\\040space rw - ext4 /dev/sdc1 rw\n"
        )
        chosen = workspace.containing_mount(Path("/mnt/with space/data"), inventory)
        self.assertEqual(chosen.source, "/dev/sdc1")

    def test_global_output_environment_is_reported_without_exposing_values(
        self,
    ) -> None:
        for key in workspace.INHERITED_OUTPUT_KEYS:
            with self.subTest(key=key), patch.dict(os.environ, {key: "private-value"}):
                self.assertFalse(workspace.no_global_cargo_output(self.worktree))

    def test_cargo_config_output_overrides_and_malformed_input_fail_closed(
        self,
    ) -> None:
        cargo_home = self.root / "cargo-home"
        cargo_home.mkdir()
        config = cargo_home / "config.toml"
        with patch.dict(os.environ, {"CARGO_HOME": str(cargo_home)}):
            for key in workspace.INHERITED_OUTPUT_KEYS:
                os.environ.pop(key, None)
            self.assertTrue(workspace.no_global_cargo_output(self.worktree))
            for key in ("target-dir", "build-dir"):
                config.write_text(f'[build]\n{key}="shared"\n')
                self.assertFalse(workspace.no_global_cargo_output(self.worktree))
            config.write_text("malformed TOML [")
            with self.assertRaises(ValueError):
                workspace.no_global_cargo_output(self.worktree)

    def test_bounded_input_reader(self) -> None:
        fixture = self.root / "oversized"
        fixture.write_bytes(b"a" * (workspace.MAX_INPUT_BYTES + 1))
        with self.assertRaises(workspace.WorkspaceError):
            workspace.read_bounded(fixture)

    def test_input_reader_rejects_symlinks_fifo_and_directory_without_blocking(
        self,
    ) -> None:
        regular = self.root / "regular"
        regular.write_text("fixture")
        linked = self.root / "linked-input"
        linked.symlink_to(regular)
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        for selected in (linked, self.root):
            with self.subTest(selected=selected):
                with self.assertRaises((OSError, workspace.WorkspaceError)):
                    workspace.read_bounded(selected)
        child = (
            "from pathlib import Path; import sys; "
            "from tools.development_workspace import read_bounded,WorkspaceError; "
            "\ntry: read_bounded(Path(sys.argv[1]))"
            "\nexcept (OSError,WorkspaceError): raise SystemExit(0)"
            "\nraise SystemExit(1)"
        )
        result = subprocess.run(
            [sys.executable, "-B", "-c", child, str(fifo)],
            cwd=ROOT,
            capture_output=True,
            check=False,
            timeout=5,
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(workspace.read_bounded(regular), "fixture")

    def test_unknown_home_path_is_an_explicit_boundary_failure(self) -> None:
        with patch.object(Path, "expanduser", side_effect=RuntimeError):
            with self.assertRaises(workspace.WorkspaceError):
                workspace.directory(self.worktree)

    def test_relative_cargo_home_is_anchored_to_the_selected_worktree(self) -> None:
        home = self.worktree / "local-home"
        home.mkdir()
        (home / "config.toml").write_text('[build]\ntarget-dir="shared"\n')
        with patch.dict(os.environ, {"CARGO_HOME": "local-home"}):
            for key in workspace.INHERITED_OUTPUT_KEYS:
                os.environ.pop(key, None)
            self.assertFalse(workspace.no_global_cargo_output(self.worktree))

    def test_cargo_config_parent_symlink_is_not_followed(self) -> None:
        home = self.root / "cargo-home"
        home.mkdir()
        (self.worktree / ".cargo").symlink_to(home, target_is_directory=True)
        with patch.dict(os.environ, {"CARGO_HOME": str(home)}):
            for key in workspace.INHERITED_OUTPUT_KEYS:
                os.environ.pop(key, None)
            self.assertFalse(workspace.no_global_cargo_output(self.worktree))

    def test_git_redirection_and_failed_probe_are_not_source_identity(self) -> None:
        with patch.dict(os.environ, {"GIT_DIR": "private-value"}):
            with self.assertRaises(workspace.WorkspaceError) as raised:
                workspace.git(self.worktree, "rev-parse", "HEAD")
            self.assertNotIn("private-value", str(raised.exception))
        with patch.object(workspace, "probe", return_value=None):
            with self.assertRaises(workspace.WorkspaceError):
                workspace.git(self.worktree, "rev-parse", "HEAD")

    def test_real_linked_worktrees_get_independent_identity_without_git_mutation(
        self,
    ) -> None:
        self.common.rmdir()
        subprocess.run(["git", "init", "--quiet", str(self.worktree)], check=True)
        subprocess.run(
            [
                "git",
                "-C",
                str(self.worktree),
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "commit",
                "--allow-empty",
                "--quiet",
                "-m",
                "fixture",
            ],
            check=True,
        )
        linked = self.root / "linked"
        subprocess.run(
            [
                "git",
                "-C",
                str(self.worktree),
                "worktree",
                "add",
                "--quiet",
                "--detach",
                str(linked),
            ],
            check=True,
        )
        first = workspace.checkout(self.worktree)
        second = workspace.checkout(linked)
        self.assertEqual(first[0], second[0])
        self.assertEqual(first[1], second[1])
        self.assertNotEqual(first[2], second[2])
        self.assertEqual(set(first[3]), {self.worktree, linked})
        self.assertEqual(
            subprocess.check_output(
                ["git", "-C", str(self.worktree), "status", "--porcelain"]
            ),
            b"",
        )

    def test_nested_directory_is_not_an_active_worktree_root(self) -> None:
        with patch.object(workspace, "git", return_value=str(self.worktree)):
            with self.assertRaises(workspace.WorkspaceError):
                workspace.checkout(self.common)

    def test_cli_reports_blocker_and_never_creates_storage(self) -> None:
        missing = self.root / "missing"
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "tools/development_workspace.py"),
                "storage",
                "--storage-root",
                str(missing),
                "--environment",
                "coding",
                "--run",
                "run-1",
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        self.assertEqual(result.returncode, 1)
        report = json.loads(result.stdout)
        self.assertFalse(report["qualification_evidence"])
        self.assertFalse(report["layout_ready"])
        self.assertFalse(missing.exists())

    def test_cli_rejects_zero_negative_overlarge_and_invalid_labels(self) -> None:
        for args in (
            ["--min-free-gib", "0"],
            ["--min-free-gib", "-1"],
            ["--max-parallel-builds", "1025"],
            ["--environment", "../escape"],
        ):
            with self.subTest(args=args):
                result = subprocess.run(
                    [
                        sys.executable,
                        str(ROOT / "tools/development_workspace.py"),
                        "storage",
                        "--storage-root",
                        str(self.storage),
                        "--environment",
                        "coding",
                        "--run",
                        "run-1",
                        *args,
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=30,
                )
                self.assertEqual(result.returncode, 2)


class DevelopmentEditorTaskTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = json.loads((ROOT / ".vscode/tasks.json").read_text())
        self.tasks = {task["label"]: task for task in self.config["tasks"]}

    def test_editor_uses_active_worktree_and_noninstalling_bounded_tasks(self) -> None:
        self.assertEqual(self.config["version"], "2.0.0")
        self.assertEqual(self.config["options"]["cwd"], "${workspaceFolder}")
        self.assertEqual(self.config["options"]["env"]["CARGO_BUILD_JOBS"], "1")
        self.assertEqual(self.config["options"]["env"]["RUSTUP_AUTO_INSTALL"], "0")
        self.assertEqual(
            self.config["options"]["env"]["PATH"],
            "${userHome}/.local/linura-tools/python312/bin:${env:PATH}",
        )
        for task in self.tasks.values():
            self.assertEqual(task["runOptions"]["instanceLimit"], 1)
            self.assertNotIn("runOn", task["runOptions"])
            if "command" in task:
                self.assertEqual(task["type"], "process")
            args = task.get("args", [])
            self.assertFalse(
                any(
                    value in args
                    for value in ("sudo", "install", "--force", "--no-fetch")
                )
            )
        self.assertIn("!.vscode/tasks.json", (ROOT / ".gitignore").read_text())

    def test_canonical_check_retains_preflight_and_exact_existing_gate(self) -> None:
        task = self.tasks["Linura: canonical check"]
        self.assertEqual(task["dependsOn"], "Linura: authority-test host")
        self.assertEqual(
            self.tasks["Linura: authority-test host"]["dependsOn"],
            "Linura: output isolation",
        )
        self.assertEqual(
            self.tasks["Linura: output isolation"]["dependsOn"], "Linura: preflight"
        )
        self.assertEqual(
            task["args"][-5:],
            ["bash", "scripts/run_codex.sh", "cargo", "xtask", "check"],
        )
        for task in self.tasks.values():
            if task.get("command") == "env":
                for key in workspace.INHERITED_OUTPUT_KEYS:
                    index = task["args"].index(key)
                    self.assertEqual(task["args"][index - 1], "-u")

    def test_default_and_complete_environment_inventories_are_distinct(self) -> None:
        default = self.tasks["Linura: default environment"]
        complete = self.tasks["Linura: complete environment inventory (not readiness)"]
        self.assertEqual(default["args"][-2:], ["--profile", "core"])
        self.assertEqual(complete["args"][-1], "--all")

    def test_qt_component_builds_are_sequential_worktree_local_not_qualification(
        self,
    ) -> None:
        group = self.tasks["Linura: Qt component builds (not qualification)"]
        self.assertEqual(group["dependsOrder"], "sequence")
        for component in ("UI", "bridge"):
            configure = self.tasks[f"Linura: {component} configure"]
            build = self.tasks[f"Linura: {component} build"]
            self.assertEqual(configure["dependsOn"], "Linura: shell prerequisites")
            self.assertEqual(build["dependsOn"], f"Linura: {component} configure")
            self.assertIn("-DCMAKE_EXPORT_COMPILE_COMMANDS=ON", configure["args"])
            self.assertEqual(build["args"][-2:], ["--parallel", "1"])
            self.assertIn(
                f"${{workspaceFolder}}/.artifacts/cmake/{component.lower()}",
                configure["args"],
            )
            self.assertIn(
                f"${{workspaceFolder}}/.artifacts/cmake/{component.lower()}",
                build["args"],
            )
        self.assertEqual(
            self.tasks["Linura: shell prerequisites"]["dependsOn"],
            "Linura: output isolation",
        )


class StorageExecutionTests(unittest.TestCase):
    """Execution plumbing tests, not real mounted-volume or QEMU evidence."""

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.storage = self.root / "data"
        self.storage.mkdir(mode=0o700)
        self.paths = workspace.layout(
            self.storage, IDENTITY, HEAD, "generic-vm", "run-1"
        )
        self.args = argparse.Namespace(
            storage_root=self.storage, storage_id=STORAGE_ID, run="run-1"
        )

    def test_execution_never_accepts_an_unready_inspection(self) -> None:
        with patch.object(
            workspace, "inspect", return_value={"layout_ready": False, "checks": []}
        ):
            with self.assertRaises(workspace.WorkspaceError):
                workspace.execution_layout(ROOT, self.args, "generic-vm")

    def test_execution_exposes_the_provider_selected_root_to_bounded_callers(
        self,
    ) -> None:
        self.args.storage_root = None
        with (
            patch.object(
                workspace,
                "select_storage_root",
                return_value=(self.storage, "environment"),
            ),
            patch.object(
                workspace,
                "inspect",
                return_value={
                    "layout_ready": True,
                    "checks": [],
                    "layout": self.paths,
                },
            ),
        ):
            self.assertEqual(
                workspace.execution_layout(ROOT, self.args, "generic-vm"), self.paths
            )
        self.assertEqual(self.args.storage_root, self.storage)

    def test_environment_run_identity_is_validated(self) -> None:
        for value in (None, "../escape", "Upper", "a" * 65):
            self.args.run = value
            with self.subTest(run=value), patch.object(workspace, "inspect") as inspect:
                with self.assertRaises(workspace.WorkspaceError):
                    workspace.execution_layout(ROOT, self.args, "generic-vm")
                inspect.assert_not_called()

    def test_vm_plan_remains_nonmutating_without_a_volume(self) -> None:
        with (
            patch.object(sys, "argv", ["vm.py", "plan", "--accel", "tcg"]),
            patch.object(workspace, "execution_layout") as inspect,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(vm.main(), 0)
            inspect.assert_not_called()

    def vm_fixture(self) -> tuple[Path, Path]:
        guest = Path(self.paths["generated"]["vm-disposable"])
        guest.mkdir(parents=True, mode=0o700)
        disk = guest / "guest.qcow2"
        disk.write_bytes(b"fixture, not a real image")
        scratch = Path(self.paths["generated"]["temporary"])
        scratch.mkdir(parents=True, mode=0o700)
        return disk, scratch

    def run_vm(self, disk: Path, *options: str) -> int:
        with (
            patch.object(
                sys,
                "argv",
                [
                    "vm.py",
                    "start",
                    "--image",
                    str(disk),
                    "--accel",
                    "tcg",
                    "--storage-root",
                    str(self.storage),
                    "--run",
                    "run-1",
                    *options,
                ],
            ),
            patch.object(
                vm.shutil, "which", return_value="/usr/bin/qemu-system-x86_64"
            ),
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            return vm.main()

    def test_vm_storage_denial_cannot_execute_or_create_outputs(self) -> None:
        disk, _ = self.vm_fixture()
        before = sorted(self.root.rglob("*"))
        with (
            patch.object(
                workspace,
                "execution_layout",
                side_effect=workspace.WorkspaceError("missing volume"),
            ),
            patch.object(vm.os, "execvpe") as execute,
        ):
            self.assertEqual(self.run_vm(disk), 2)
            execute.assert_not_called()
        self.assertEqual(before, sorted(self.root.rglob("*")))

    def test_vm_uses_only_checked_scratch_and_exec_replaces_the_harness(self) -> None:
        disk, scratch = self.vm_fixture()
        with (
            patch.object(workspace, "execution_layout", return_value=self.paths),
            patch.dict(os.environ, {"TMPDIR": "/wrong-root-disk"}),
            patch.object(
                vm.os, "execvpe", side_effect=OSError("test exec boundary")
            ) as execute,
        ):
            self.assertEqual(self.run_vm(disk), 2)
            self.assertEqual(execute.call_count, 1)
            self.assertEqual(execute.call_args.args[2]["TMPDIR"], str(scratch))
            self.assertIn("-snapshot", execute.call_args.args[1])

    def test_persistent_vm_cannot_write_a_base_image(self) -> None:
        self.vm_fixture()
        base = self.storage / "qualification/vm-images/base"
        base.mkdir()
        disk = base / "guest.qcow2"
        disk.write_bytes(b"fixture")
        with (
            patch.object(workspace, "execution_layout", return_value=self.paths),
            patch.object(vm.os, "execvpe") as execute,
        ):
            self.assertEqual(self.run_vm(disk, "--persistent"), 2)
            execute.assert_not_called()

    def test_vm_missing_or_public_scratch_is_denied(self) -> None:
        disk, scratch = self.vm_fixture()
        scratch.chmod(0o755)
        with (
            patch.object(workspace, "execution_layout", return_value=self.paths),
            patch.object(vm.os, "execvpe") as execute,
        ):
            self.assertEqual(self.run_vm(disk), 2)
            execute.assert_not_called()
        scratch.rmdir()
        with (
            patch.object(workspace, "execution_layout", return_value=self.paths),
            patch.object(vm.os, "execvpe") as execute,
        ):
            self.assertEqual(self.run_vm(disk), 2)
            execute.assert_not_called()
        self.assertFalse(scratch.exists())

    def test_regular_inputs_reject_symlinks_hardlinks_fifo_and_qemu_option_syntax(
        self,
    ) -> None:
        disk, _ = self.vm_fixture()
        root = disk.parent
        link = root / "link"
        link.symlink_to(disk)
        fifo = root / "fifo"
        os.mkfifo(fifo)
        unsafe = root / "guest,cache=unsafe"
        unsafe.write_bytes(b"fixture")
        alias = root / "hardlink"
        os.link(disk, alias)
        for selected in (disk, alias, link, fifo, unsafe):
            with (
                self.subTest(path=selected),
                self.assertRaises((OSError, workspace.WorkspaceError)),
            ):
                workspace.regular_storage_input(selected, root)

    def test_image_denied_storage_has_no_side_effects(self) -> None:
        before = sorted(self.root.rglob("*"))
        with patch.object(
            workspace,
            "execution_layout",
            side_effect=workspace.WorkspaceError("missing volume"),
        ):
            with self.assertRaises(workspace.WorkspaceError):
                image.reserve_image_paths(self.args)
        self.assertEqual(before, sorted(self.root.rglob("*")))

    def test_image_reserves_a_fresh_namespace_and_never_purges_a_previous_run(
        self,
    ) -> None:
        with patch.object(workspace, "execution_layout", return_value=self.paths):
            selected = image.reserve_image_paths(self.args)
            retained = selected.output.parent / "failure-diagnostic"
            retained.write_bytes(b"retain")
            with self.assertRaises(workspace.WorkspaceError):
                image.reserve_image_paths(self.args)
        self.assertEqual(retained.read_bytes(), b"retain")
        self.assertTrue(selected.staged.is_relative_to(self.storage))
        self.assertEqual(selected.output.parent.stat().st_mode & 0o777, 0o700)

    def test_image_creation_cannot_follow_a_layout_symlink(self) -> None:
        outside = self.root / "outside"
        outside.mkdir()
        (self.storage / "builds").symlink_to(outside, target_is_directory=True)
        with patch.object(workspace, "execution_layout", return_value=self.paths):
            with self.assertRaises(OSError):
                image.reserve_image_paths(self.args)
        self.assertEqual(list(outside.iterdir()), [])

    def test_image_execution_denial_cannot_stage_or_build(self) -> None:
        with (
            patch.object(sys, "argv", ["image.py", "build", "--run", "run-1"]),
            patch.object(image.shutil, "which", return_value="/usr/bin/mkarchiso"),
            patch.object(
                workspace,
                "execution_layout",
                side_effect=workspace.WorkspaceError("missing volume"),
            ),
            patch.object(image, "stage_profile") as stage,
            patch.object(image.subprocess, "run") as execute,
            contextlib.redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(image.main(), 2)
            stage.assert_not_called()
            execute.assert_not_called()

    def test_image_processes_use_dedicated_scratch_and_keep_failed_work(self) -> None:
        with (
            patch.object(
                sys,
                "argv",
                [
                    "image.py",
                    "build",
                    "--run",
                    "run-1",
                    "--storage-root",
                    str(self.storage),
                ],
            ),
            patch.object(image.shutil, "which", return_value="/usr/bin/mkarchiso"),
            patch.object(workspace, "execution_layout", return_value=self.paths),
            patch.dict(os.environ, {"TMPDIR": "/wrong-root-disk"}),
            patch.object(
                image,
                "stage_profile",
                side_effect=subprocess.CalledProcessError(1, ["cmake"]),
            ) as stage,
            patch.object(image.subprocess, "run") as execute,
            contextlib.redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(image.main(), 2)
            selected = stage.call_args.args[1]
            self.assertEqual(os.environ["TMPDIR"], str(selected.work))
            self.assertTrue(selected.work.is_dir())
            self.assertTrue(selected.work.is_relative_to(self.storage))
            execute.assert_not_called()
        self.assertTrue(selected.work.is_dir())


if __name__ == "__main__":
    unittest.main()
