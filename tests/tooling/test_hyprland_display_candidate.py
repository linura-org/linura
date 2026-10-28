"""Build-handoff rejection tests; these do not qualify native display effects."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import tomllib
import unittest
from unittest.mock import patch

from tools import hyprland_display_candidate as candidate

ROOT = Path(__file__).resolve().parents[2]
SHA = "1" * 40


class HyprlandDisplayCandidateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.root = self.base / "source"
        for name in candidate.INPUTS:
            destination = self.root / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, destination)
        self.inputs = self.base / "inputs"
        self.inputs.mkdir()
        elf = bytearray(64)
        elf[:7], elf[18:20] = b"\x7fELF\x02\x01\x01", b"\x3e\x00"
        (self.inputs / "Hyprland").write_bytes(elf)
        (self.inputs / "integration-build.h").write_text(
            "#pragma once\n\nnamespace Linura::HyprlandDisplay {\n"
            'inline constexpr char IntegrationSourceDigest[] = "' + "a" * 64 + '";\n}\n'
        )
        contract = tomllib.loads((self.root / candidate.INPUTS[1]).read_text())
        self.prepared = {
            "id": contract["id"],
            "claim": "non-authoritative-prepared-substrate",
            "contract_sha256": hashlib.sha256(
                (self.root / candidate.INPUTS[1]).read_bytes()
            ).hexdigest(),
            "prepared_image_sha256": "b" * 64,
            "qualification_evidence": False,
            "sanitized": True,
            "package_versions": [
                row["name"] + " " + row["version"]
                for row in [*contract["package"], contract["archived_package"]]
            ],
        }
        (self.inputs / "prepared-substrate.json").write_text(json.dumps(self.prepared))
        pin = tomllib.loads((self.root / candidate.INPUTS[0]).read_text())
        self.staged = {
            "schema_version": 1,
            "upstream_commit": pin["upstream_commit"],
            "source_sha256": pin["source_sha256"],
            "integration_recipe_sha256": hashlib.sha256(
                (self.root / candidate.INPUTS[2]).read_bytes()
            ).hexdigest(),
            "qualification_evidence": False,
        }
        (self.inputs / "staged-source.json").write_text(json.dumps(self.staged))
        self.record = {
            "source_sha": SHA,
            "dirty": False,
            "development": False,
            "build_passed": True,
            "qualification_evidence": False,
            "build_input_sha256": "c" * 64,
        }
        self.destination = self.base / "candidate"

    def retain(self):
        return candidate.retain(
            self.root,
            self.destination,
            SHA,
            {name: self.inputs / name for name in candidate.FILES},
            self.record,
        )

    def test_exact_build_roundtrip_binds_bytes_without_promoting_support(self):
        result = self.retain()
        self.assertEqual(
            candidate.verify(
                self.root, self.destination, SHA, self.inputs / "integration-build.h"
            ),
            result,
        )
        self.assertEqual(set(result["files"]), set(candidate.FILES))
        for flag in (
            "qualification_evidence",
            "native_execution_qualified",
            "rollback_qualified",
            "s17_qualified",
        ):
            self.assertIs(result[flag], False)
        (self.inputs / "Hyprland").write_bytes(b"discarded original output")
        self.assertEqual(candidate.verify(self.root, self.destination, SHA), result)

    def test_failed_dirty_development_or_foreign_build_cannot_publish(self):
        for key, wrong in (
            ("dirty", True),
            ("development", True),
            ("build_passed", False),
            ("source_sha", "2" * 40),
            ("qualification_evidence", True),
        ):
            with self.subTest(key=key):
                original = self.record[key]
                self.record[key] = wrong
                with self.assertRaises(ValueError):
                    self.retain()
                self.assertFalse(self.destination.exists())
                self.record[key] = original

    def test_stale_source_contract_or_recipe_and_foreign_owner_fail_closed(self):
        self.retain()
        with self.assertRaisesRegex(ValueError, "source_sha"):
            candidate.verify(self.root, self.destination, "2" * 40)
        header = self.inputs / "integration-build.h"
        header.write_text(header.read_text().replace("a" * 64, "d" * 64))
        with self.assertRaisesRegex(ValueError, "identities differ"):
            candidate.verify(self.root, self.destination, SHA, header)
        for name in candidate.INPUTS:
            path = self.root / name
            original = path.read_bytes()
            path.write_bytes(original + b"\n# changed\n")
            with (
                self.subTest(name=name),
                self.assertRaisesRegex(ValueError, "source_inputs"),
            ):
                candidate.verify(self.root, self.destination, SHA)
            path.write_bytes(original)

    def test_every_retained_file_is_verified_and_unknown_files_are_rejected(self):
        self.retain()
        for name in candidate.FILES:
            path = self.destination / name
            original = path.read_bytes()
            path.write_bytes(original + b"corrupt")
            with self.subTest(name=name), self.assertRaises(ValueError):
                candidate.verify(self.root, self.destination, SHA)
            path.write_bytes(original)
        extra = self.destination / "unreviewed.sh"
        extra.write_text("exit 0\n")
        with self.assertRaisesRegex(ValueError, "inventory"):
            candidate.verify(self.root, self.destination, SHA)

    def test_manifest_cannot_upgrade_claims_add_keys_or_duplicate_keys(self):
        metadata = self.retain()
        path = self.destination / candidate.MANIFEST
        for key, wrong in (
            ("qualification_evidence", True),
            ("s17_qualified", True),
            ("schema_version", True),
            ("unreviewed", False),
        ):
            changed = {**metadata, key: wrong}
            path.write_text(json.dumps(changed))
            with self.subTest(key=key), self.assertRaises(ValueError):
                candidate.verify(self.root, self.destination, SHA)
        path.write_text(json.dumps(metadata)[:-1] + ',"source_sha":"' + SHA + '"}')
        with self.assertRaisesRegex(ValueError, "duplicate"):
            candidate.verify(self.root, self.destination, SHA)

    def test_links_special_files_and_read_budget_are_rejected_without_blocking(self):
        self.retain()
        path = self.destination / "Hyprland"
        original = path.read_bytes()
        for kind in ("symlink", "hardlink", "fifo", "oversized"):
            path.unlink()
            if kind == "symlink":
                path.symlink_to(self.inputs / "Hyprland")
            elif kind == "hardlink":
                os.link(self.inputs / "Hyprland", path)
            elif kind == "fifo":
                os.mkfifo(path)
            else:
                with path.open("wb") as stream:
                    stream.truncate(candidate.FILES["Hyprland"] + 1)
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                candidate.verify(self.root, self.destination, SHA)
            path.unlink()
            path.write_bytes(original)
        with self.assertRaises(ValueError):
            candidate.read_bounded(path, 3)
        real = self.destination.with_name("real")
        self.destination.rename(real)
        self.destination.symlink_to(real, target_is_directory=True)
        with self.assertRaises(ValueError):
            candidate.verify(self.root, self.destination, SHA)

    def test_incompatible_sdk_recipe_or_non_elf_output_cannot_be_retained(self):
        for failure in ("package", "duplicate-package", "recipe", "binary"):
            with self.subTest(failure=failure):
                prepared, staged = dict(self.prepared), dict(self.staged)
                prepared["package_versions"] = list(prepared["package_versions"])
                if failure == "package":
                    prepared["package_versions"][0] = "systemd-libs unsupported"
                elif failure == "duplicate-package":
                    prepared["package_versions"].append(prepared["package_versions"][0])
                elif failure == "recipe":
                    staged["integration_recipe_sha256"] = "d" * 64
                else:
                    (self.inputs / "Hyprland").write_bytes(b"#!/usr/bin/bash\nexit 0\n")
                (self.inputs / "prepared-substrate.json").write_text(
                    json.dumps(prepared)
                )
                (self.inputs / "staged-source.json").write_text(json.dumps(staged))
                with self.assertRaises(ValueError):
                    self.retain()
                shutil.rmtree(self.destination)

    def test_shared_binder_enforces_budget_before_copy_and_during_growth(self):
        path, copied = self.inputs / "bounded", self.base / "bounded-copy"
        path.write_bytes(b"abc")
        with self.assertRaisesRegex(ValueError, "budget"):
            candidate.artifacts._bind_file(path, copied, max_size=2)
        self.assertFalse(copied.exists())
        original_read = os.read

        def growing(descriptor, size):
            path.write_bytes(b"abcdef")
            return original_read(descriptor, size)

        with patch.object(candidate.artifacts.os, "read", side_effect=growing) as read:
            with self.assertRaisesRegex(ValueError, "grew beyond"):
                candidate.artifacts._bind_file(path, copied, max_size=3)
        self.assertEqual(read.call_args.args[1], 4)
        self.assertEqual(copied.stat().st_size, 0)

    def test_runtime_can_omit_build_only_packages_but_cannot_change_providers(self):
        self.retain()
        runtime = tomllib.loads((self.root / candidate.INPUTS[3]).read_text())
        required = set(runtime["runtime_packages"])
        # Reproduce the actual Arch guest: no git/meson/private protocol build
        # tools or Glaze. Removing only the last Glaze row missed this mismatch.
        inventory = "\n".join(
            row
            for row in self.prepared["package_versions"]
            if row.split(" ", 1)[0] in required
        )
        for build_only in (
            "git",
            "meson",
            "hyprland-protocols",
            "hyprwayland-scanner",
            "glaze",
        ):
            self.assertNotIn(
                build_only, {row.split(" ", 1)[0] for row in inventory.splitlines()}
            )
        self.assertEqual(
            len(
                candidate.verify_runtime_packages(
                    self.root, self.destination, inventory
                )
            ),
            64,
        )
        for wrong in (
            "",
            inventory.replace("hyprland 0.56.2-3", "hyprland unsupported"),
            inventory + "\nunbound-runtime-provider 1",
            inventory + "\n" + inventory.splitlines()[0],
            "\n".join(
                row for row in inventory.splitlines() if not row.startswith("wayland ")
            ),
            "x" * (1024 * 1024 + 1),
        ):
            with self.subTest(length=len(wrong)), self.assertRaises(ValueError):
                candidate.verify_runtime_packages(self.root, self.destination, wrong)

        for name in required:
            incomplete = "\n".join(
                row for row in inventory.splitlines() if not row.startswith(name + " ")
            )
            with self.subTest(missing=name), self.assertRaises(ValueError):
                candidate.verify_runtime_packages(
                    self.root, self.destination, incomplete
                )

    def test_runtime_contract_requires_same_frozen_environment_and_complete_declaration(
        self,
    ):
        self.retain()
        path = self.root / candidate.INPUTS[3]
        original = path.read_text()
        inventory = "\n".join(self.prepared["package_versions"])
        for changed in (
            original.replace('architecture = "x86_64"', 'architecture = "aarch64"'),
            original.replace(
                'arch_archive_snapshot = "2026-09-16"',
                'arch_archive_snapshot = "2026-09-17"',
            ),
            original.replace(
                'id = "qualification/v010-shell-runtime-substrate"', 'id = "other"'
            ),
            original.replace('  "wayland",', '  "wayland",\n  "wayland",'),
            original.replace(
                '  "wayland",', '  "wayland",\n  "missing-runtime-provider",'
            ),
        ):
            path.write_text(changed)
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                candidate.verify_runtime_packages(
                    self.root, self.destination, inventory
                )
        path.write_text(original)


if __name__ == "__main__":
    unittest.main()
