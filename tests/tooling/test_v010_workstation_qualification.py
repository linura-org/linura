from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[2]


class V010WorkstationQualificationTests(unittest.TestCase):
    def _run(self, root: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(ROOT / "tools/check_v010_workstation_qualification.py"), str(root)],
            capture_output=True,
            text=True,
            check=False,
        )

    def _copy_fixture(self, destination: Path) -> None:
        paths = (
            "contracts/roadmap.toml",
            "contracts/v010-workstation-qualification.toml",
            "profiles/arch-hyprland-v1.toml",
            "hardware/support-matrix.json",
            "docs/qualification/v0.10.0.md",
            "docs/adr/0031-v010-many-interfaces-one-authority-path.md",
            "packaging/arch/archiso/packages.linura",
        )
        for rel in paths:
            source = ROOT / rel
            target = destination / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)

    def _rewrite_contract(self, root: Path, old: str, new: str) -> None:
        path = root / "contracts/v010-workstation-qualification.toml"
        text = path.read_text(encoding="utf-8")
        self.assertEqual(text.count(old), 1)
        path.write_text(text.replace(old, new, 1), encoding="utf-8")

    def _refresh_profile_digest(self, root: Path) -> None:
        profile = root / "profiles/arch-hyprland-v1.toml"
        digest = hashlib.sha256(profile.read_bytes()).hexdigest()
        contract = root / "contracts/v010-workstation-qualification.toml"
        text = contract.read_text(encoding="utf-8")
        data = tomllib.loads(text)
        old = data["profile_sha256"]
        contract.write_text(text.replace(old, digest, 1), encoding="utf-8")

    def _required_packages(self, root: Path) -> list[str]:
        path = root / "packaging/arch/archiso/packages.linura"
        return sorted(
            line.strip()
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        )

    def _write_frozen_manifest(self, root: Path, *, omit: str | None = None) -> Path:
        manifest = root / "qualification/v010/arch-packages.tsv"
        manifest.parent.mkdir(parents=True, exist_ok=True)
        records = []
        for package in self._required_packages(root):
            if package == omit:
                continue
            records.append(f"core\t{package}\t1:1.0.0-1\tx86_64")
        manifest.write_text(
            "# linura-arch-package-manifest-v1\n"
            "# snapshot_date=2026-09-16\n"
            "# architecture=x86_64\n"
            + "\n".join(records)
            + "\n",
            encoding="utf-8",
        )
        return manifest

    def _freeze_contract(self, root: Path, manifest: Path) -> None:
        digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
        self._rewrite_contract(
            root,
            'state = "source-pinned-package-set-pending"',
            'state = "frozen"',
        )
        self._rewrite_contract(
            root,
            'package_manifest = ""',
            'package_manifest = "qualification/v010/arch-packages.tsv"',
        )
        self._rewrite_contract(
            root,
            'package_manifest_sha256 = ""',
            f'package_manifest_sha256 = "{digest}"',
        )
        self._rewrite_contract(
            root,
            "release_qualification_ready = false",
            "release_qualification_ready = true",
        )

    def test_repository_contract_is_valid(self) -> None:
        result = self._run(ROOT)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_profile_cannot_self_promote_before_release_closure(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            profile = root / "profiles/arch-hyprland-v1.toml"
            profile.write_text(
                profile.read_text(encoding="utf-8").replace(
                    'status = "development"',
                    'status = "release-qualified"',
                    1,
                ),
                encoding="utf-8",
            )
            self._refresh_profile_digest(root)
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("must remain development", result.stderr)

    def test_support_matrix_cannot_promote_target_profile_early(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            matrix = root / "hardware/support-matrix.json"
            payload = json.loads(matrix.read_text(encoding="utf-8"))
            payload["machine_classes"]["workstation"]["release_qualified_profiles"] = [
                "arch-hyprland-v1"
            ]
            matrix.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("cannot be release-qualified", result.stderr)

    def test_profile_provider_identity_cannot_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            profile = root / "profiles/arch-hyprland-v1.toml"
            profile.write_text(
                profile.read_text(encoding="utf-8").replace(
                    'network = "networkmanager"',
                    'network = "systemd-networkd"',
                    1,
                ),
                encoding="utf-8",
            )
            self._refresh_profile_digest(root)
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("provider identity drifted", result.stderr)

    def test_mutable_archive_alias_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            self._rewrite_contract(
                root,
                'repository_url = "https://archive.archlinux.org/repos/2026/09/16/$repo/os/$arch"',
                'repository_url = "https://archive.archlinux.org/repos/last/$repo/os/$arch"',
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("exact dated Arch Linux Archive", result.stderr)

    def test_pending_package_set_cannot_claim_release_readiness(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            self._rewrite_contract(
                root,
                "release_qualification_ready = false",
                "release_qualification_ready = true",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("cannot be release_qualification_ready", result.stderr)

    def test_frozen_package_set_requires_digest_bound_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            self._rewrite_contract(
                root,
                'state = "source-pinned-package-set-pending"',
                'state = "frozen"',
            )
            self._rewrite_contract(
                root,
                "release_qualification_ready = false",
                "release_qualification_ready = true",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("requires package_manifest", result.stderr)
            self.assertIn("requires lowercase package_manifest_sha256", result.stderr)

    def test_frozen_package_manifest_requires_typed_required_package_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            manifest = self._write_frozen_manifest(root, omit="hyprland")
            self._freeze_contract(root, manifest)
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("missing required versioned packages: hyprland", result.stderr)

    def test_frozen_package_manifest_rejects_empty_or_unrelated_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            manifest = root / "qualification/v010/arch-packages.tsv"
            manifest.parent.mkdir(parents=True, exist_ok=True)
            manifest.write_text("", encoding="utf-8")
            self._freeze_contract(root, manifest)
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("identity headers", result.stderr)

    def test_frozen_package_manifest_rejects_malformed_or_nonofficial_records(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            manifest = self._write_frozen_manifest(root)
            text = manifest.read_text(encoding="utf-8")
            first_record = text.splitlines()[3]
            manifest.write_text(
                text.replace(first_record, first_record.replace("core\t", "aur\t", 1), 1),
                encoding="utf-8",
            )
            self._freeze_contract(root, manifest)
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("non-official repository", result.stderr)

    def test_frozen_package_manifest_must_live_in_qualification_namespace(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            manifest = self._write_frozen_manifest(root)
            self._freeze_contract(root, manifest)
            contract = root / "contracts/v010-workstation-qualification.toml"
            text = contract.read_text(encoding="utf-8")
            contract.write_text(
                text.replace(
                    'package_manifest = "qualification/v010/arch-packages.tsv"',
                    'package_manifest = "docs/qualification/v0.10.0.md"',
                    1,
                ),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("must be a .tsv file under qualification/v010/", result.stderr)

    def test_frozen_package_manifest_digest_is_verified(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            manifest = self._write_frozen_manifest(root)
            self._freeze_contract(root, manifest)
            result = self._run(root)
            self.assertEqual(result.returncode, 0, result.stderr)

            manifest.write_text(
                manifest.read_text(encoding="utf-8") + "extra\tzstd\t1.0-1\tx86_64\n",
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("package manifest digest mismatch", result.stderr)

    def test_interaction_adr_is_required(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            (root / "docs/adr/0031-v010-many-interfaces-one-authority-path.md").unlink()
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("interaction ADR 0031 is missing", result.stderr)

    def test_roadmap_must_bind_machine_readable_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            roadmap = root / "contracts/roadmap.toml"
            roadmap.write_text(
                roadmap.read_text(encoding="utf-8").replace(
                    'qualification_contract = "contracts/v010-workstation-qualification.toml"\n',
                    "",
                    1,
                ),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("qualification_contract must point", result.stderr)


if __name__ == "__main__":
    unittest.main()
