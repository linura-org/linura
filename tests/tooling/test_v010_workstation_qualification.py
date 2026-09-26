from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import tomllib
import unittest
import zlib

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
            "contracts/v010-workstation-slices.toml",
            "contracts/operation-semantics.toml",
            "profiles/arch-hyprland-v1.toml",
            "hardware/support-matrix.json",
            "docs/qualification/v0.10.0.md",
            "docs/adr/0031-v010-many-interfaces-one-authority-path.md",
            "docs/adr/0033-v010-complete-workstation-product-boundary.md",
            "packaging/arch/archiso/packages.linura",
            "visual/baselines/manifest.json",
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

    def _png_bytes(
        self,
        width: int,
        height: int,
        *,
        pixel_value: int = 0,
        transparent_gray: int | None = None,
        extra_raw_bytes: int = 0,
        ancillary_chunks: tuple[tuple[bytes, bytes], ...] = (),
    ) -> bytes:
        def chunk(kind: bytes, payload: bytes) -> bytes:
            return (
                struct.pack(">I", len(payload))
                + kind
                + payload
                + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)
            )

        ihdr = struct.pack(">IIBBBBB", width, height, 8, 0, 0, 0, 0)
        self.assertGreaterEqual(pixel_value, 0)
        self.assertLessEqual(pixel_value, 255)
        if transparent_gray is not None:
            self.assertGreaterEqual(transparent_gray, 0)
            self.assertLessEqual(transparent_gray, 255)
        self.assertGreaterEqual(extra_raw_bytes, 0)
        rows = b"".join(
            b"\x00" + bytes([pixel_value]) * width for _ in range(height)
        ) + (b"\x00" * extra_raw_bytes)
        result = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr)
        if transparent_gray is not None:
            result += chunk(b"tRNS", struct.pack(">H", transparent_gray))
        for kind, payload in ancillary_chunks:
            self.assertEqual(len(kind), 4)
            result += chunk(kind, payload)
        return result + chunk(b"IDAT", zlib.compress(rows)) + chunk(b"IEND", b"")

    def _refresh_experience_evidence_digest(self, root: Path) -> None:
        evidence = root / "qualification/v010/experience-evidence.json"
        digest = hashlib.sha256(evidence.read_bytes()).hexdigest()
        contract = root / "contracts/v010-workstation-qualification.toml"
        text = contract.read_text(encoding="utf-8")
        data = tomllib.loads(text)
        old_digest = data["experience"]["experience_evidence_manifest_sha256"]
        contract.write_text(text.replace(old_digest, digest, 1), encoding="utf-8")

    def _refresh_visual_baseline_manifest_digest(self, root: Path) -> None:
        manifest = root / "visual/baselines/manifest.json"
        digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
        contract = root / "contracts/v010-workstation-qualification.toml"
        text = contract.read_text(encoding="utf-8")
        data = tomllib.loads(text)
        old_digest = data["experience"]["visual_baseline_manifest_sha256"]
        contract.write_text(text.replace(old_digest, digest, 1), encoding="utf-8")

    def _visual_failure_binding(
        self,
        baseline_id: str,
        baseline_sha256: str,
        failed_capture_sha256: str,
        diff_sha256: str,
    ) -> str:
        payload = (
            "linura-v010-visual-failure-v1\n"
            f"{baseline_id}\n"
            f"{baseline_sha256}\n"
            f"{failed_capture_sha256}\n"
            f"{diff_sha256}\n"
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def _complete_product_slices_for_q10(self, root: Path) -> None:
        path = root / "contracts/v010-workstation-slices.toml"
        text = path.read_text(encoding="utf-8")
        parts = text.split("[[slice]]")
        rewritten = [parts[0]]
        for block in parts[1:]:
            if any(f'id = "S{index:02d}"' in block for index in range(15, 29)):
                block = block.replace('status = "planned"', 'status = "complete"', 1)
                block = block.replace("evidence_prs = []", "evidence_prs = [999]", 1)
            rewritten.append("[[slice]]" + block)
        text = "".join(rewritten)
        text = text.replace("completed_slice_count = 14", "completed_slice_count = 28", 1)
        text = text.replace('next_slice = "S15"', 'next_slice = "S29"', 1)
        path.write_text(text, encoding="utf-8")

    def _write_complete_experience_evidence(self, root: Path) -> None:
        self._complete_product_slices_for_q10(root)
        baseline_manifest = root / "visual/baselines/manifest.json"
        required_visual_surfaces = ["linura-firstboot","linura-installer","linura-control-center","command-palette","quick-settings","desktop-shell-integration","shell-panel-tray-status","launcher-workspace","notifications-osd","lock-session-controls","network-connectivity","bluetooth","audio-media","display-power","desktop-utilities","applications-packages","updates-snapshots-recovery","personalization"]
        baseline_records = [
            ("firstboot-1280x800-1x", "linura-firstboot", 1280, 800, 1.0),
            ("firstboot-1280x800-2x", "linura-firstboot", 1280, 800, 2.0),
            ("control-center-1440x900-1x", "linura-control-center", 1440, 900, 1.0),
        ]
        existing_surfaces = {record[1] for record in baseline_records}
        for surface in required_visual_surfaces:
            if surface in existing_surfaces:
                continue
            baseline_records.append(
                (f"{surface}-1280x800-1x", surface, 1280, 800, 1.0)
            )
        baselines = []
        visual_dir = root / "visual/baselines"
        visual_dir.mkdir(parents=True, exist_ok=True)
        qualification_dir = root / "qualification/v010"
        qualification_dir.mkdir(parents=True, exist_ok=True)
        comparisons = []
        for baseline_id, surface, width, height, scale in baseline_records:
            baseline_rel = f"visual/baselines/{baseline_id}.png"
            baseline_path = root / baseline_rel
            baseline_path.write_bytes(self._png_bytes(width, height))
            capture_rel = f"qualification/v010/{baseline_id}-capture.png"
            capture_path = root / capture_rel
            capture_path.write_bytes(self._png_bytes(width, height))
            baselines.append(
                {
                    "id": baseline_id,
                    "surface": surface,
                    "width": width,
                    "height": height,
                    "scale": scale,
                    "baseline": baseline_rel,
                    "sha256": hashlib.sha256(baseline_path.read_bytes()).hexdigest(),
                }
            )
            comparisons.append(
                {
                    "baseline_id": baseline_id,
                    "capture": capture_rel,
                    "capture_sha256": hashlib.sha256(capture_path.read_bytes()).hexdigest(),
                    "status": "pass",
                    "reviewed": True,
                }
            )
        baseline_manifest.write_text(
            json.dumps({"schema_version": 1, "baselines": baselines}, indent=2) + "\n",
            encoding="utf-8",
        )
        baseline_digest = hashlib.sha256(baseline_manifest.read_bytes()).hexdigest()
        self._rewrite_contract(
            root,
            'visual_baseline_manifest_sha256 = ""',
            f'visual_baseline_manifest_sha256 = "{baseline_digest}"',
        )

        failed_baseline = baselines[0]
        failed_capture_rel = "qualification/v010/visual-failure-capture.png"
        failed_capture_path = root / failed_capture_rel
        failed_capture_path.write_bytes(
            self._png_bytes(
                int(failed_baseline["width"]),
                int(failed_baseline["height"]),
                pixel_value=255,
            )
        )
        failed_capture_digest = hashlib.sha256(failed_capture_path.read_bytes()).hexdigest()
        diff_rel = "qualification/v010/visual-failure-diff.png"
        diff_path = root / diff_rel
        diff_path.write_bytes(
            self._png_bytes(
                int(failed_baseline["width"]),
                int(failed_baseline["height"]),
                pixel_value=255,
            )
        )
        diff_digest = hashlib.sha256(diff_path.read_bytes()).hexdigest()
        baseline_digest = str(failed_baseline["sha256"])
        failure_binding = self._visual_failure_binding(
            str(failed_baseline["id"]),
            baseline_digest,
            failed_capture_digest,
            diff_digest,
        )

        required_surfaces = ["linura-firstboot","linura-installer","linura-control-center","command-palette","quick-settings","desktop-shell-integration","shell-panel-tray-status","launcher-workspace","notifications-osd","lock-session-controls","network-connectivity","bluetooth","audio-media","display-power","desktop-utilities","applications-packages","updates-snapshots-recovery","personalization"]
        interaction_records = []
        for surface in required_surfaces:
            report_rel = f"qualification/v010/{surface}-interaction-accessibility.json"
            report_path = root / report_rel
            report = {
                "schema_version": 1,
                "artifact_type": "linura-v010-interaction-accessibility",
                "surface": surface,
                "result": "pass",
                "runner": {
                    "name": "fixture-runner",
                    "version": "1.0",
                    "run_id": f"fixture-{surface}",
                    "platform": "arch-hyprland-v1",
                },
                "checks": {
                    "keyboard": "pass",
                    "pointer": "pass",
                    "screen_reader": "pass",
                    "reduced_motion": "pass",
                    "display_scaling": "pass",
                    "offline_error": "pass",
                    "reconnect": "pass",
                },
            }
            report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
            interaction_records.append(
                {
                    "surface": surface,
                    "report": report_rel,
                    "report_sha256": hashlib.sha256(report_path.read_bytes()).hexdigest(),
                }
            )

        evidence = {
            "schema_version": 1,
            "visual_comparisons": comparisons,
            "retained_failure_diffs": [
                {
                    "baseline_id": failed_baseline["id"],
                    "baseline_sha256": baseline_digest,
                    "failed_capture": failed_capture_rel,
                    "failed_capture_sha256": failed_capture_digest,
                    "status": "fail",
                    "diff": diff_rel,
                    "diff_sha256": diff_digest,
                    "binding_sha256": failure_binding,
                    "reviewed": True,
                }
            ],
            "interaction_accessibility": interaction_records,
        }
        evidence_path = qualification_dir / "experience-evidence.json"
        evidence_path.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
        digest = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
        self._rewrite_contract(
            root,
            'experience_evidence_manifest_sha256 = ""',
            f'experience_evidence_manifest_sha256 = "{digest}"',
        )
        self._rewrite_contract(
            root,
            "experience_evidence_ready = false",
            "experience_evidence_ready = true",
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

    def test_experience_evidence_cannot_be_ready_with_null_visual_baselines(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            manifest = root / "visual/baselines/manifest.json"
            manifest_digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
            self._rewrite_contract(
                root,
                'visual_baseline_manifest_sha256 = ""',
                f'visual_baseline_manifest_sha256 = "{manifest_digest}"',
            )
            self._rewrite_contract(
                root,
                "experience_evidence_ready = false",
                "experience_evidence_ready = true",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("visual baseline artifact", result.stderr)

    def test_nonexistent_visual_baseline_strings_do_not_satisfy_readiness(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            manifest = root / "visual/baselines/manifest.json"
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            for item in payload["baselines"]:
                item["baseline"] = f"visual/baselines/{item['id']}.png"
            manifest.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            manifest_digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
            self._rewrite_contract(
                root,
                'visual_baseline_manifest_sha256 = ""',
                f'visual_baseline_manifest_sha256 = "{manifest_digest}"',
            )
            self._rewrite_contract(
                root,
                "experience_evidence_ready = false",
                "experience_evidence_ready = true",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("missing or not a regular file", result.stderr)

    def test_experience_readiness_requires_all_product_slices(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            self._write_complete_experience_evidence(root)
            slices = root / "contracts/v010-workstation-slices.toml"
            text = slices.read_text(encoding="utf-8")
            parts = text.split("[[slice]]")
            rewritten = [parts[0]]
            for block in parts[1:]:
                if 'id = "S28"' in block:
                    block = block.replace('status = "complete"', 'status = "planned"', 1)
                    block = block.replace("evidence_prs = [999]", "evidence_prs = []", 1)
                rewritten.append("[[slice]]" + block)
            text = "".join(rewritten)
            text = text.replace("completed_slice_count = 28", "completed_slice_count = 27", 1)
            text = text.replace('next_slice = "S29"', 'next_slice = "S28"', 1)
            slices.write_text(text, encoding="utf-8")

            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "experience evidence cannot be ready until product slices S01-S28 are complete: S28",
                result.stderr,
            )

    def test_complete_artifact_backed_experience_evidence_can_become_ready(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            self._write_complete_experience_evidence(root)
            result = self._run(root)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_experience_evidence_manifest_digest_is_verified(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            self._write_complete_experience_evidence(root)
            evidence = root / "qualification/v010/experience-evidence.json"
            evidence.write_text(
                evidence.read_text(encoding="utf-8") + "\n",
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("experience evidence manifest digest mismatch", result.stderr)

    def test_truncated_digest_valid_png_evidence_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            self._write_complete_experience_evidence(root)
            evidence_path = root / "qualification/v010/experience-evidence.json"
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
            comparison = evidence["visual_comparisons"][0]
            capture_path = root / comparison["capture"]
            capture_path.write_bytes(self._png_bytes(1280, 800)[:33])
            comparison["capture_sha256"] = hashlib.sha256(
                capture_path.read_bytes()
            ).hexdigest()
            evidence_path.write_text(
                json.dumps(evidence, indent=2) + "\n",
                encoding="utf-8",
            )
            self._refresh_experience_evidence_digest(root)
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("missing IDAT image data", result.stderr)

    def test_visual_pass_requires_independent_pixel_equivalence(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            self._write_complete_experience_evidence(root)
            evidence_path = root / "qualification/v010/experience-evidence.json"
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
            comparison = evidence["visual_comparisons"][0]
            capture_path = root / comparison["capture"]
            capture_path.write_bytes(
                self._png_bytes(1280, 800, pixel_value=255)
            )
            comparison["capture_sha256"] = hashlib.sha256(
                capture_path.read_bytes()
            ).hexdigest()
            evidence_path.write_text(
                json.dumps(evidence, indent=2) + "\n",
                encoding="utf-8",
            )
            self._refresh_experience_evidence_digest(root)
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "visual comparison for firstboot-1280x800-1x does not match baseline pixels",
                result.stderr,
            )

    def test_png_transparency_is_part_of_pixel_equivalence(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            self._write_complete_experience_evidence(root)
            evidence_path = root / "qualification/v010/experience-evidence.json"
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
            comparison = evidence["visual_comparisons"][0]
            capture_path = root / comparison["capture"]
            capture_path.write_bytes(
                self._png_bytes(1280, 800, pixel_value=0, transparent_gray=0)
            )
            comparison["capture_sha256"] = hashlib.sha256(
                capture_path.read_bytes()
            ).hexdigest()
            evidence_path.write_text(
                json.dumps(evidence, indent=2) + "\n",
                encoding="utf-8",
            )
            self._refresh_experience_evidence_digest(root)
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "visual comparison for firstboot-1280x800-1x does not match baseline pixels",
                result.stderr,
            )

    def test_png_color_management_metadata_is_rejected_before_pixel_equivalence(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            self._write_complete_experience_evidence(root)
            evidence_path = root / "qualification/v010/experience-evidence.json"
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
            comparison = evidence["visual_comparisons"][0]
            capture_path = root / comparison["capture"]
            capture_path.write_bytes(
                self._png_bytes(
                    1280,
                    800,
                    ancillary_chunks=((b"gAMA", struct.pack(">I", 45455)),),
                )
            )
            comparison["capture_sha256"] = hashlib.sha256(
                capture_path.read_bytes()
            ).hexdigest()
            evidence_path.write_text(
                json.dumps(evidence, indent=2) + "\n",
                encoding="utf-8",
            )
            self._refresh_experience_evidence_digest(root)
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unsupported color-management PNG chunk gAMA", result.stderr)

    def test_png_overlong_inflate_is_rejected_under_declared_dimensions(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            self._write_complete_experience_evidence(root)
            evidence_path = root / "qualification/v010/experience-evidence.json"
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
            comparison = evidence["visual_comparisons"][0]
            capture_path = root / comparison["capture"]
            capture_path.write_bytes(
                self._png_bytes(1280, 800, extra_raw_bytes=4 * 1024 * 1024)
            )
            comparison["capture_sha256"] = hashlib.sha256(
                capture_path.read_bytes()
            ).hexdigest()
            evidence_path.write_text(
                json.dumps(evidence, indent=2) + "\n",
                encoding="utf-8",
            )
            self._refresh_experience_evidence_digest(root)
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("overlong PNG image data", result.stderr)

    def test_retained_failure_diff_must_bind_an_actual_failed_pair(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            self._write_complete_experience_evidence(root)
            evidence_path = root / "qualification/v010/experience-evidence.json"
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
            failure = evidence["retained_failure_diffs"][0]
            baseline_path = root / "visual/baselines/firstboot-1280x800-1x.png"
            failed_capture_path = root / failure["failed_capture"]
            failed_capture_path.write_bytes(baseline_path.read_bytes())
            failure["failed_capture_sha256"] = hashlib.sha256(
                failed_capture_path.read_bytes()
            ).hexdigest()
            failure["binding_sha256"] = self._visual_failure_binding(
                failure["baseline_id"],
                failure["baseline_sha256"],
                failure["failed_capture_sha256"],
                failure["diff_sha256"],
            )
            evidence_path.write_text(
                json.dumps(evidence, indent=2) + "\n",
                encoding="utf-8",
            )
            self._refresh_experience_evidence_digest(root)
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("does not represent an actual failed pixel comparison", result.stderr)

    def test_retained_failure_diff_pixels_must_match_bound_failed_pair(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            self._write_complete_experience_evidence(root)
            evidence_path = root / "qualification/v010/experience-evidence.json"
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
            failure = evidence["retained_failure_diffs"][0]
            baseline_path = root / "visual/baselines/firstboot-1280x800-1x.png"
            diff_path = root / failure["diff"]
            diff_path.write_bytes(baseline_path.read_bytes())
            failure["diff_sha256"] = hashlib.sha256(diff_path.read_bytes()).hexdigest()
            failure["binding_sha256"] = self._visual_failure_binding(
                failure["baseline_id"],
                failure["baseline_sha256"],
                failure["failed_capture_sha256"],
                failure["diff_sha256"],
            )
            evidence_path.write_text(
                json.dumps(evidence, indent=2) + "\n",
                encoding="utf-8",
            )
            self._refresh_experience_evidence_digest(root)
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "pixels do not match the canonical failed-pair diff",
                result.stderr,
            )

    def test_accessibility_claims_require_digest_bound_runner_report(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            self._write_complete_experience_evidence(root)
            evidence_path = root / "qualification/v010/experience-evidence.json"
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
            record = evidence["interaction_accessibility"][0]
            report_path = root / record["report"]
            report = json.loads(report_path.read_text(encoding="utf-8"))
            report["checks"]["screen_reader"] = "fail"
            report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
            record["report_sha256"] = hashlib.sha256(report_path.read_bytes()).hexdigest()
            evidence_path.write_text(
                json.dumps(evidence, indent=2) + "\n",
                encoding="utf-8",
            )
            self._refresh_experience_evidence_digest(root)
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "interaction/accessibility report linura-firstboot checks.screen_reader must be pass",
                result.stderr,
            )

    def test_experience_artifact_digest_tampering_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            self._write_complete_experience_evidence(root)
            baseline = root / "visual/baselines/firstboot-1280x800-1x.png"
            baseline.write_bytes(self._png_bytes(640, 480))
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("visual baseline artifact firstboot-1280x800-1x digest mismatch", result.stderr)

    def test_experience_requires_visual_baselines_for_every_supported_surface(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            self._write_complete_experience_evidence(root)
            manifest = root / "visual/baselines/manifest.json"
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            payload["baselines"] = [
                item
                for item in payload["baselines"]
                if item["surface"] != "notifications-osd"
            ]
            manifest.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
            contract = root / "contracts/v010-workstation-qualification.toml"
            data = tomllib.loads(contract.read_text(encoding="utf-8"))
            old_digest = data["experience"]["visual_baseline_manifest_sha256"]
            contract.write_text(
                contract.read_text(encoding="utf-8").replace(old_digest, digest, 1),
                encoding="utf-8",
            )
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("visual baseline coverage missing required surfaces: notifications-osd", result.stderr)

    def test_interaction_adr_is_required(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            (root / "docs/adr/0031-v010-many-interfaces-one-authority-path.md").unlink()
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("interaction ADR 0031 is missing", result.stderr)

    def test_product_scope_adr_is_required(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            (root / "docs/adr/0033-v010-complete-workstation-product-boundary.md").unlink()
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("product-scope ADR 0033 is missing", result.stderr)

    def test_operation_semantics_contract_is_required(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            (root / "contracts/operation-semantics.toml").unlink()
            result = self._run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("operation-semantics contract file is missing", result.stderr)

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
