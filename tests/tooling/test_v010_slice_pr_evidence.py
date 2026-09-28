from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "tools" / "verify_v010_slice_pr_evidence.py"
SPEC = importlib.util.spec_from_file_location("verify_v010_slice_pr_evidence", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)


class V010SlicePREvidenceTests(unittest.TestCase):
    def test_all_v010_slices_have_canonical_owned_paths(self) -> None:
        self.assertEqual(
            set(verifier.SLICE_PATH_PREFIXES),
            {f"S{index:02d}" for index in range(1, 33)},
        )
        self.assertTrue(all(verifier.SLICE_PATH_PREFIXES.values()))

    def test_current_completed_ledger_evidence_has_canonical_owners(self) -> None:
        owners = verifier.load_completed_evidence(ROOT)
        self.assertTrue(owners)
        self.assertTrue(all(slice_id in verifier.SLICE_PATH_PREFIXES for slice_id in owners.values()))

    def test_scope_matching_accepts_owned_implementation_paths(self) -> None:
        cases = {
            "S01": "contracts/v010-workstation-qualification.toml",
            "S03": "crates/linura-linux-observation/src/platform_discovery.rs",
            "S08": "apps/linurad/src/session_audio.rs",
            "S12": "apps/linura-shell/integrations/hyprland/WorkspaceNavigationController.qml",
            "S14": "qualification/v010/shell-runtime/run-shell-runtime.sh",
            "S29": "qualification/v010/experience-evidence.json",
            "S31": "qualification/v010/update-recovery/case.json",
            "S32": ".github/workflows/post-release-closure.yml",
        }
        for slice_id, path in cases.items():
            with self.subTest(slice_id=slice_id, path=path):
                self.assertTrue(verifier.path_matches_slice(slice_id, path))

    def test_evidence_seal_paths_allow_only_retained_artifact_surfaces(self) -> None:
        self.assertTrue(
            verifier.evidence_seal_path_allowed(
                "contracts/v010-workstation-qualification.toml"
            )
        )
        self.assertTrue(
            verifier.evidence_seal_path_allowed(
                "qualification/v010/experience-evidence.json"
            )
        )
        self.assertTrue(
            verifier.evidence_seal_path_allowed(
                "qualification/v010/interactive-workstation/physical-session-start.json"
            )
        )
        self.assertTrue(
            verifier.evidence_seal_path_allowed(
                "qualification/v010/security/polkit-attestation.json"
            )
        )
        for executable_harness in (
            "qualification/v010/shell-runtime/run-shell-runtime.sh",
            "qualification/v010/shell-runtime/prepare-substrate.sh",
            "qualification/v010/shell-runtime/verify-substrate.py",
            "qualification/v010/future-harness/run.py",
        ):
            with self.subTest(path=executable_harness):
                self.assertFalse(verifier.evidence_seal_path_allowed(executable_harness))
        self.assertFalse(verifier.evidence_seal_path_allowed("apps/linurad/src/main.rs"))
        self.assertFalse(verifier.evidence_seal_path_allowed("Cargo.lock"))

    def test_evidence_seal_rename_checks_source_and_destination(self) -> None:
        paths = verifier.evidence_seal_record_paths(
            {
                "filename": "qualification/v010/interactive-workstation/moved-evidence.json",
                "previous_filename": "apps/linurad/src/main.rs",
                "status": "renamed",
            }
        )
        self.assertEqual(
            paths,
            ("qualification/v010/interactive-workstation/moved-evidence.json", "apps/linurad/src/main.rs"),
        )
        self.assertTrue(verifier.evidence_seal_path_allowed(paths[0]))
        self.assertFalse(verifier.evidence_seal_path_allowed(paths[1]))

    def test_slice_scope_requires_added_or_modified_owned_path(self) -> None:
        original = verifier.pr_file_records
        try:
            for status in ("added", "modified"):
                with self.subTest(status=status):
                    verifier.pr_file_records = lambda repository, number, status=status: [
                        {
                            "filename": "apps/linurad/src/session_audio.rs",
                            "status": status,
                        }
                    ]
                    verifier.require_slice_scope("linura-org/linura", 154, "S08")
        finally:
            verifier.pr_file_records = original

    def test_slice_scope_rejects_deleted_owned_path(self) -> None:
        original = verifier.pr_file_records
        try:
            verifier.pr_file_records = lambda repository, number: [
                {
                    "filename": "apps/linurad/src/session_audio.rs",
                    "status": "removed",
                }
            ]
            with self.assertRaisesRegex(
                verifier.EvidenceError,
                "does not add or modify a canonical owned path",
            ):
                verifier.require_slice_scope("linura-org/linura", 154, "S08")
        finally:
            verifier.pr_file_records = original

    def test_slice_scope_rejects_renamed_only_owned_path(self) -> None:
        original = verifier.pr_file_records
        try:
            verifier.pr_file_records = lambda repository, number: [
                {
                    "filename": "apps/linurad/src/session_audio.rs",
                    "previous_filename": "apps/linurad/src/legacy_audio.rs",
                    "status": "renamed",
                }
            ]
            with self.assertRaisesRegex(
                verifier.EvidenceError,
                "does not add or modify a canonical owned path",
            ):
                verifier.require_slice_scope("linura-org/linura", 154, "S08")
        finally:
            verifier.pr_file_records = original

    def test_scope_matching_rejects_unrelated_paths(self) -> None:
        self.assertFalse(verifier.path_matches_slice("S18", "README.md"))
        self.assertFalse(
            verifier.path_matches_slice(
                "S13",
                "apps/linura-shell/plugins/command-palette/CommandPalette.qml",
            )
        )
        self.assertFalse(verifier.path_matches_slice("S31", "docs/roadmap.md"))


if __name__ == "__main__":
    unittest.main()
