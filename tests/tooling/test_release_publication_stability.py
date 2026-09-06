from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "tools" / "check_release_publication_stability.py"
SPEC = importlib.util.spec_from_file_location("check_release_publication_stability", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("unable to load release publication-stability checker")
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)


def contract(tag: str, status: str, publication: str, *, outcome: str = "Stable outcome text.") -> str:
    return (
        f"# {tag} — test release\n\n"
        f"**Status:** {status}\n"
        "**Claim class:** Experimental\n"
        "**Supported platform profiles:** none\n\n"
        "## Outcome\n\n"
        f"{outcome}\n\n"
        "## Publication evidence\n\n"
        f"{publication}\n"
    )


class ReleasePublicationStabilityTests(unittest.TestCase):
    def test_repository_release_contracts_are_publication_stable(self) -> None:
        checker.validate_tree(ROOT / "docs" / "releases")

    def test_v07_rejects_candidate_status_that_would_become_stale(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "v0.7.0.md"
            path.write_text(
                contract(
                    "v0.7.0",
                    "implementation qualified; release candidate; publication pending",
                    "Publication state is externally recorded.",
                ),
                encoding="utf-8",
            )
            with self.assertRaises(checker.PublicationStabilityError):
                checker.validate_contract(path)

    def test_v07_rejects_pending_publication_section(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "v0.7.0.md"
            path.write_text(
                contract(
                    "v0.7.0",
                    "immutable release contract; live publication state is external to this frozen document.",
                    "Publication evidence remains pending until verification succeeds.",
                ),
                encoding="utf-8",
            )
            with self.assertRaises(checker.PublicationStabilityError):
                checker.validate_contract(path)

    def test_v07_rejects_temporary_wording_in_arbitrary_section(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "v0.7.0.md"
            path.write_text(
                contract(
                    "v0.7.0",
                    "immutable release contract; live publication state is external to this frozen document.",
                    "The protected lifecycle records terminal publication externally.",
                    outcome="This release is not yet released; publication remains pending.",
                ),
                encoding="utf-8",
            )
            with self.assertRaises(checker.PublicationStabilityError):
                checker.validate_contract(path)

    def test_v07_prerelease_filename_is_guarded(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "v0.7.0-rc.1.md"
            path.write_text(
                contract(
                    "v0.7.0-rc.1",
                    "release candidate",
                    "Publication state is externally recorded.",
                ),
                encoding="utf-8",
            )
            self.assertEqual(checker.version_from_path(path), (0, 7, 0))
            with self.assertRaises(checker.PublicationStabilityError):
                checker.validate_contract(path)

    def test_v07_build_metadata_filename_is_guarded(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "v0.7.0+build.1.md"
            path.write_text(
                contract(
                    "v0.7.0+build.1",
                    "immutable release contract; live publication state is external to this frozen document.",
                    "Publication is not established.",
                ),
                encoding="utf-8",
            )
            self.assertEqual(checker.version_from_path(path), (0, 7, 0))
            with self.assertRaises(checker.PublicationStabilityError):
                checker.validate_contract(path)

    def test_v07_accepts_timeless_external_publication_state(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "v0.7.0.md"
            path.write_text(
                contract(
                    "v0.7.0",
                    "immutable release contract; live publication state is external to this frozen document.",
                    "The protected lifecycle binds source, sealed bytes, tag, publication, independent verification, and terminal roadmap evidence without mutating this contract.",
                    outcome="The release contract defines the bounded v0.7 capability and evidence requirements.",
                ),
                encoding="utf-8",
            )
            checker.validate_contract(path)

    def test_candidate_artifact_term_is_not_treated_as_lifecycle_state(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "v0.7.0-rc.1.md"
            path.write_text(
                contract(
                    "v0.7.0-rc.1",
                    "immutable release contract; live publication state is external to this frozen document.",
                    "The protected lifecycle verifies every candidate artifact before publication.",
                ),
                encoding="utf-8",
            )
            checker.validate_contract(path)

    def test_pre_v07_historical_contracts_remain_valid_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "v0.6.0.md"
            path.write_text(
                contract(
                    "v0.6.0",
                    "implementation qualified; release candidate; publication evidence remains pending",
                    "Publication evidence remains pending.",
                    outcome="This release is not yet released.",
                ),
                encoding="utf-8",
            )
            checker.validate_contract(path)


if __name__ == "__main__":
    unittest.main()
