from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "tools" / "release_contract.py"
SPEC = importlib.util.spec_from_file_location("release_contract", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("unable to load release_contract module")
release_contract = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release_contract)


def valid_notes(tag: str = "v0.0.0") -> str:
    headings = "\n\n".join(
        f"{heading}\n\nEvidence text."
        for heading in release_contract.REQUIRED_HEADINGS
    )
    return (
        f"# {tag} — test release\n\n"
        "**Status:** implementation complete\n"
        "**Claim class:** Architecture\n"
        "**Supported platform profiles:** none\n\n"
        f"{headings}\n\n"
        "Trace link: "
        "https://github.com/linura-org/linura/commit/"
        "0123456789abcdef0123456789abcdef01234567\n"
    )


def git(repository: Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", *args],
        cwd=repository,
        text=True,
    ).strip()


def initialized_repository(directory: Path) -> Path:
    repository = directory / "repo"
    repository.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repository, check=True)
    subprocess.run(
        ["git", "config", "user.name", "Release Contract Test"],
        cwd=repository,
        check=True,
    )
    subprocess.run(
        ["git", "config", "user.email", "release-contract@example.invalid"],
        cwd=repository,
        check=True,
    )
    (repository / "candidate.txt").write_text("candidate\n", encoding="utf-8")
    subprocess.run(["git", "add", "candidate.txt"], cwd=repository, check=True)
    subprocess.run(
        ["git", "commit", "-q", "-m", "chore: reviewed release candidate"],
        cwd=repository,
        check=True,
    )
    return repository


def create_release_intent(
    repository: Path,
    *,
    change_tree: bool = False,
    wrong_tree: bool = False,
    wrong_qualification_tree: bool = False,
) -> tuple[str, str, str, str, str]:
    qualification_source = git(repository, "rev-parse", "HEAD")
    qualification_tree = git(repository, "rev-parse", "HEAD^{tree}")
    evidence = repository / "qualification-evidence.json"
    evidence.write_text('{"result":"passed"}\n', encoding="utf-8")
    subprocess.run(["git", "add", "qualification-evidence.json"], cwd=repository, check=True)
    subprocess.run(
        ["git", "commit", "-q", "-m", "test: seal release qualification evidence"],
        cwd=repository,
        check=True,
    )
    reviewed_source = git(repository, "rev-parse", "HEAD")
    reviewed_tree = git(repository, "rev-parse", "HEAD^{tree}")
    if change_tree:
        (repository / "candidate.txt").write_text("changed after review\n", encoding="utf-8")
        subprocess.run(["git", "add", "candidate.txt"], cwd=repository, check=True)
    recorded_tree = "0" * 40 if wrong_tree else reviewed_tree
    recorded_qualification_tree = reviewed_tree if wrong_qualification_tree else qualification_tree
    message = (
        "release: v0.0.0 — test release\n\n"
        "Authorize the exact reviewed tree.\n\n"
        f"Reviewed-Source: {reviewed_source}\n"
        f"Reviewed-Tree: {recorded_tree}\n"
        f"Qualification-Source: {qualification_source}\n"
        f"Qualification-Tree: {recorded_qualification_tree}"
    )
    command = ["git", "commit", "-q", "-m", message]
    if not change_tree:
        command.insert(2, "--allow-empty")
    subprocess.run(command, cwd=repository, check=True)
    return (
        git(repository, "rev-parse", "HEAD"),
        reviewed_source,
        reviewed_tree,
        qualification_source,
        qualification_tree,
    )


def create_release_preparation(
    repository: Path,
    *,
    changed_files: tuple[str, ...] = ("Cargo.lock", "Cargo.toml"),
    wrong_qualification_tree: bool = False,
    duplicate_source_trailer: bool = False,
) -> tuple[str, str, str, str]:
    qualification_source = git(repository, "rev-parse", "HEAD")
    qualification_tree = git(repository, "rev-parse", "HEAD^{tree}")

    evidence = repository / "qualification-evidence.json"
    evidence.write_text('{"result":"passed"}\n', encoding="utf-8")
    subprocess.run(["git", "add", "qualification-evidence.json"], cwd=repository, check=True)
    subprocess.run(
        ["git", "commit", "-q", "-m", "test: seal release qualification evidence"],
        cwd=repository,
        check=True,
    )
    parent = git(repository, "rev-parse", "HEAD")

    for name in changed_files:
        path = repository / name
        path.write_text(f"{name} prepared\n", encoding="utf-8")
        subprocess.run(["git", "add", name], cwd=repository, check=True)

    recorded_tree = "0" * 40 if wrong_qualification_tree else qualification_tree
    duplicate = (
        f"\nQualification-Source: {qualification_source}"
        if duplicate_source_trailer
        else ""
    )
    message = (
        "release: prepare v0.10.0 complete-workstation\n\n"
        "Deterministic release preparation.\n\n"
        f"Qualification-Source: {qualification_source}\n"
        f"Qualification-Tree: {recorded_tree}"
        f"{duplicate}"
    )
    command = ["git", "commit", "-q", "-m", message]
    if not changed_files:
        command.insert(2, "--allow-empty")
    subprocess.run(command, cwd=repository, check=True)
    return (
        git(repository, "rev-parse", "HEAD"),
        parent,
        qualification_source,
        qualification_tree,
    )


class ReleaseContractTests(unittest.TestCase):
    def test_contract_requires_canonical_sections_and_traceability(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            notes = Path(temp_dir) / "v0.0.0.md"
            notes.write_text(valid_notes(), encoding="utf-8")
            metadata = release_contract.validate_contract(notes, "v0.0.0")
            self.assertEqual(metadata["claim_class"], "Architecture")
            self.assertEqual(
                metadata["commits"],
                ["0123456789abcdef0123456789abcdef01234567"],
            )

    def test_contract_rejects_product_name_in_release_notes_heading(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            notes = Path(temp_dir) / "v0.0.0.md"
            notes.write_text(
                valid_notes().replace("# v0.0.0 —", "# Linura v0.0.0 —", 1),
                encoding="utf-8",
            )
            with self.assertRaises(release_contract.ContractError):
                release_contract.validate_contract(notes, "v0.0.0")

    def test_contract_rejects_empty_release_theme(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            notes = Path(temp_dir) / "v0.0.0.md"
            notes.write_text(
                valid_notes().replace("# v0.0.0 — test release", "# v0.0.0 — ", 1),
                encoding="utf-8",
            )
            with self.assertRaises(release_contract.ContractError):
                release_contract.validate_contract(notes, "v0.0.0")

    def test_contract_rejects_missing_heading(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            notes = Path(temp_dir) / "v0.0.0.md"
            notes.write_text(
                valid_notes().replace("## Recovery and rollback", "## Recovery"),
                encoding="utf-8",
            )
            with self.assertRaises(release_contract.ContractError):
                release_contract.validate_contract(notes, "v0.0.0")

    def test_release_intent_requires_tree_identical_single_parent_and_exact_trailers(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repository = initialized_repository(Path(temp_dir))
            source, reviewed_source, reviewed_tree, qualification_source, qualification_tree = create_release_intent(repository)
            metadata = release_contract.validate_release_intent(source, repository)
            self.assertEqual(metadata["source_sha"], source)
            self.assertEqual(metadata["reviewed_source_sha"], reviewed_source)
            self.assertEqual(metadata["reviewed_tree_sha"], reviewed_tree)
            self.assertEqual(metadata["qualification_source_sha"], qualification_source)
            self.assertEqual(metadata["qualification_tree_sha"], qualification_tree)

    def test_release_intent_rejects_tree_changed_after_review(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repository = initialized_repository(Path(temp_dir))
            source, _, _, _, _ = create_release_intent(repository, change_tree=True)
            with self.assertRaises(release_contract.ContractError):
                release_contract.validate_release_intent(source, repository)

    def test_release_intent_rejects_forged_reviewed_tree_trailer(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repository = initialized_repository(Path(temp_dir))
            source, _, _, _, _ = create_release_intent(repository, wrong_tree=True)
            with self.assertRaises(release_contract.ContractError):
                release_contract.validate_release_intent(source, repository)

    def test_release_intent_rejects_non_independent_qualification_tree_trailer(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repository = initialized_repository(Path(temp_dir))
            source, _, _, _, _ = create_release_intent(
                repository,
                wrong_qualification_tree=True,
            )
            with self.assertRaises(release_contract.ContractError):
                release_contract.validate_release_intent(source, repository)

    def test_release_preparation_accepts_exact_mechanical_two_file_shape(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repository = initialized_repository(Path(temp_dir))
            source, parent, qualification_source, qualification_tree = (
                create_release_preparation(repository)
            )
            metadata = release_contract.validate_release_preparation(
                source,
                "v0.10.0",
                repository,
            )
            self.assertEqual(metadata["parent_sha"], parent)
            self.assertEqual(metadata["qualification_source_sha"], qualification_source)
            self.assertEqual(metadata["qualification_tree_sha"], qualification_tree)
            self.assertEqual(metadata["changed_files"], ["Cargo.lock", "Cargo.toml"])

    def test_release_preparation_accepts_idempotent_zero_diff_shape(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repository = initialized_repository(Path(temp_dir))
            source, _, qualification_source, _ = create_release_preparation(
                repository,
                changed_files=(),
            )
            metadata = release_contract.validate_release_preparation(
                source,
                "v0.10.0",
                repository,
            )
            self.assertEqual(metadata["qualification_source_sha"], qualification_source)
            self.assertEqual(metadata["changed_files"], [])

    def test_release_preparation_rejects_non_mechanical_changed_path(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repository = initialized_repository(Path(temp_dir))
            source, _, _, _ = create_release_preparation(
                repository,
                changed_files=("Cargo.lock", "Cargo.toml", "product.txt"),
            )
            with self.assertRaises(release_contract.ContractError):
                release_contract.validate_release_preparation(
                    source,
                    "v0.10.0",
                    repository,
                )

    def test_release_preparation_rejects_forged_or_duplicate_qualification_binding(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repository = initialized_repository(Path(temp_dir))
            source, _, _, _ = create_release_preparation(
                repository,
                wrong_qualification_tree=True,
            )
            with self.assertRaises(release_contract.ContractError):
                release_contract.validate_release_preparation(
                    source,
                    "v0.10.0",
                    repository,
                )

        with tempfile.TemporaryDirectory() as temp_dir:
            repository = initialized_repository(Path(temp_dir))
            source, _, _, _ = create_release_preparation(
                repository,
                duplicate_source_trailer=True,
            )
            with self.assertRaises(release_contract.ContractError):
                release_contract.validate_release_preparation(
                    source,
                    "v0.10.0",
                    repository,
                )

    def test_evidence_detects_artifact_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            tag = f"v{release_contract.workspace_version()}"
            notes = directory / "RELEASE_NOTES.md"
            notes.write_text(valid_notes(tag), encoding="utf-8")
            artifact = directory / "linurad"
            artifact.write_bytes(b"original")
            evidence = release_contract.build_evidence(notes, tag, "a" * 40, [artifact])
            (directory / "RELEASE-EVIDENCE.json").write_text(json.dumps(evidence) + "\n", encoding="utf-8")
            release_contract.verify_evidence(directory, tag, "a" * 40)
            artifact.write_bytes(b"tampered")
            with self.assertRaises(release_contract.ContractError):
                release_contract.verify_evidence(directory, tag, "a" * 40)

    def test_evidence_rejects_tag_that_does_not_match_workspace_version(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            current = release_contract.workspace_version()
            mismatched_tag = "v9.9.8" if current == "9.9.9" else "v9.9.9"
            notes = directory / "RELEASE_NOTES.md"
            notes.write_text(valid_notes(mismatched_tag), encoding="utf-8")
            artifact = directory / "linurad"
            artifact.write_bytes(b"candidate")
            with self.assertRaises(release_contract.ContractError):
                release_contract.build_evidence(notes, mismatched_tag, "a" * 40, [artifact])

    def test_release_tree_uses_filename_as_tag(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            (directory / "v0.0.0.md").write_text(valid_notes(), encoding="utf-8")
            release_contract.validate_tree(directory)

    def test_release_body_comparison_normalizes_final_newline(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            notes = directory / "notes.md"
            body = directory / "body.md"
            notes.write_text("same\n", encoding="utf-8")
            body.write_text("same\n\n", encoding="utf-8")
            release_contract.compare_release_body(notes, body)


if __name__ == "__main__":
    unittest.main()
