from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
PREPARE_PATH = ROOT / "tools" / "prepare_release.py"
SPEC = importlib.util.spec_from_file_location("prepare_release", PREPARE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("unable to load prepare_release")
prepare_release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(prepare_release)


class ReleaseHandoffAutomationTests(unittest.TestCase):
    def _fixture(self, root: Path, workspace_version: str = "0.7.0") -> None:
        (root / "contracts").mkdir()
        (root / "docs" / "milestones").mkdir(parents=True)
        (root / "docs" / "releases").mkdir(parents=True)
        (root / "docs" / "qualification").mkdir(parents=True)
        (root / "crates" / "alpha").mkdir(parents=True)
        (root / "crates" / "beta").mkdir(parents=True)

        (root / "contracts" / "roadmap.toml").write_text(
            '''next_release = "v0.8.0"

[[milestone]]
version = "v0.8.0"
title = "next release"
status = "planned"
milestone_contract = "docs/milestones/v0.8.0.md"
release_contract = "docs/releases/v0.8.0.md"
qualification = "docs/qualification/v0.8.0.md"
''',
            encoding="utf-8",
        )
        for relative in (
            "docs/milestones/v0.8.0.md",
            "docs/releases/v0.8.0.md",
            "docs/qualification/v0.8.0.md",
            "docs/qualification/v0.8.0-security.md",
            "docs/qualification/v0.8.0-release-review.md",
        ):
            (root / relative).write_text("fixture\n", encoding="utf-8")

        (root / "Cargo.toml").write_text(
            f'''[workspace]
members = ["crates/alpha", "crates/beta"]

[workspace.package]
version = "{workspace_version}"
edition = "2024"
''',
            encoding="utf-8",
        )
        for name in ("alpha", "beta"):
            (root / "crates" / name / "Cargo.toml").write_text(
                f'''[package]
name = "{name}"
version.workspace = true
edition.workspace = true
''',
                encoding="utf-8",
            )
        (root / "Cargo.lock").write_text(
            f'''version = 4

[[package]]
name = "alpha"
version = "{workspace_version}"

[[package]]
name = "beta"
version = "{workspace_version}"

[[package]]
name = "external"
version = "9.9.9"
''',
            encoding="utf-8",
        )

    def test_prepare_release_only_bumps_workspace_and_lock_versions(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._fixture(root)

            changed = prepare_release.prepare(root, "v0.8.0")
            self.assertEqual(changed, ["Cargo.toml", "Cargo.lock"])
            cargo = (root / "Cargo.toml").read_text(encoding="utf-8")
            lock = (root / "Cargo.lock").read_text(encoding="utf-8")
            self.assertIn('version = "0.8.0"', cargo)
            self.assertEqual(lock.count('version = "0.8.0"'), 2)
            self.assertIn('version = "9.9.9"', lock)

    def test_prepare_release_rejects_non_next_or_non_monotonic_versions(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._fixture(root, workspace_version="0.8.0")

            with self.assertRaises(prepare_release.PreparationError):
                prepare_release.prepare(root, "v0.7.0")
            with self.assertRaises(prepare_release.PreparationError):
                prepare_release.prepare(root, "v0.8.0")

    def test_workflows_pin_complete_automatic_handoff_without_main_bypass(self) -> None:
        preparation = (ROOT / ".github/workflows/release-preparation.yml").read_text(encoding="utf-8")
        authorization = (ROOT / ".github/workflows/release-authorization.yml").read_text(encoding="utf-8")
        verification = (ROOT / ".github/workflows/release-verification.yml").read_text(encoding="utf-8")
        handoff = (ROOT / ".github/workflows/release-closure-handoff.yml").read_text(encoding="utf-8")
        proof = (ROOT / ".github/workflows/release-proof-dispatch.yml").read_text(encoding="utf-8")
        closure = (ROOT / ".github/workflows/post-release-closure.yml").read_text(encoding="utf-8")

        self.assertIn("release: ready v", preparation)
        self.assertIn("python3 tools/prepare_release.py --tag", preparation)
        self.assertIn("@codex review", preparation)
        self.assertIn("tools/release_workflow_dispatch.py dispatch", preparation)
        self.assertIn("release-preparation-head-runs.jsonl", preparation)
        self.assertIn("release-preparation-main-runs.jsonl", preparation)
        self.assertIn('pulls/$PR_NUMBER/merge', preparation)
        self.assertIn("GH_TOKEN: ${{ github.token }}", preparation)
        self.assertIn("--credential-source github", preparation)
        self.assertIn("release-authorization.yml", preparation)
        self.assertIn("verify_candidate()", preparation)
        self.assertIn('git diff --name-only "$SOURCE_SHA" "$candidate_sha"', preparation)
        self.assertIn('git show "$candidate_sha:Cargo.toml" | cmp - Cargo.toml', preparation)
        self.assertIn('git show "$HEAD_SHA:Cargo.lock" | cmp - Cargo.lock', preparation)
        self.assertNotIn("active=0", preparation)
        self.assertNotIn("active=1", preparation)

        self.assertIn("release: prepare v", authorization)
        self.assertIn("zero-diff", authorization)
        self.assertIn("@codex review", authorization)
        self.assertIn('pulls/$PR_NUMBER/merge', authorization)
        self.assertIn("Reviewed-Source:", authorization)
        self.assertIn("Reviewed-Tree:", authorization)
        self.assertIn("verify_candidate()", authorization)
        self.assertIn('test "$(jq -r .changed_files <<<"$pr_payload")" = "0"', authorization)
        self.assertIn('test "$(jq -r .message <<<"$candidate_payload")" = "$message"', authorization)
        self.assertNotIn('PATCH "repos/$GITHUB_REPOSITORY/git/refs/heads/main"', authorization)
        self.assertIn("GH_TOKEN: ${{ github.token }}", authorization)
        self.assertIn("trusted-release-proof.yml", authorization)

        self.assertIn("dispatch terminal closure handoff", verification)
        self.assertIn("manual release verification must run from the exact requested tag", verification)
        self.assertNotIn("types: [published]", verification)
        self.assertIn("Await exact verification terminal success", handoff)
        self.assertIn("Dispatch protected post-release closure", handoff)
        self.assertNotIn("Prefer already-materialized workflow_run closure", handoff)
        self.assertNotIn("recovery-workflow-run", handoff)
        self.assertIn("post-release-closure.yml", handoff)
        self.assertNotIn("workflow_run:", closure)
        self.assertNotIn("github.event.workflow_run", closure)
        self.assertIn("release: v", proof)
        self.assertIn("@codex review", closure)
        self.assertIn("event=workflow_dispatch", closure)
        self.assertIn('pulls/$PR_NUMBER/merge', closure)
        self.assertNotIn('gh pr merge "$PR_NUMBER"', closure)
        self.assertIn("--credential-source github", closure)

    def test_release_guide_declares_explicit_readiness_and_no_manual_missing_handoff(self) -> None:
        guide = (ROOT / "agents/skills/release.md").read_text(encoding="utf-8")
        self.assertIn("release: ready vX.Y.Z — <implementation theme>", guide)
        self.assertIn("Release Preparation", guide)
        self.assertIn("Release Authorization", guide)
        self.assertIn("metadata-only zero-diff authorization PR", guide)

    def test_release_automation_has_architecture_and_threat_contracts(self) -> None:
        adr = (ROOT / "docs/adr/0027-protected-release-handoff-automation.md").read_text(encoding="utf-8")
        threat = (ROOT / "docs/threat-model-release-automation.md").read_text(encoding="utf-8")
        for marker in (
            "Repository-scoped operator",
            "protected `main`",
            "zero-diff",
            "tag-last",
            "One verification-to-closure path",
        ):
            self.assertIn(marker, adr)
        for marker in (
            "Candidate substitution and retry tampering",
            "Event-recursion failure",
            "Credential compromise",
            "Rotation, revocation and permission drift",
            "exact release tag",
        ):
            self.assertIn(marker, threat)


if __name__ == "__main__":
    unittest.main()
