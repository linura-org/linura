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

    def test_machine_prs_use_release_app_and_native_ruleset_gates(self) -> None:
        preparation = (ROOT / ".github/workflows/release-preparation.yml").read_text(encoding="utf-8")
        authorization = (ROOT / ".github/workflows/release-authorization.yml").read_text(encoding="utf-8")
        closure = (ROOT / ".github/workflows/post-release-closure.yml").read_text(encoding="utf-8")
        for workflow in (preparation, authorization, closure):
            self.assertIn(
                "actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1",
                workflow,
            )
            self.assertIn("LINURA_RELEASE_APP_CLIENT_ID", workflow)
            self.assertIn("LINURA_RELEASE_APP_PRIVATE_KEY", workflow)
            self.assertIn("--credential-source github-app", workflow)
            self.assertIn("tools/release_native_gates.py", workflow)
            self.assertNotIn("@codex review", workflow)
            self.assertNotIn("release_workflow_dispatch.py", workflow)

        self.assertIn("release: ready v", preparation)
        self.assertIn("python3 tools/prepare_release.py --tag", preparation)
        self.assertIn("--expected-changed-files 2", preparation)
        self.assertIn('pulls/$PR_NUMBER/merge', preparation)
        self.assertIn("event-driven authorization handoff", preparation)
        self.assertIn("Native PR CI/Security/CodeQL are the ruleset-authoritative gates", preparation)

        self.assertIn("release: prepare v", authorization)
        self.assertIn("zero-diff", authorization)
        self.assertIn("Reviewed-Source:", authorization)
        self.assertIn("Reviewed-Tree:", authorization)
        self.assertIn("--expected-changed-files 0", authorization)
        self.assertIn('pulls/$PR_NUMBER/merge', authorization)
        self.assertIn("release-proof-dispatch.yml", authorization)
        self.assertIn("workflow_dispatch checks are not used as substitutes", authorization)
        self.assertNotIn('PATCH "repos/$GITHUB_REPOSITORY/git/refs/heads/main"', authorization)

        self.assertIn("deterministic closure", closure)
        self.assertIn("post-release-cleanup.yml", closure)
        self.assertIn("event-driven terminal cleanup handoff", closure)
        self.assertIn('pulls/$PR_NUMBER/merge', closure)
        self.assertNotIn("Delete obsolete release-scoped branches", closure)

    def test_main_transitions_are_event_driven_and_retryable(self) -> None:
        authorization = (ROOT / ".github/workflows/release-authorization.yml").read_text(encoding="utf-8")
        proof_dispatch = (ROOT / ".github/workflows/release-proof-dispatch.yml").read_text(encoding="utf-8")
        cleanup = (ROOT / ".github/workflows/post-release-cleanup.yml").read_text(encoding="utf-8")

        self.assertIn("push:", authorization)
        self.assertIn("branches: [main]", authorization)
        self.assertIn("workflow_run:", proof_dispatch)
        self.assertIn('startsWith(github.event.workflow_run.head_commit.message, \'release: v\')', proof_dispatch)
        self.assertIn("workflow_run:", cleanup)
        self.assertIn('startsWith(github.event.workflow_run.head_commit.message, \'chore: close v\')', cleanup)
        self.assertIn("tools/release_native_gates.py", cleanup)
        self.assertIn("tools/release_branch_cleanup.py", cleanup)

    def test_semantic_review_stops_at_release_ready_boundary(self) -> None:
        preparation = (ROOT / ".github/workflows/release-preparation.yml").read_text(encoding="utf-8")
        authorization = (ROOT / ".github/workflows/release-authorization.yml").read_text(encoding="utf-8")
        closure = (ROOT / ".github/workflows/post-release-closure.yml").read_text(encoding="utf-8")
        guide = (ROOT / "agents/skills/release.md").read_text(encoding="utf-8")
        self.assertIn("release: ready vX.Y.Z — <implementation theme>", guide)
        self.assertIn("last semantic review boundary", guide)
        for workflow in (preparation, authorization, closure):
            self.assertNotIn("@codex review", workflow)
            self.assertNotIn("chatgpt-codex-connector", workflow)

    def test_release_chain_preserves_proof_publication_and_verification_handoffs(self) -> None:
        proof = (ROOT / ".github/workflows/release-proof-dispatch.yml").read_text(encoding="utf-8")
        trusted = (ROOT / ".github/workflows/trusted-release-proof.yml").read_text(encoding="utf-8")
        promotion = (ROOT / ".github/workflows/release-promotion.yml").read_text(encoding="utf-8")
        release = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        verification = (ROOT / ".github/workflows/release-verification.yml").read_text(encoding="utf-8")
        handoff = (ROOT / ".github/workflows/release-closure-handoff.yml").read_text(encoding="utf-8")

        self.assertIn("trusted-release-proof.yml", proof)
        self.assertIn("dispatch release promotion", trusted)
        self.assertIn("release-promotion.yml", trusted)
        self.assertIn("prove Release App closure authority before publication", promotion)
        self.assertIn("gh workflow run release.yml", promotion)
        self.assertIn("Create or verify immutable version tag", release)
        self.assertIn("verification-dispatch:", release)
        self.assertIn("release-verification.yml", release)
        self.assertIn("dispatch terminal closure handoff", verification)
        self.assertIn("post-release-closure.yml", handoff)

    def test_release_automation_has_architecture_and_threat_contracts(self) -> None:
        adr = (ROOT / "docs/adr/0027-protected-release-handoff-automation.md").read_text(encoding="utf-8")
        threat = (ROOT / "docs/threat-model-release-automation.md").read_text(encoding="utf-8")
        for marker in (
            "Repository-scoped operator",
            "protected `main`",
            "zero-diff",
            "tag-last",
            "One verification-to-closure path",
            "Linura Release GitHub App",
        ):
            self.assertIn(marker, adr)
        for marker in (
            "Candidate substitution and retry tampering",
            "Event-recursion failure",
            "Credential compromise",
            "Rotation, revocation and permission drift",
            "exact release tag",
            "native PR",
        ):
            self.assertIn(marker, threat)


if __name__ == "__main__":
    unittest.main()
